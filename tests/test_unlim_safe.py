"""Offline regression tests; synthetic secrets only, never contact Yandex."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.request
import zipfile

import unlim_download as collector
import unlim_worker as worker


class Response(io.BytesIO):
    def __init__(self, payload=b"", code=200, headers=None):
        super().__init__(payload)
        self.code, self.headers = code, headers or {}


class Opener:
    def __init__(self, responses):
        self.responses, self.requests = list(responses), []
    def open(self, request, timeout):
        self.requests.append(request)
        return self.responses.pop(0)


class FakeClient:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []
    def api(self, method, params=None):
        self.calls.append((method, params))
        return self.responses.pop(0)


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.old_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.conn = collector.connect_db(self.root)
    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()
        os.umask(self.old_umask)
    def cookies(self, entries=None):
        path = self.root / "cookies.json"
        if entries is None:
            entries = [self.cookie()]
        path.write_text(json.dumps(entries))
        return collector.load_cookies(path)
    def cookie(self, **kwargs):
        return dict(name="Session_id", value="synthetic-secret", domain=".yandex.ru",
                    path="/", secure=True, hostOnly=False, **kwargs)
    def record(self, fid="/a", name="a.jpg", content=b"photo", md5=True):
        record = dict(file_id=fid, cluster_id="c", name=name, size=len(content),
                      md5=hashlib.md5(content).hexdigest() if md5 else None)
        self.conn.execute("INSERT INTO unlim_files(file_id,cluster_id,name,size,md5) VALUES(:file_id,:cluster_id,:name,:size,:md5)", record)
        self.conn.commit()
        return record
    def archive(self, members):
        path = self.root / "test.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as zip_:
            for name, body in members:
                zip_.writestr(name, body)
        return path
    def stage(self):
        path = self.root / "stage"
        path.mkdir()
        return path
    def verify(self, zip_, records):
        return worker.verify_zip(zip_, records, self.stage())


class CookieTests(Sandbox):
    def test_scope_secure_expiry_and_host_only(self):
        cookies = [self.cookie(),
                   dict(name="host", value="h", domain="disk.yandex.ru", hostOnly=True, path="/client", secure=True),
                   dict(name="unrelated", value="no", domain="evil.test", path="/", secure=True),
                   dict(name="expired", value="no", domain=".yandex.ru", path="/", secure=True, expirationDate=1)]
        jar = self.cookies(cookies)
        self.assertEqual(len(list(jar)), 2)
        request = urllib.request.Request("https://disk.yandex.ru/client/disk")
        jar.add_cookie_header(request)
        self.assertIn("host=h", request.get_header("Cookie"))
        for url in ("http://disk.yandex.ru/client/disk", "https://evil.test/client/disk"):
            request = urllib.request.Request(url)
            jar.add_cookie_header(request)
            self.assertIsNone(request.get_header("Cookie"))
        for url in ("https://sub.disk.yandex.ru/client/disk", "https://disk.yandex.ru/models-v2"):
            request = urllib.request.Request(url)
            jar.add_cookie_header(request)
            self.assertNotIn("host=h", request.get_header("Cookie", ""))
    def test_non_dot_domain_flag_is_preserved(self):
        cookie = dict(name="session", value="s", domain="yandex.ru", path="/", secure=True, hostOnly=False)
        jar = self.cookies([cookie])
        req = urllib.request.Request("https://disk.yandex.ru/")
        jar.add_cookie_header(req)
        self.assertEqual(req.get_header("Cookie"), "session=s")
    def test_missing_scope_is_not_reconstructed(self):
        with self.assertRaises(collector.SafeError):
            self.cookies([dict(name="s", value="secret")])
    def test_header_injection_rejected(self):
        item = self.cookie()
        item["value"] = "secret\r\nInjected: true"
        with self.assertRaises(collector.SafeError):
            self.cookies([item])
    def test_world_readable_secrets_refused(self):
        self.cookies()
        path = self.root / "cookies.json"
        path.chmod(0o644)
        with self.assertRaises(collector.SafeError):
            collector.load_cookies(path)
    def test_symlink_and_hardlink_secrets_refused(self):
        self.cookies()
        target = self.root / "cookies.json"
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            collector.load_cookies(link)
        link.unlink()
        os.link(target, link)
        with self.assertRaises(collector.SafeError):
            collector.load_cookies(link)
    def test_api_redirect_never_carries_cookies_to_other_host(self):
        client = collector.YandexClient(self.cookies())
        client.opener = Opener([Response(code=302, headers={"Location": "https://evil.test/"})])
        with self.assertRaises(collector.SafeError):
            client.login()
        self.assertEqual(len(client.opener.requests), 1)
        self.assertIn("synthetic-secret", client.opener.requests[0].get_header("Cookie"))
    def test_api_client_refuses_other_origins_before_transport(self):
        client = collector.YandexClient(self.cookies())
        client.opener = Opener([])
        with self.assertRaises(collector.SafeError):
            client.request("https://passport.yandex.ru/")
        self.assertEqual(client.opener.requests, [])
    def test_no_proxy_or_cookie_processor(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1234"}):
            opener = collector.build_opener()
        self.assertFalse(any(isinstance(h, urllib.request.HTTPCookieProcessor) for h in opener.handlers))
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))


class NetworkTests(Sandbox):
    def test_download_redirects_have_no_credentials(self):
        opener = Opener([Response(code=302, headers={"Location": "https://s1.storage.yandex.net/archive?signature=fake"}), Response(b"zip")])
        with worker.archive_response("https://downloader.disk.yandex.ru/zip?token=fake", opener) as response:
            self.assertEqual(response.read(), b"zip")
        self.assertEqual(len(opener.requests), 2)
        for req in opener.requests:
            self.assertIsNone(req.get_header("Cookie"))
            self.assertIsNone(req.get_header("Authorization"))
            self.assertIsNone(req.get_header("Referer"))
    def test_bad_redirect_blocked_before_request(self):
        for dest in ("https://evil.test/", "http://downloader.disk.yandex.ru/", "https://127.0.0.1/", "https://169.254.169.254/", "https://downloader.disk.yandex.ru.evil.test/"):
            with self.subTest(dest=dest):
                opener = Opener([Response(code=302, headers={"Location": dest})])
                with self.assertRaises(collector.SafeError):
                    worker.archive_response("https://downloader.disk.yandex.ru/", opener)
                self.assertEqual(len(opener.requests), 1)
    def test_url_tricks_blocked(self):
        for url in ("https://evil.test@downloader.disk.yandex.ru/", "https://downloader.disk.yandex.ru:444/", "https://downloader.disk.yandex.ru/\n", "https://downloader.disk.yandex.ru\\@evil.test/", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(collector.SafeError):
                collector.validate_url(url, archive=True)
    def test_truncated_or_oversized_response(self):
        for payload, declared, limit in ((b"12", "3", 10), (b"123", None, 2)):
            target = self.root / "response.zip"
            if target.exists():
                target.unlink()
            with patch.object(worker, "archive_response", return_value=Response(payload, headers={} if declared is None else {"Content-Length": declared})):
                with self.assertRaises(collector.SafeError):
                    worker.download_zip("unused", target, limit)
    def test_secret_errors_not_printed(self):
        def bad():
            raise ValueError("secret-token-in-url")
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            self.assertEqual(collector.run_cli(bad), 1)
        self.assertNotIn("secret-token", out.getvalue())
    def test_api_error_body_not_printed(self):
        client = collector.YandexClient(self.cookies())
        client.opener = Opener([Response(b"secret-token", code=400)])
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            self.assertEqual(collector.run_cli(client.login), 1)
        self.assertNotIn("secret-token", out.getvalue())


class InventoryTests(Sandbox):
    def test_paginates_past_short_page(self):
        client = FakeClient([{"items": [{"id": "a", "size": 1}]}, {"items": [{"id": "b", "size": 1}]}, {"items": []}])
        self.assertEqual(len(collector.get_all_clusters(client, "s")), 2)
        self.assertEqual([call[1]["offset"] for call in client.calls], [0, 1, 2])
    def test_repeated_page_rejected(self):
        client = FakeClient([{"items": [{"id": "a", "size": 1}]}] * 2)
        with self.assertRaises(collector.SafeError):
            collector.get_all_clusters(client, "s")
    def test_missing_items_not_treated_as_empty_success(self):
        with self.assertRaises(collector.SafeError):
            collector.get_all_clusters(FakeClient([{}]), "s")
    def test_partial_cluster_not_complete(self):
        client = FakeClient([{"clusters": {"fetched": [{"id": "c", "items": [{"id": "a", "name": "a", "size": 1}]}]}}])
        with self.assertRaises(collector.SafeError):
            collector.fetch_cluster(client, "s", {"id": "c", "size": 2})
    def test_collection_and_account_binding(self):
        collector.bind_account(self.conn, "1")
        with self.assertRaises(collector.SafeError):
            collector.bind_account(self.conn, "2")
        client = FakeClient([{"photoslice_id": "s"}, {"items": [{"id": "c", "size": 1}]}, {"items": []}, {"clusters": {"fetched": [{"id": "c", "items": [{"id": "a", "name": "a.jpg", "size": 2}]}]}}])
        collector.collect(self.conn, client)
        self.assertEqual(collector.meta(self.conn, "collection_complete"), "1")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM unlim_files").fetchone()[0], 1)
        with self.assertRaises(collector.SafeError):
            collector.collect(self.conn, FakeClient([{}]))
        self.assertEqual(collector.meta(self.conn, "collection_complete"), "0")
    def test_etag_not_assumed_md5_and_missing_size_refused(self):
        row = collector.parse_resource({"id": "a", "name": "a", "size": 1, "etag": "arbitrary"}, "c")
        self.assertIsNone(row[4])
        with self.assertRaises(collector.SafeError):
            collector.parse_resource({"id": "a", "name": "a"}, "c")


class ArchiveTests(Sandbox):
    def test_verified_download_records_paths_and_hashes(self):
        rec = self.record()
        zip_ = self.archive([("folder/a.jpg", b"photo")])
        output = collector.private_dir(self.root / "out")
        verified = self.verify(zip_, [rec])
        worker.commit_batch(self.conn, verified, output)
        row = self.conn.execute("SELECT * FROM unlim_files").fetchone()
        self.assertEqual(row["status"], "downloaded")
        self.assertEqual(Path(row["local_path"]).read_bytes(), b"photo")
        self.assertEqual(row["sha256"], hashlib.sha256(b"photo").hexdigest())
        worker.verify_local(self.conn, output)
    def test_partial_batch_never_marked_downloaded(self):
        rows = [self.record(), self.record("b", "b.jpg", b"other")]
        with self.assertRaises(collector.SafeError):
            self.verify(self.archive([("a.jpg", b"photo")]), rows)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM unlim_files WHERE status='downloaded'").fetchone()[0], 0)
    def test_wrong_hash_with_right_size_rejected(self):
        with self.assertRaises(collector.SafeError):
            self.verify(self.archive([("a.jpg", b"wrong")]), [self.record()])
    def test_corrupt_crc_rejected(self):
        rec = self.record(md5=False)
        path = self.archive([("a.jpg", b"photo")])
        path.write_bytes(path.read_bytes().replace(b"photo", b"wrong", 1))
        with self.assertRaises(collector.SafeError):
            self.verify(path, [rec])
    def test_missing_md5_still_checks_crc_size_and_records_sha(self):
        rec = self.record(md5=False)
        verified = self.verify(self.archive([("a.jpg", b"photo")]), [rec])
        self.assertEqual(verified[0][-1], hashlib.sha256(b"photo").hexdigest())
    def test_extra_file_and_duplicate_basename_rejected(self):
        rec = self.record()
        for members in ([('a.jpg', b'photo'), ('b.jpg', b'other')], [('one/a.jpg', b'photo'), ('two/a.jpg', b'photo')]):
            with self.subTest(members=members):
                with zipfile.ZipFile(self.archive(members)) as archive:
                    if len(members) == 2 and members[1][0].startswith("two"):
                        with self.assertRaises(collector.SafeError):
                            worker.archive_members(archive)
                    else:
                        with self.assertRaises(collector.SafeError):
                            self.verify(self.root / "test.zip", [rec])
    def test_traversal_absolute_drive_and_symlink_members_rejected(self):
        for name in ("../evil", "/etc/passwd", "C:/evil", "folder/../../evil", "folder\\evil"):
            with self.subTest(name=name), zipfile.ZipFile(self.archive([(name, b'x')])) as archive:
                with self.assertRaises(collector.SafeError):
                    worker.archive_members(archive)
        link = zipfile.ZipInfo("a.jpg")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.archive([(link, b'/etc/passwd')])) as archive:
            with self.assertRaises(collector.SafeError):
                worker.archive_members(archive)
    def test_equal_names_different_ids_selected_in_separate_batches(self):
        self.record("a", "a.jpg", b"photo")
        self.record("b", "a.jpg", b"other")
        batch = worker.next_batch(self.conn, 25, 100)
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["file_id"], "a")
    def test_oversize_file_not_silently_skipped(self):
        self.record()
        with self.assertRaises(collector.SafeError):
            worker.next_batch(self.conn, 1, 2)
    def test_existing_different_content_not_overwritten(self):
        rec = self.record()
        output = collector.private_dir(self.root / "out")
        folder = collector.private_dir(output / hashlib.sha256(rec["file_id"].encode()).hexdigest())
        target = folder / rec["name"]
        target.write_bytes(b"other")
        with self.assertRaises(collector.SafeError):
            worker.commit_batch(self.conn, self.verify(self.archive([("a.jpg", b"photo")]), [rec]), output)
        self.assertEqual(target.read_bytes(), b"other")
    def test_existing_symlink_output_rejected(self):
        rec = self.record()
        output = collector.private_dir(self.root / "out")
        key = hashlib.sha256(rec["file_id"].encode()).hexdigest()
        (output / key).symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(collector.SafeError):
            worker.commit_batch(self.conn, self.verify(self.archive([("a.jpg", b"photo")]), [rec]), output)
    def test_download_flow_and_rerun_audit(self):
        rec = self.record()
        zip_ = self.archive([("a.jpg", b"photo")])
        output = collector.private_dir(self.root / "out")
        with patch.object(worker, "prepare_zip", return_value="fake"), patch.object(worker, "archive_response", return_value=Response(zip_.read_bytes())):
            self.assertEqual(worker.download_batch(self.conn, None, [rec], output, 4096), (1, 5))
        self.assertEqual(worker.next_batch(self.conn, 25, 1000), [])
        row = self.conn.execute("SELECT * FROM unlim_files").fetchone()
        Path(row['local_path']).write_bytes(b"wrong")
        with self.assertRaises(collector.SafeError):
            worker.verify_local(self.conn, output)
    def test_interruption_before_db_commit_can_resume(self):
        rec = self.record()
        output = collector.private_dir(self.root / "out")
        verified = self.verify(self.archive([("a.jpg", b"photo")]), [rec])
        # Simulate a previous run that published file bytes but had not committed SQLite.
        _, key, name, staged, _ = verified[0]
        folder = collector.private_dir(output / key)
        (folder / name).write_bytes(staged.read_bytes())
        worker.commit_batch(self.conn, verified, output)
        self.assertEqual(self.conn.execute("SELECT status FROM unlim_files").fetchone()[0], "downloaded")
    def test_process_lock_blocks_second_worker(self):
        with collector.state_lock(self.root):
            with self.assertRaises(collector.SafeError):
                with collector.state_lock(self.root):
                    pass


if __name__ == '__main__':
    unittest.main()
