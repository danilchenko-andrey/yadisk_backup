"""Verified photoslice download worker. Standard library only; see README_SAFE.md."""
from __future__ import annotations

import hashlib
import errno
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
import zlib

from unlim_download import (
    SafeError, FatalError, NetworkError, YandexClient, base_parser, bind_account, build_opener,
    configure_runtime, connect_db, load_cookies, meta, open_no_redirect,
    private_dir, run_cli, safe_name, state_lock, validate_url,
    record_issue, rescue_inventory, print_status,
)

CHUNK = 1024 * 1024


def archive_response(url, opener=None, timeout=120):
    """Every hop revalidated, no cookie jar/auth headers/referer on the CDN session."""
    opener = opener or build_opener()
    for _ in range(6):
        validate_url(url, archive=True)
        request = urllib.request.Request(url, headers={"User-Agent": "yadisk-unlim-safe/1", "Accept": "application/zip"})
        response = open_no_redirect(opener, request, timeout)
        if response.code == 200:
            return response
        location = response.headers.get("Location")
        status = response.code
        response.close()
        if status in (301, 302, 303, 307, 308) and location:
            url = urllib.parse.urljoin(url, location)
            continue
        if status == 429 or 500 <= status <= 599:
            if status == 429:
                print("Archive rate limit: pausing 30 seconds.", flush=True)
                time.sleep(30)
            raise NetworkError("Archive server temporarily unavailable; retry deferred.")
        raise SafeError("Archive server refused the download; response and URL omitted.")
    raise SafeError("Too many archive redirects.")


def prepare_zip(client, records):
    data = client.api("mpfs/bulk-download-prepare", {"items": [row["file_id"] for row in records]})
    url = data.get("download_url")
    if isinstance(url, str) and url.startswith("//"):
        url = "https:" + url
    return validate_url(url, archive=True)


def download_zip(url, target, max_bytes, timeout=120, progress=False):
    try:
        with archive_response(url, timeout=timeout) as response, target.open("xb") as output:
            header = response.headers.get("Content-Length")
            declared = int(header) if header is not None else None
            if declared is not None and (declared < 0 or declared > max_bytes):
                raise SafeError("Archive Content-Length exceeds the configured byte limit.")
            count = 0
            last_report = time.monotonic()
            while chunk := response.read(CHUNK):
                count += len(chunk)
                if count > max_bytes:
                    raise SafeError("Archive exceeds the configured byte limit.")
                output.write(chunk)
                if progress and time.monotonic() - last_report >= 10:
                    print(f"Downloading ZIP: {count / 1024**2:.1f} MiB", flush=True)
                    last_report = time.monotonic()
            if declared is not None and count != declared:
                raise SafeError("Truncated archive download.")
            output.flush()
            os.fsync(output.fileno())
    except SafeError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ENOSPC, errno.EDQUOT, errno.EACCES, errno.EROFS, errno.EIO):
            raise FatalError("Local storage failed; free space/permissions must be fixed before resuming.") from None
        raise NetworkError("Archive connection failed; download deferred.") from None
    except Exception:
        raise NetworkError("Archive transfer failed; download deferred.") from None


def archive_members(archive):
    result = {}
    for member in archive.infolist():
        raw = member.filename
        path = PurePosixPath(raw)
        mode = member.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if (member.orig_filename != raw or not raw or raw.startswith("/") or "\\" in raw
                or ":" in raw or ".." in path.parts
                or any(ord(c) < 32 or ord(c) == 127 for c in raw)
                or kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                or member.flag_bits & 1):
            raise SafeError("Unsafe, special, symlink or encrypted ZIP member rejected.")
        if member.is_dir():
            continue
        if kind == stat.S_IFDIR:
            raise SafeError("ZIP member type conflicts with its name.")
        name = safe_name(path.name)
        if name in result:
            raise SafeError("Ambiguous duplicate basenames in ZIP; use a smaller batch.")
        result[name] = member
    return result


def digest_stream(src, dst=None, expected_size=None):
    md5, sha256, size = hashlib.md5(usedforsecurity=False), hashlib.sha256(), 0
    while chunk := src.read(CHUNK):
        size += len(chunk)
        if expected_size is not None and size > expected_size:
            raise SafeError("File is larger than its manifest size.")
        md5.update(chunk)
        sha256.update(chunk)
        if dst is not None:
            dst.write(chunk)
    if expected_size is not None and size != expected_size:
        raise SafeError("File size differs from manifest.")
    return size, md5.hexdigest(), sha256.hexdigest()


def verify_zip(zip_path, records, staging):
    """Validate the entire requested set before publishing any file or DB success."""
    expected = {safe_name(row["name"]): row for row in records}
    if len(expected) != len(records):
        raise SafeError("Batch contains ambiguous names.")
    verified = []
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = archive_members(archive)
            if set(members) != set(expected):
                raise SafeError("ZIP has missing/unexpected files; no files in this batch are marked downloaded.")
            for name, row in expected.items():
                member = members[name]
                if member.file_size != row["size"]:
                    raise SafeError("ZIP member size differs from manifest.")
                key = hashlib.sha256(row["file_id"].encode("utf-8")).hexdigest()
                temp_file = staging / (key + ".part")
                with archive.open(member) as src, temp_file.open("xb") as output:
                    _, md5, sha256 = digest_stream(src, output, row["size"])
                    output.flush()
                    os.fsync(output.fileno())
                # ZipExtFile also validates CRC when read through EOF.
                if row["md5"] and md5 != row["md5"]:
                    raise SafeError("File checksum differs from upstream MD5.")
                verified.append((row["file_id"], key, name, temp_file, sha256))
    except (zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError):
        raise SafeError("Invalid, truncated, corrupt or unsupported ZIP archive.") from None
    return verified


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def commit_batch(conn, verified, output):
    # Hashed resource ID directory preserves equal filenames from different resources.
    # Staging is on the same filesystem so os.replace is atomic.
    destinations = []
    for fid, key, name, staged, sha256 in verified:
        folder = private_dir(output / key)
        target = folder / name
        if target.exists() or target.is_symlink():
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise SafeError("Unsafe existing output file.")
            with target.open("rb") as source:
                _, _, old_sha = digest_stream(source)
            if old_sha != sha256:
                raise SafeError("Existing output differs; refusing to overwrite it.")
        destinations.append((fid, staged, target, sha256))
    for fid, staged, target, sha256 in destinations:
        os.replace(staged, target)
        fsync_dir(target.parent)
    fsync_dir(output)
    with conn:
        conn.executemany(
            "UPDATE unlim_files SET status='downloaded',local_path=?,sha256=?,"
            "name=?,size=?,downloaded_at=CURRENT_TIMESTAMP,error=NULL WHERE file_id=?",
            [(str(target), sha256, target.name, target.stat().st_size, fid)
             for fid, _, target, sha256 in destinations])
        conn.executemany("DELETE FROM rescue_issues WHERE scope='file' AND item_key=?",
                         [(fid,) for fid, _, _, _ in destinations])


def next_batch(conn, count, max_bytes, *, rescue=False):
    rows, names, size = [], set(), 0
    for row in conn.execute("SELECT * FROM unlim_files WHERE status='pending' ORDER BY file_id"):
        if row["size"] > max_bytes:
            if rescue:
                defer_records(conn, [dict(row)], "File exceeds --max-batch-bytes; increase limit and retry errors.")
                continue
            if not rows:
                raise SafeError("A pending file exceeds --max-batch-bytes. Increase it explicitly.")
            break
        if row["name"] in names:
            continue
        if rows and size + row["size"] > max_bytes:
            break
        if rescue and not row["name_known"] and rows:
            continue
        rows.append(dict(row))
        names.add(row["name"])
        size += row["size"]
        if len(rows) >= count or (rescue and not row["name_known"]):
            break
    return rows


def defer_records(conn, records, reason):
    for row in records:
        record_issue(conn, "file", row["file_id"], reason)
    with conn:
        conn.executemany("UPDATE unlim_files SET status='error',error=? "
                         "WHERE file_id=? AND status!='downloaded'",
                         [(reason, row["file_id"]) for row in records])


def rescue_zip(zip_path, records, staging, max_extracted_bytes):
    """Verify each available requested member independently; never mark a missing one done."""
    verified, failed, extracted = [], [], 0
    try:
        with zipfile.ZipFile(zip_path) as archive:
            members = archive_members(archive)
            for row in records:
                if row.get("name_known", 1):
                    name = safe_name(row["name"])
                elif len(records) == 1 and len(members) == 1:
                    name = next(iter(members))
                else:
                    failed.append(row)
                    continue
                member = members.get(name)
                if member is None:
                    failed.append(row)
                    continue
                if (member.file_size > max_extracted_bytes - extracted or
                        (row.get("size_known", 1) and member.file_size != row["size"])):
                    failed.append(row)
                    continue
                key = hashlib.sha256(row["file_id"].encode()).hexdigest()
                part = staging / (key + ".part")
                extracted += member.file_size
                try:
                    with archive.open(member) as src, part.open("xb") as dst:
                        _, md5, sha256 = digest_stream(src, dst, expected_size=member.file_size)
                        dst.flush()
                        os.fsync(dst.fileno())
                    if row["md5"] and md5 != row["md5"]:
                        raise SafeError("File checksum differs from upstream MD5.")
                    verified.append((row["file_id"], key, name, part, sha256))
                except (SafeError, zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError, zlib.error):
                    failed.append(row)
                    part.unlink(missing_ok=True)
    except (zipfile.BadZipFile, EOFError, RuntimeError, NotImplementedError, ValueError, zlib.error):
        raise SafeError("Archive is incomplete or unreadable; retry separately.") from None
    return verified, failed


def rescue_download(conn, client, records, output, max_archive_bytes, max_extracted_bytes):
    expected = sum(row["size"] for row in records)
    known = all(row.get("size_known", 1) for row in records)
    # ZIP can slightly exceed its payload, but reserve space for both copies.
    zip_limit = min(max_archive_bytes, expected + expected // 20 + 16 * 1024**2) if known else max_archive_bytes
    extract_limit = expected if known else max_extracted_bytes
    if shutil.disk_usage(output).free < zip_limit + extract_limit + 64 * 1024**2:
        raise FatalError("Insufficient local free space; completed files preserved. Free space before resuming.")
    downloaded = 0
    try:
        with tempfile.TemporaryDirectory(prefix=".batch-", dir=output) as tmp:
            staging = Path(tmp)
            archive = staging / "archive.zip"
            download_zip(prepare_zip(client, records), archive, zip_limit, timeout=client.timeout, progress=True)
            verified, failed = rescue_zip(archive, records, staging, max_extracted_bytes)
            lookup = {row["file_id"]: row for row in records}
            for entry in verified:
                try:
                    commit_batch(conn, [entry], output)
                    downloaded += 1
                except SafeError:
                    defer_records(conn, [lookup[entry[0]]], "Local output conflict; original preserved.")
            if failed:
                defer_records(conn, failed, "Missing/corrupt/oversized ZIP member; other valid files preserved.")
    except FatalError:
        raise
    except NetworkError as exc:
        defer_records(conn, records, str(exc))
        print(f"Download deferred for {len(records)} files: {exc}", flush=True)
        time.sleep(1)
    except SafeError as exc:
        if len(records) > 1:
            print(f"Batch unavailable; trying {len(records)} files separately.", flush=True)
            for row in records:
                downloaded += rescue_download(conn, client, [row], output, max_archive_bytes, max_extracted_bytes)
        else:
            defer_records(conn, records, str(exc))
            print(f"One file deferred: {exc}", flush=True)
    return downloaded


def run_rescue(conn, client, output, args):
    if args.retry_errors:
        with conn:
            conn.execute("UPDATE unlim_files SET status='pending',error=NULL WHERE status='error'")
    batches, total = 0, 0

    def drain():
        nonlocal batches, total
        while not args.max_batches or batches < args.max_batches:
            records = next_batch(conn, args.batch, args.max_batch_bytes, rescue=True)
            if not records:
                return False
            total += rescue_download(conn, client, records, output, args.max_archive_bytes, args.max_batch_bytes)
            batches += 1
            deferred = conn.execute("SELECT COUNT(*) FROM unlim_files WHERE status='error'").fetchone()[0]
            print(f"Rescue: saved this run: {total}; deferred files: {deferred}; batches: {batches}", flush=True)
        return True

    # Resume pending downloads before doing any new metadata requests.
    if drain():
        return
    for _ in rescue_inventory(conn, client, retry_errors=args.retry_errors, refresh=args.refresh_snapshot):
        if drain():
            return
    print_status(conn)
    missing = conn.execute("SELECT COUNT(*) FROM rescue_progress WHERE failed=1").fetchone()[0]
    print(f"Rescue pass finished. Incomplete metadata clusters: {missing}. "
          "Use --rescue --retry-errors for another attempt at deferred work.", flush=True)


def verify_local(conn, output):
    bad, checked = [], 0
    for row in conn.execute("SELECT * FROM unlim_files WHERE status='downloaded'"):
        checked += 1
        key = hashlib.sha256(row["file_id"].encode("utf-8")).hexdigest()
        target = output / key / safe_name(row["name"])
        try:
            if str(target) != row["local_path"]:
                raise SafeError("Unexpected stored output path.")
            private_dir(target.parent)
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise SafeError("Unsafe output file.")
            with target.open("rb") as source:
                _, md5, sha256 = digest_stream(source, expected_size=row["size"])
            if sha256 != row["sha256"] or (row["md5"] and md5 != row["md5"]):
                raise SafeError("Local checksum mismatch.")
        except (OSError, SafeError):
            bad.append(row["file_id"])
    # Read-only audit: never silently reset/delete/overwrite damaged local files.
    print(f"Local verification: {checked - len(bad)}/{checked} valid; missing/corrupt: {len(bad)}")
    if bad:
        raise SafeError("Local verification failed. Preserve originals and investigate before continuing.")


def download_batch(conn, client, records, output, max_archive_bytes):
    expected_bytes = sum(row["size"] for row in records)
    # Worst-case reservation, including ZIP + extracted data. Not a lifetime quota.
    if shutil.disk_usage(output).free < expected_bytes + max_archive_bytes + 64 * 1024 * 1024:
        raise SafeError("Insufficient free space for ZIP, extracted batch and safety margin.")
    with tempfile.TemporaryDirectory(prefix=".batch-", dir=output) as tmp:
        staging = Path(tmp)
        zip_path = staging / "archive.zip"
        url = prepare_zip(client, records)
        download_zip(url, zip_path, max_archive_bytes)
        verified = verify_zip(zip_path, records, staging)
        commit_batch(conn, verified, output)
    return len(records), expected_bytes


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--output", type=Path, help="Private output directory, defaults to STATE/files")
    parser.add_argument("--batch", type=int, default=25)
    parser.add_argument("--max-batch-bytes", type=int, default=4 * 1024**3)
    parser.add_argument("--max-archive-bytes", type=int, default=5 * 1024**3)
    parser.add_argument("--max-batches", type=int, default=0, help="0 = all, 1 = a trial batch")
    parser.add_argument("--verify", action="store_true", help="Check local files offline, no cookies needed")
    parser.add_argument("--rescue", action="store_true", help="Collect and download incrementally; defer individual failures")
    parser.add_argument("--retry-errors", action="store_true", help="Retry previously deferred files and metadata in rescue mode")
    parser.add_argument("--refresh-snapshot", action="store_true", help="Rescan metadata from a fresh snapshot; keep completed files")
    parser.add_argument("--timeout", type=int, default=30, help="Rescue network inactivity timeout in seconds")
    parser.add_argument("--passes", type=int, default=1, help="Rescue passes; later passes retry only deferred work")
    args = parser.parse_args()
    if not 1 <= args.batch <= 250 or args.max_batch_bytes < 1 or args.max_archive_bytes < 1 or args.max_batches < 0 or args.timeout < 1 or args.passes < 1:
        parser.error("Invalid batch/byte limits")
    if (args.retry_errors or args.refresh_snapshot or args.passes != 1) and not args.rescue:
        parser.error("--retry-errors, --refresh-snapshot and --passes require --rescue")
    configure_runtime()
    state = private_dir(args.state_dir)
    with state_lock(state):
        conn = connect_db(state)
        try:
            output = private_dir(args.output or state / "files")
            bound_output = meta(conn, "output_directory")
            if bound_output and bound_output != str(output):
                raise SafeError("Manifest is bound to a different output directory.")
            if args.verify:
                verify_local(conn, output)
                return 0
            if not args.rescue and meta(conn, "collection_complete") != "1":
                raise SafeError("Collect a complete inventory before downloading.")
            meta(conn, "output_directory", output)
            conn.commit()
            if not args.rescue:
                verify_local(conn, output)
            client = YandexClient(load_cookies(args.cookies or state / "cookies.json"),
                                 timeout=args.timeout if args.rescue else 120,
                                 attempts=1 if args.rescue else 3)
            client.login()
            bind_account(conn, client.uid)
            if args.rescue:
                for pass_number in range(args.passes):
                    print(f"Rescue pass {pass_number + 1}/{args.passes}", flush=True)
                    run_rescue(conn, client, output, args)
                    deferred = conn.execute("SELECT COUNT(*) FROM unlim_files WHERE status='error'").fetchone()[0]
                    incomplete = conn.execute("SELECT COUNT(*) FROM rescue_progress WHERE failed=1").fetchone()[0]
                    if args.max_batches or not (deferred or incomplete):
                        break
                    if pass_number + 1 < args.passes:
                        args.retry_errors, args.refresh_snapshot = True, False
                        print("Pausing 30 seconds before retrying deferred work.", flush=True)
                        time.sleep(30)
                return 0
            batches, total = 0, 0
            while not args.max_batches or batches < args.max_batches:
                records = next_batch(conn, args.batch, args.max_batch_bytes)
                if not records:
                    break
                # Rows stay pending until the entire batch is verified and atomically recorded.
                count, _ = download_batch(conn, client, records, output, args.max_archive_bytes)
                batches += 1
                total += count
                print(f"Verified batches: {batches}; downloaded this run: {total}", flush=True)
            pending = conn.execute("SELECT COUNT(*) FROM unlim_files WHERE status='pending'").fetchone()[0]
            print(f"Run finished; pending resources: {pending}")
        finally:
            conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(run_cli(main))
