"""Verified photoslice download worker. Standard library only; see README_SAFE.md."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

from unlim_download import (
    SafeError, YandexClient, base_parser, bind_account, build_opener,
    configure_runtime, connect_db, load_cookies, meta, open_no_redirect,
    private_dir, run_cli, safe_name, state_lock, validate_url,
)

CHUNK = 1024 * 1024


def archive_response(url, opener=None):
    """Every hop revalidated, no cookie jar/auth headers/referer on the CDN session."""
    opener = opener or build_opener()
    for _ in range(6):
        validate_url(url, archive=True)
        request = urllib.request.Request(url, headers={"User-Agent": "yadisk-unlim-safe/1", "Accept": "application/zip"})
        response = open_no_redirect(opener, request, 120)
        if response.code == 200:
            return response
        location = response.headers.get("Location")
        status = response.code
        response.close()
        if status in (301, 302, 303, 307, 308) and location:
            url = urllib.parse.urljoin(url, location)
            continue
        raise SafeError("Archive server refused the download; response and URL omitted.")
    raise SafeError("Too many archive redirects.")


def prepare_zip(client, records):
    data = client.api("mpfs/bulk-download-prepare", {"items": [row["file_id"] for row in records]})
    url = data.get("download_url")
    if isinstance(url, str) and url.startswith("//"):
        url = "https:" + url
    return validate_url(url, archive=True)


def download_zip(url, target, max_bytes):
    try:
        with archive_response(url) as response, target.open("xb") as output:
            header = response.headers.get("Content-Length")
            declared = int(header) if header is not None else None
            if declared is not None and (declared < 0 or declared > max_bytes):
                raise SafeError("Archive Content-Length exceeds the configured byte limit.")
            count = 0
            while chunk := response.read(CHUNK):
                count += len(chunk)
                if count > max_bytes:
                    raise SafeError("Archive exceeds the configured byte limit.")
                output.write(chunk)
            if declared is not None and count != declared:
                raise SafeError("Truncated archive download.")
            output.flush()
            os.fsync(output.fileno())
    except SafeError:
        raise
    except Exception:
        raise SafeError("Archive network/disk write failed; retry this batch after resolving the cause.") from None


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
            "downloaded_at=CURRENT_TIMESTAMP,error=NULL WHERE file_id=?",
            [(str(target), sha256, fid) for fid, _, target, sha256 in destinations])


def next_batch(conn, count, max_bytes):
    rows, names, size = [], set(), 0
    for row in conn.execute("SELECT * FROM unlim_files WHERE status='pending' ORDER BY file_id"):
        if row["size"] > max_bytes:
            if not rows:
                raise SafeError("A pending file exceeds --max-batch-bytes. Increase it explicitly.")
            break
        if row["name"] in names:
            continue
        if rows and size + row["size"] > max_bytes:
            break
        rows.append(dict(row))
        names.add(row["name"])
        size += row["size"]
        if len(rows) >= count:
            break
    return rows


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
    args = parser.parse_args()
    if not 1 <= args.batch <= 250 or args.max_batch_bytes < 1 or args.max_archive_bytes < 1 or args.max_batches < 0:
        parser.error("Invalid batch/byte limits")
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
            if meta(conn, "collection_complete") != "1":
                raise SafeError("Collect a complete inventory before downloading.")
            meta(conn, "output_directory", output)
            conn.commit()
            verify_local(conn, output)
            client = YandexClient(load_cookies(args.cookies or state / "cookies.json"))
            client.login()
            bind_account(conn, client.uid)
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
