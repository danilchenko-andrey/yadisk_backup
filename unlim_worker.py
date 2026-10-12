"""Verified photoslice download worker. Standard library only; see README_SAFE.md."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
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
    record_issue, rescue_inventory, media_inventory, print_status,
)

CHUNK = 1024 * 1024
REMOTE_DIRECTORY_LOCK = threading.Lock()
REMOTE_DIRECTORIES = set()


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


# Individual-media rescue is separate from the legacy ZIP worker. A preview never
# changes the original's status. Assets are durable before any upload or cleanup.
def preview_candidates(sizes):
    ranks = {name: n for n, name in enumerate(['C', 'XXXS', 'XXS', 'XS', 'S', 'M', 'L', 'XL', 'XXL', 'XXXL'], 1)}
    candidates = {}
    for entry in sizes:
        url, name = entry.get('url'), str(entry.get('name', '')).upper()
        if not isinstance(url, str) or name == 'ORIGINAL':
            continue
        try:
            validate_url(url, archive=True)
            parsed = urllib.parse.urlsplit(url)
            if not parsed.path.startswith('/preview/'):
                continue
            query = urllib.parse.parse_qs(parsed.query)
            if query.get('crop', ['0'])[0] == '1':
                continue
            size = query.get('size', [name])[0].upper()
            rank = ranks.get(size, 0)
            match = re.fullmatch(r'(\d+)X(\d+)', size)
            if match:
                rank = 10 + min(int(match[1]), int(match[2])) / 10000
            if name == 'DEFAULT' and not query.get('size'):
                # The base preview URL supports the documented named sizes.
                for size in ('XXXL', 'XXL', 'XL'):
                    q = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                    q = [(k, v) for k, v in q if k not in ('size', 'crop')]
                    candidate = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(q + [('size', size), ('crop', '0')])))
                    candidates[candidate] = ranks[size]
            candidates[url] = rank
        except (SafeError, ValueError, TypeError):
            continue
    return sorted(candidates, key=candidates.get, reverse=True)


def image_dimensions(path):
    """Basic container validation, not a full pixel decoder. Never accept HTML as a preview."""
    data = path.read_bytes()  # Preview downloads have a separate 32 MiB cap.
    if data.startswith(b'\xff\xd8') and data.endswith(b'\xff\xd9'):
        i = 2
        while i + 4 <= len(data):
            if data[i] != 255:
                break
            while i < len(data) and data[i] == 255:
                i += 1
            marker = data[i]
            i += 1
            if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
                continue
            length = int.from_bytes(data[i:i+2], 'big')
            if length < 2 or i + length > len(data):
                break
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF) and length >= 8:
                height, width = struct.unpack('>HH', data[i+3:i+7])
                if width and height:
                    return '.jpg', width, height
            if marker == 0xDA:
                break
            i += length
    elif data.startswith(b'\x89PNG\r\n\x1a\n'):
        i, width, height = 8, 0, 0
        while i + 12 <= len(data):
            length = int.from_bytes(data[i:i+4], 'big')
            end = i + 12 + length
            if end > len(data):
                break
            kind, payload = data[i+4:i+8], data[i+8:i+8+length]
            if zlib.crc32(kind + payload) & 0xffffffff != int.from_bytes(data[end-4:end], 'big'):
                break
            if kind == b'IHDR' and length == 13:
                width, height = struct.unpack('>II', payload[:8])
            if kind == b'IEND' and end == len(data) and width and height:
                return '.png', width, height
            i = end
    elif data[:6] in (b'GIF87a', b'GIF89a') and len(data) > 13 and data.endswith(b';'):
        width, height = struct.unpack('<HH', data[6:10])
        if width and height:
            return '.gif', width, height
    elif data.startswith(b'RIFF') and data[8:12] == b'WEBP' and len(data) >= 30 and int.from_bytes(data[4:8], 'little') + 8 == len(data):
        if data[12:16] == b'VP8X':
            return '.webp', 1 + int.from_bytes(data[24:27], 'little'), 1 + int.from_bytes(data[27:30], 'little')
        if data[12:16] == b'VP8 ' and data[23:26] == b'\x9d\x01\x2a':
            width, height = struct.unpack('<HH', data[26:30])
            if width & 0x3fff and height & 0x3fff:
                return '.webp', width & 0x3fff, height & 0x3fff
        if data[12:16] == b'VP8L' and data[20] == 0x2f:
            bits = int.from_bytes(data[21:25], 'little')
            return '.webp', (bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1
    raise SafeError('Preview is incomplete, not an image, or has an unsupported image container.')


def media_response(url, timeout, cookies=None):
    opener = build_opener()  # Redirects and cookie forwarding are handled explicitly.
    for _ in range(6):
        validate_url(url, archive=True)
        request = urllib.request.Request(url, headers={'Accept': '*/*'})
        host = urllib.parse.urlsplit(url).hostname
        # Private previews need the existing session's domain-scoped cookies.
        # Rebuild headers on every hop; never carry them to storage or other hosts.
        if cookies is not None and (host == 'downloader.disk.yandex.ru' or
                                    re.fullmatch(r'[0-9]+\.downloader\.disk\.yandex\.ru', host)):
            cookies.add_cookie_header(request)
        response = open_no_redirect(opener, request, timeout)
        if response.code == 200:
            return response
        status, location = response.code, response.headers.get('Location')
        response.close()
        if status in (301, 302, 303, 307, 308) and location:
            url = urllib.parse.urljoin(url, location)
            continue
        if status == 429 or status >= 500:
            if status == 429:
                time.sleep(30)
            raise NetworkError(f'Media HTTP {status}: temporarily unavailable; file deferred.')
        raise SafeError(f'Media HTTP {status}: URL unavailable; file deferred.')
    raise SafeError('Too many media redirects.')


def download_media(url, target, limit, timeout, deadline_seconds, cookies=None):
    start = time.monotonic()
    try:
        with media_response(url, timeout, cookies=cookies) as response, target.open('xb') as dst:
            raw_length = response.headers.get('Content-Length')
            length = int(raw_length) if raw_length is not None else None
            if length is not None and not 0 < length <= limit:
                raise SafeError('Media response exceeds the size limit or is empty.')
            count = 0
            while block := response.read(CHUNK):
                count += len(block)
                if count > limit:
                    raise SafeError('Media download exceeds the size limit.')
                if time.monotonic() - start > deadline_seconds:
                    raise NetworkError('Media download exceeded its time budget; deferred.')
                dst.write(block)
            if not count or (length is not None and count != length):
                raise SafeError('Media download is empty or truncated.')
            dst.flush()
            os.fsync(dst.fileno())
    except SafeError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ENOSPC, errno.EDQUOT, errno.EACCES, errno.EROFS, errno.EIO):
            raise FatalError('Local storage failed; completed files preserved.') from None
        raise NetworkError('Media connection failed; file deferred.') from None
    except Exception:
        raise NetworkError('Media transfer failed; file deferred.') from None


def save_asset(conn, row, variant, staged, output, extension=None, width=None, height=None):
    key = hashlib.sha256(row['file_id'].encode()).hexdigest()
    folder = private_dir(private_dir(output / variant) / key[:2])
    # Full resource hash prevents collisions. Original name remains in the manifest.
    original_name = safe_name(row['name'])
    stem = Path(original_name).stem.encode('utf-8')[:120].decode('utf-8', errors='ignore')
    name = stem + '--' + key + (extension or Path(original_name).suffix.lower())
    target = folder / safe_name(name)
    with staged.open('rb') as stream:
        size, md5, sha = digest_stream(stream)
    if target.exists() or target.is_symlink():
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise FatalError('Unsafe existing media output; preserved.')
        with target.open('rb') as stream:
            if digest_stream(stream)[2] != sha:
                raise FatalError('Existing media output differs; preserved for investigation.')
    os.replace(staged, target)
    fsync_dir(folder)
    with conn:
        conn.execute("INSERT INTO rescue_assets(file_id,variant,status,local_path,size,md5,sha256,width,height) "
                     "VALUES(?,?,'local',?,?,?,?,?,?) ON CONFLICT(file_id,variant) DO UPDATE SET "
                     "status='local',local_path=excluded.local_path,size=excluded.size,md5=excluded.md5,"
                     "sha256=excluded.sha256,width=excluded.width,height=excluded.height,error=NULL",
                     (row['file_id'], variant, str(target), size, md5, sha, width, height))
    return target


def rclone_failure(stderr):
    """Return only fixed diagnostic labels, never private stderr/paths/tokens."""
    message = stderr.decode('utf-8', errors='replace').lower()
    for markers, label, retryable in (
        (('invalid_grant', 'invalid credentials', 'unauthorized', 'token has been expired'), 'authentication failed', False),
        (('storagequotaexceeded', 'storage quota exceeded'), 'Drive storage quota exceeded', False),
        (('dailylimitexceeded', 'daily limit exceeded', 'upload limit'), 'Drive daily limit reached', False),
        (('immutable',), 'existing destination differs (immutable)', False),
        (('no space left on device',), 'local disk full', False),
        (('userratelimitexceeded', 'ratelimitexceeded', 'rate limit', 'error 429'), 'Drive rate limit', True),
        (('directory not found', 'object not found', 'file not found'), 'destination not found', True),
        (('timeout', 'timed out', 'deadline exceeded', 'connection reset', 'tls handshake', 'temporary failure'), 'network timeout/failure', True),
        (('backenderror', 'internalerror', 'error 500', 'error 502', 'error 503', 'error 504'), 'Drive server failure', True),
        (('insufficientpermissions', 'permission denied', 'access denied'), 'permission denied', False),
    ):
        if any(marker in message for marker in markers):
            return label, retryable
    return 'unclassified failure (private stderr omitted)', True


def rclone_run(argv, missing_ok=False):
    operation = argv[0] if argv[0] in ('mkdir', 'copyto', 'lsjson', 'moveto', 'rmdirs') else 'command'
    for attempt in range(3):
        try:
            result = subprocess.run(['rclone', *argv, '--contimeout', '30s', '--timeout', '3m',
                                     '--retries', '2', '--low-level-retries', '1'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900, check=False)
            if not result.returncode:
                return result.stdout
            reason, retryable = rclone_failure(result.stderr)
            if (missing_ok and reason == 'destination not found'
                    and (result.returncode in (3, 4) or operation == 'rmdirs')):
                return None
            if operation == 'moveto' and reason == 'destination not found':
                retryable = False  # Caller checks whether the move already completed.
            detail = f'exit {result.returncode}; {reason}'
        except subprocess.TimeoutExpired:
            detail, retryable = 'process time limit exceeded', True
        except OSError:
            raise FatalError(f'rclone {operation} could not start; local copies kept.') from None
        if not retryable or attempt == 2:
            raise FatalError(f'rclone {operation} failed ({detail}); local copies kept. Retry after fixing Drive access.')
        pause = 30 * (attempt + 1)
        print(f'rclone {operation}: {detail}; retry {attempt + 2}/3 in {pause}s; local copy kept.', flush=True)
        time.sleep(pause)


def ensure_remote_directory(destination):
    # Independent rclone processes can race to create the same Drive folder.
    # Serialize creation of ALL parents, even when leaf folders differ; transfers
    # remain concurrent once their parent is known to exist. Cache only success.
    directory = destination.rsplit('/', 1)[0]
    with REMOTE_DIRECTORY_LOCK:
        if directory not in REMOTE_DIRECTORIES:
            rclone_run(['mkdir', directory])
            REMOTE_DIRECTORIES.add(directory)


def asset_destinations(asset, output, remote):
    try:
        relative = Path(asset['local_path']).relative_to(output)
    except (ValueError, TypeError):
        raise FatalError('Unexpected local asset path; refusing remote changes.') from None
    if (asset['variant'] not in ('preview', 'original') or len(relative.parts) != 3
            or relative.parts[0] != asset['variant']
            or not re.fullmatch(r'[0-9a-f]{2}', relative.parts[1])):
        raise FatalError('Unexpected asset layout; refusing remote changes.')
    name = safe_name(relative.name)
    legacy = remote.rstrip('/') + '/' + relative.as_posix()
    flat = remote.rstrip('/') + '/' + asset['variant'] + '--' + name
    if asset['remote_path'] not in (None, legacy, flat):
        raise FatalError('Asset belongs to a different remote; refusing remote changes.')
    return legacy, flat


def remote_record(destination):
    raw = rclone_run(['lsjson', destination, '--stat', '--hash'], missing_ok=True)
    if raw is None:
        return None
    try:
        record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError
        return record
    except (ValueError, TypeError):
        raise FatalError('Invalid Drive metadata; local files and checkpoints kept.') from None


def matches_asset(record, asset):
    if not isinstance(record, dict) or not isinstance(record.get('Hashes'), dict):
        return False
    hashes = {key.lower().replace('-', ''): value for key, value in record['Hashes'].items()}
    return (record.get('IsDir') is False and record.get('Size') == asset['size']
            and str(hashes.get('md5', '')).lower() == asset['md5'])


def flatten_asset(conn, asset, output, remote):
    legacy, flat = asset_destinations(asset, output, remote)
    if asset['remote_path'] == flat:
        return
    current = remote_record(flat)
    if current is not None and not matches_asset(current, asset):
        raise FatalError('Flat destination differs from saved checksum; both copies preserved.')
    old = remote_record(legacy)
    if old is not None:
        if not matches_asset(old, asset):
            raise FatalError('Legacy Drive file differs from saved checksum; preserved.')
        try:
            rclone_run(['moveto', legacy, flat, '--checksum', '--immutable'])
        except FatalError:
            # The server may have completed the move before a connection failed.
            if not matches_asset(remote_record(flat), asset) or remote_record(legacy) is not None:
                raise
        current = remote_record(flat)
        if not matches_asset(current, asset):
            raise FatalError('Moved file failed Drive checksum verification; checkpoint kept for retry.')
    if current is None:
        if asset['status'] == 'local' and Path(asset['local_path']).is_file():
            return  # Normal offload will upload directly to the flat folder.
        raise FatalError('Previously saved Drive file not found; checkpoint preserved.')
    with conn:
        conn.execute('UPDATE rescue_assets SET remote_path=? WHERE file_id=? AND variant=?',
                     (flat, asset['file_id'], asset['variant']))


def flatten_remote_layout(conn, output, remote, workers=8):
    previous = meta(conn, 'media_remote')
    if previous and previous != remote:
        raise FatalError('Media manifest is bound to another remote.')
    if meta(conn, 'media_remote_layout') == 'flat-v1':
        return
    assets = [dict(row) for row in conn.execute(
        "SELECT * FROM rescue_assets WHERE status IN ('remote','uploaded','local')")]
    ensure_remote_directory(remote.rstrip('/') + '/placeholder')
    if assets:
        print(f'Flattening Drive layout: checking {len(assets)} saved assets; no Yandex downloads.', flush=True)
        database = conn.execute('PRAGMA database_list').fetchone()[2]
        def migrate(asset):
            worker_conn = sqlite3.connect(database, timeout=30)
            try:
                flatten_asset(worker_conn, asset, output, remote)
            finally:
                worker_conn.close()
        pending = iter(assets)
        pool = ThreadPoolExecutor(max_workers=workers)
        futures = {pool.submit(migrate, asset) for asset in assets[:workers]}
        for _ in futures:
            next(pending)
        number = 0
        try:
            while futures:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
                    number += 1
                    if number % 10 == 0 or number == len(assets):
                        print(f'Drive layout checked: {number}/{len(assets)}', flush=True)
                for _ in done:
                    asset = next(pending, None)
                    if asset is not None:
                        futures.add(pool.submit(migrate, asset))
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        # Only empty directories are removed; unrelated/nonempty folders stay.
        for variant in sorted({asset['variant'] for asset in assets}):
            rclone_run(['rmdirs', remote.rstrip('/') + '/' + variant], missing_ok=True)
    with conn:
        meta(conn, 'media_remote', remote)
        meta(conn, 'media_remote_layout', 'flat-v1')
    print('Drive layout: one folder; preview-- / original-- filename prefixes.', flush=True)


def offload_asset(conn, asset, output, remote):
    if not remote:
        return
    target = Path(asset['local_path'])
    _, destination = asset_destinations(asset, output, remote)
    private_dir(target.parent)
    if asset['remote_path'] and asset['remote_path'] != destination:
        raise FatalError('Run Drive layout migration before offload; local copy kept.')
    exists = target.exists() or target.is_symlink()
    if exists:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise FatalError('Unsafe local asset; refusing upload or deletion.')
        with target.open('rb') as stream:
            size, md5, sha = digest_stream(stream)
        if (size, md5, sha) != (asset['size'], asset['md5'], asset['sha256']):
            raise FatalError('Local asset changed; refusing upload or deletion.')
    elif asset['status'] != 'uploaded':
        raise FatalError('Local asset missing before verified upload.')
    if asset['status'] != 'uploaded':
        ensure_remote_directory(destination)
        rclone_run(['copyto', str(target), destination, '--checksum', '--immutable'])
    try:
        record = json.loads(rclone_run(['lsjson', destination, '--stat', '--hash']))
        hashes = {key.lower().replace('-', ''): value for key, value in record.get('Hashes', {}).items()}
        valid = (record.get('IsDir') is False and record.get('Size') == asset['size']
                 and str(hashes.get('md5', '')).lower() == asset['md5'])
    except (ValueError, AttributeError, TypeError):
        valid = False
    if not valid:
        raise FatalError('Remote size/MD5 verification failed; local copy kept.')
    # Checkpoint precedes deletion. Restart handles either side of the unlink.
    with conn:
        conn.execute("UPDATE rescue_assets SET status='uploaded',remote_path=? WHERE file_id=? AND variant=?",
                     (destination, asset['file_id'], asset['variant']))
    if exists:
        now = target.lstat()
        if (now.st_ino, now.st_size, now.st_mtime_ns) != (info.st_ino, info.st_size, info.st_mtime_ns):
            raise FatalError('Local asset changed during upload; copy kept.')
        target.unlink()
        fsync_dir(target.parent)
    with conn:
        conn.execute("UPDATE rescue_assets SET status='remote' WHERE file_id=? AND variant=?", (asset['file_id'], asset['variant']))


def rescue_one_media(conn, client, row, variant, output, args):
    sizes = json.loads(row['sizes_json'])
    known = row['size_known'] and row['size'] > 0
    limit = 32 * 1024**2 if variant == 'preview' else (min(args.max_batch_bytes, row['size']) if known else args.max_batch_bytes)
    if variant == 'original' and known and row['size'] > args.max_batch_bytes:
        raise SafeError('Original exceeds configured maximum; deferred.')
    if shutil.disk_usage(output).free < limit + 128 * 1024**2:
        raise FatalError('Not enough local space for one file; previous files preserved.')
    with tempfile.TemporaryDirectory(prefix='.media-', dir=output) as tmp:
        staged = Path(tmp) / 'file.part'
        if variant == 'preview':
            urls = preview_candidates(sizes)
            if not urls:
                raise SafeError('No supported preview URL in metadata.')
        else:
            result = client.api('mpfs/url', {'path': row['path']})
            url = result.get('file')
            if isinstance(url, str) and url.startswith('//'):
                url = 'https:' + url
            urls = [validate_url(url, archive=True)]
        last_error = None
        for url in urls[:4]:
            try:
                download_media(url, staged, limit, args.timeout, 45 if variant == 'preview' else 300,
                               cookies=getattr(client, 'cookies', None))
                if variant == 'preview':
                    ext, width, height = image_dimensions(staged)
                else:
                    ext, width, height = None, None, None
                    with staged.open('rb') as source:
                        size, md5, _ = digest_stream(source, expected_size=row['size'] if known else None)
                    if row['md5'] and row['md5'] != md5:
                        raise SafeError('Original checksum differs from metadata.')
                save_asset(conn, row, variant, staged, output, ext, width, height)
                return
            except FatalError:
                raise
            except SafeError as exc:
                last_error = exc
                staged.unlink(missing_ok=True)
                if isinstance(exc, NetworkError):
                    # Do not fan out a server/rate-limit error into four requests.
                    break
        raise last_error or SafeError('Media unavailable.')


def media_summary(conn):
    counts = [f"{row[0]} {row[1]}: {row[2]}" for row in conn.execute(
        'SELECT variant,status,COUNT(*) FROM rescue_assets GROUP BY variant,status')]
    print('Media rescue: ' + ('; '.join(counts) or 'no assets yet'), flush=True)


def run_photos_first(conn, client, output, args):
    with REMOTE_DIRECTORY_LOCK:
        REMOTE_DIRECTORIES.clear()
    # One new scan obtains paths and preview URLs absent from the older manifest.
    refresh = args.refresh_snapshot or meta(conn, 'media_metadata_version') != '1'
    if refresh:
        with conn:
            meta(conn, 'media_metadata_version', '1')
            # Clear snapshot atomically with version so an interrupted start reinitializes.
            conn.execute("DELETE FROM meta WHERE key='rescue_snapshot'")
    if args.retry_errors:
        with conn:
            conn.execute("DELETE FROM rescue_assets WHERE status='error'")
    if args.gdrive:
        flatten_remote_layout(conn, output, args.gdrive, args.workers)
        previous = meta(conn, 'media_remote')
        if previous and previous != args.gdrive:
            raise FatalError('Media manifest is bound to another remote.')
        with conn:
            meta(conn, 'media_remote', args.gdrive)
        for asset in conn.execute("SELECT * FROM rescue_assets WHERE status IN ('local','uploaded')").fetchall():
            offload_asset(conn, asset, output, args.gdrive)
    completed = 0
    database = conn.execute('PRAGMA database_list').fetchone()[2]
    api_lock, space = threading.Lock(), threading.Condition()
    reserved = 0
    stopping = threading.Event()

    class SerialAPI:
        # Link preparation shares a session; actual media and Drive transfers run concurrently.
        cookies = getattr(client, 'cookies', None)

        def api(self, method, params):
            with api_lock:
                return client.api(method, params)

    def process(row, variant):
        nonlocal reserved
        limit = 32 * 1024**2 if variant == 'preview' else (row['size'] if row['size_known'] and row['size'] > 0 else args.max_batch_bytes)
        limit = min(limit, args.max_batch_bytes) if variant == 'original' else limit
        with space:
            while shutil.disk_usage(output).free < reserved + limit + 128 * 1024**2:
                if stopping.is_set():
                    return False
                if not reserved:
                    raise FatalError('Insufficient local space for one file; completed copies preserved.')
                space.wait(timeout=1)
            reserved += limit
        worker_conn = sqlite3.connect(database, timeout=30)
        worker_conn.row_factory = sqlite3.Row
        try:
            rescue_one_media(worker_conn, SerialAPI(), dict(row), variant, output, args)
            asset = worker_conn.execute('SELECT * FROM rescue_assets WHERE file_id=? AND variant=?', (row['file_id'], variant)).fetchone()
            offload_asset(worker_conn, asset, output, args.gdrive)
            return False
        except FatalError:
            stopping.set()
            raise
        except SafeError as exc:
            with worker_conn:
                worker_conn.execute("INSERT INTO rescue_assets(file_id,variant,status,error) VALUES(?,?,'error',?)",
                                    (row['file_id'], variant, str(exc)))
            print(f'{row["kind"]}/{variant}: deferred: {exc}', flush=True)
            return isinstance(exc, NetworkError)
        finally:
            worker_conn.close()
            with space:
                reserved -= limit
                space.notify_all()

    def drain(kind, variant):
        nonlocal completed
        rows = conn.execute('SELECT f.*,m.path,m.kind,m.sizes_json FROM unlim_files f JOIN rescue_media m USING(file_id) '
                            'WHERE m.path IS NOT NULL AND m.kind=? AND NOT EXISTS '
                            '(SELECT 1 FROM rescue_assets a WHERE a.file_id=f.file_id AND a.variant=?) '
                            'ORDER BY f.rowid', (kind, variant)).fetchall()
        if args.max_batches:
            rows = rows[:max(0, args.max_batches - completed)]
        if not rows:
            return bool(args.max_batches and completed >= args.max_batches)
        root = private_dir(output / variant)
        # Pre-create shared directories before concurrent writers can race on mkdir.
        for row in rows:
            private_dir(root / hashlib.sha256(row['file_id'].encode()).hexdigest()[:2])
        pending_rows = iter(rows)
        network_failures = 0
        pool = ThreadPoolExecutor(max_workers=args.workers)
        futures = set()
        try:
            for row in list(rows[:args.workers]):
                next(pending_rows)
                futures.add(pool.submit(process, row, variant))
            while futures:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    network_failures = network_failures + 1 if future.result() else 0
                    completed += 1
                    if completed % 10 == 0 or args.max_batches:
                        media_summary(conn)
                if network_failures >= 3:
                    print('Repeated media failures: cooling down for 60 seconds; continuing with other files.', flush=True)
                    time.sleep(60)
                    network_failures = 0
                for _ in done:
                    row = next(pending_rows, None)
                    if row is not None:
                        futures.add(pool.submit(process, row, variant))
        finally:
            if sys.exc_info()[0]:
                stopping.set()
            pool.shutdown(wait=True, cancel_futures=True)
        return bool(args.max_batches and completed >= args.max_batches)
    print('Phase 1: largest available photo previews -> Google Drive.', flush=True)
    if drain('image', 'preview'):
        return
    for _ in media_inventory(conn, client, retry_errors=args.retry_errors):
        if drain('image', 'preview'):
            return
    if args.previews_only:
        media_summary(conn)
        return
    print('Phase 2: individual photo originals -> Google Drive.', flush=True)
    if drain('image', 'original'):
        return
    if not args.skip_videos:
        print('Phase 3: video originals -> Google Drive (after photo attempts).', flush=True)
        drain('video', 'original')
    media_summary(conn)
    missing = conn.execute('SELECT COUNT(*) FROM rescue_progress WHERE failed=1').fetchone()[0]
    print(f'Pass finished; incomplete metadata clusters: {missing}. Errors remain retryable.', flush=True)


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
    parser.add_argument("--workers", type=int, default=8, help="Concurrent media download/upload workers (default 8)")
    parser.add_argument("--photos-first", action="store_true", help="Rescue unlimited photos: previews, then originals, then videos; no ZIP")
    parser.add_argument("--flatten-remote", action="store_true", help="Move saved Drive files into one folder and exit; no Yandex login/downloads")
    parser.add_argument("--gdrive", help="rclone destination folder; verified uploads are removed from local staging")
    parser.add_argument("--previews-only", action="store_true", help="Only rescue photo previews in this pass")
    parser.add_argument("--skip-videos", action="store_true", help="Rescue photos only")
    args = parser.parse_args()
    if args.flatten_remote:
        if not args.gdrive:
            parser.error('--flatten-remote requires --gdrive')
        args.photos_first = True
    if not 1 <= args.workers <= 64:
        parser.error("--workers must be between 1 and 64")
    if args.photos_first:
        args.rescue = True
    if (args.gdrive or args.previews_only or args.skip_videos) and not args.photos_first:
        parser.error("Media options require --photos-first")
    if args.photos_first and args.passes != 1:
        parser.error("Use one photos-first pass; rerun with --retry-errors for deferred assets")
    if args.gdrive and (not re.fullmatch(r"[A-Za-z0-9_-]+:[^\\\r\n]+", args.gdrive) or
                        ".." in args.gdrive.split(":", 1)[1].split("/")):
        parser.error("--gdrive must be a configured rclone remote with a destination folder")
    if args.gdrive and not shutil.which("rclone"):
        parser.error("rclone is required for --gdrive")
    if not 1 <= args.batch <= 250 or args.max_batch_bytes < 1 or args.max_archive_bytes < 1 or args.max_batches < 0 or args.timeout < 1 or args.passes < 1:
        parser.error("Invalid batch/byte limits")
    if (args.retry_errors or args.refresh_snapshot or args.passes != 1) and not args.rescue:
        parser.error("--retry-errors, --refresh-snapshot and --passes require --rescue")
    configure_runtime()
    state = private_dir(args.state_dir)
    with state_lock(state):
        conn = connect_db(state)
        try:
            if args.flatten_remote:
                flatten_remote_layout(conn, private_dir(state / 'media'), args.gdrive, args.workers)
                media_summary(conn)
                return 0
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
            if args.photos_first:
                run_photos_first(conn, client, private_dir(state / "media"), args)
                return 0
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
