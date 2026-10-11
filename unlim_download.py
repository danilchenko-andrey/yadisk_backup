"""Restricted, standard-library-only photoslice collector (Linux/macOS, Python 3.10+).

No web server, .env, OAuth token, proxy, third-party package or import-time I/O.
See README_SAFE.md. The private API is inherited from upstream and unverified live.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import http.cookiejar
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = "https://disk.yandex.ru"
API_METHODS = frozenset({
    "intapi/photo-init-snapshot", "intapi/photo-get-snapshot",
    "intapi/photo-get-clusters-with-resources", "mpfs/bulk-download-prepare",
})
DEFAULT_STATE = Path.home() / ".local/share/yadisk-unlim-safe"
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS unlim_files (
 file_id TEXT PRIMARY KEY, cluster_id TEXT NOT NULL, name TEXT NOT NULL,
 size INTEGER NOT NULL CHECK(size >= 0), md5 TEXT,
 status TEXT NOT NULL DEFAULT 'pending', local_path TEXT, sha256 TEXT,
 downloaded_at TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS unlim_clusters (
 cluster_id TEXT PRIMARY KEY, size INTEGER NOT NULL, fetched INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_unlim_status ON unlim_files(status);
"""


class SafeError(Exception):
    """Only fixed, non-secret diagnostic messages may be put in this exception."""


def private_dir(path: Path) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    # Reject symlinks in all existing components; never chmod an arbitrary parent.
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            part.mkdir(mode=0o700)
            continue
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise SafeError("Directory path contains a non-directory or symlink.")
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise SafeError("Private directory must be owned by this user and have mode 700.")
    return path


def open_private(path: Path, mode="r"):
    flags = os.O_RDONLY if mode == "r" else os.O_RDWR | os.O_CREAT
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise SafeError("Private file must be regular, owned by this user, unlinked elsewhere, and mode 600.")
        return os.fdopen(fd, "r" if mode == "r" else "r+", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def state_lock(state: Path):
    # One collector/worker per state. No time-based lease can steal a slow download.
    import fcntl
    with open_private(state / "run.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SafeError("Another collector or worker is using this state directory.") from None
        yield


def connect_db(state: Path) -> sqlite3.Connection:
    path = state / "manifest-v2.sqlite3"
    with open_private(path, "a"):
        pass
    # Reject unsafe SQLite sidecars before SQLite can open them.
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            with open_private(sidecar):
                pass
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    conn.executescript(SCHEMA)
    return conn


def meta(conn, key, value=None):
    if value is not None:
        conn.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, str(value)))
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def safe_name(name):
    if (not isinstance(name, str) or not name or name in (".", "..")
            or any(c in name for c in '/\\:')
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise SafeError("Unsafe or missing file name in metadata/archive.")
    return name


def load_cookies(path: Path) -> http.cookiejar.CookieJar:
    try:
        with open_private(path) as file:
            raw = file.read(2 * 1024 * 1024 + 1)
    except FileNotFoundError:
        raise SafeError("Cookie export not found. Supply a private JSON file using --cookies.") from None
    if len(raw) > 2 * 1024 * 1024:
        raise SafeError("Cookie export exceeds the size limit.")
    try:
        entries = json.loads(raw)
    except (ValueError, TypeError):
        raise SafeError("Invalid cookie JSON; expected an array with browser metadata.") from None
    if not isinstance(entries, list):
        raise SafeError("Cookie export must be an array; plain name/value maps are rejected.")
    policy = http.cookiejar.DefaultCookiePolicy(
        strict_ns_domain=http.cookiejar.DefaultCookiePolicy.DomainStrictNonDomain)
    jar = http.cookiejar.CookieJar(policy)
    for entry in entries:
        if not isinstance(entry, dict):
            raise SafeError("Invalid cookie entry.")
        domain = entry.get("domain")
        # Select only cookies which can apply to the one API host. Never rewrite domains.
        if domain not in (".yandex.ru", "yandex.ru", ".disk.yandex.ru", "disk.yandex.ru"):
            continue
        host_only = entry.get("hostOnly", not domain.startswith("."))
        if not isinstance(host_only, bool):
            raise SafeError("Invalid cookie hostOnly flag.")
        if host_only and domain.lstrip(".") != "disk.yandex.ru":
            continue
        name, value, path_ = entry.get("name"), entry.get("value"), entry.get("path")
        secure = entry.get("secure")
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or not isinstance(value, str)
                or any(ord(c) < 33 or ord(c) > 126 or c in ';,' for c in value)
                or not isinstance(path_, str) or not path_.startswith("/")
                or not isinstance(secure, bool)):
            raise SafeError("Cookie export lacks valid name/value/path/secure metadata.")
        expiry = entry.get("expirationDate", entry.get("expires"))
        if expiry is not None:
            if isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or not math.isfinite(expiry):
                raise SafeError("Invalid cookie expiry.")
            expiry = int(expiry)
            if expiry <= time.time():
                continue
        jar.set_cookie(http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=domain, domain_specified=not host_only,
            domain_initial_dot=domain.startswith("."), path=path_, path_specified=True,
            secure=secure, expires=expiry, discard=expiry is None,
            comment=None, comment_url=None,
            rest={"HttpOnly": entry.get("httpOnly", False), "SameSite": entry.get("sameSite")},
            rfc2109=False,
        ))
    if not list(jar):
        raise SafeError("No unexpired cookies applicable to disk.yandex.ru.")
    return jar


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener():
    # Ignore environment proxies, .netrc and system proxy discovery. TLS validation stays on.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )


def validate_url(url, *, archive=False):
    try:
        if not isinstance(url, str) or any(ord(c) < 33 or ord(c) > 126 for c in url) or "\\" in url:
            raise ValueError()
        p = urllib.parse.urlsplit(url)
        if p.scheme != "https" or p.username or p.password or p.port not in (None, 443) or p.fragment:
            raise ValueError()
        host = p.hostname
        if archive:
            allowed = host in {"downloader.disk.yandex.ru", "downloader.yandex.ru"}
            allowed = allowed or (host is not None and host.endswith(".storage.yandex.net"))
            if not allowed:
                raise ValueError()
        elif host != "disk.yandex.ru":
            raise ValueError()
        return url
    except (ValueError, TypeError):
        raise SafeError("Blocked URL: HTTPS and an explicitly allowed Yandex host are required.") from None


def open_no_redirect(opener, request, timeout):
    try:
        return opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # Treat status as a response, but never log its URL/body/headers.
        return exc
    except Exception:
        raise SafeError("Network/TLS request failed; URL and credentials omitted.") from None


def read_bounded(response, limit):
    try:
        body = response.read(limit + 1)
    except Exception:
        raise SafeError("Incomplete HTTP response.") from None
    if len(body) > limit:
        raise SafeError("API response exceeded its size limit.")
    return body


class YandexClient:
    def __init__(self, cookies):
        self.cookies = cookies
        self.opener = build_opener()
        self.sk = None
        self.uid = None

    def request(self, url, body=None):
        validate_url(url)
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*",
                   "Referer": BASE + "/client/photo", "Origin": BASE,
                   "X-Requested-With": "XMLHttpRequest"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers)
        self.cookies.add_cookie_header(request)
        for attempt in range(3):
            with open_no_redirect(self.opener, request, 120) as response:
                status = response.code
                if status == 200:
                    return read_bounded(response, 32 * 1024 * 1024)
                if status in (301, 302, 303, 307, 308, 401, 403):
                    raise SafeError("API authentication/redirect refused. Refresh the cookie export locally.")
                if status not in (429, 500, 502, 503, 504):
                    raise SafeError("Unexpected API HTTP status; response omitted.")
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
        raise SafeError("API rate limit or server failure after three attempts.")

    def login(self):
        page = self.request(BASE + "/client/disk").decode("utf-8", errors="replace")
        sk = re.search(r'"sk"\s*:\s*"([^"\r\n]+)"', page)
        uid = re.search(r'"uid"\s*:\s*"?(\d+)"?', page)
        if not sk or not uid:
            raise SafeError("Cannot find session fields; login expired or Yandex API changed.")
        self.sk, self.uid = sk.group(1), uid.group(1)

    def api(self, method, params=None):
        if method not in API_METHODS or not self.sk or not self.uid:
            raise SafeError("Unsupported API method or missing authenticated session.")
        body = {"sk": self.sk, "connection_id": f"{self.uid}{int(time.time() * 1000)}{100 + uuid.uuid4().int % 900}",
                "apiMethod": method}
        if params is not None:
            body["requestParams"] = params
        raw = self.request(BASE + "/models-v2?" + urllib.parse.urlencode({"m": method}), body)
        try:
            result = json.loads(raw)
        except ValueError:
            raise SafeError("Invalid API JSON response.") from None
        if not isinstance(result, dict) or result.get("error") or result.get("errors"):
            raise SafeError("API reported an error or returned an unexpected structure.")
        return result


def bind_account(conn, uid):
    existing = meta(conn, "account_uid")
    if existing and existing != uid:
        raise SafeError("Cookie account differs from the account bound to this manifest.")
    meta(conn, "account_uid", uid)
    conn.commit()


def get_all_clusters(client, snapshot):
    # This endpoint returns a snapshot, not a page. In the observed API response,
    # amount=1000 returned 5343 clusters and changing offset returned them all
    # again. Do not invent pagination or treat repetition as an end-of-list signal.
    result = client.api("intapi/photo-get-snapshot", {"id": snapshot, "locale": "ru"})
    items = result.get("items")
    if not isinstance(items, list):
        raise SafeError("Snapshot response is missing an items array.")
    clusters, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            raise SafeError("Invalid snapshot cluster ID.")
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise SafeError("Snapshot cluster has an invalid resource count.")
        if item["id"] in seen:
            raise SafeError("Repeated cluster ID within snapshot.")
        seen.add(item["id"])
        clusters.append({"id": item["id"], "size": size})
    return clusters


def parse_resource(item, cluster):
    if not isinstance(item, dict):
        raise SafeError("Invalid resource metadata.")
    fid = item.get("id") or item.get("resource_id")
    if not isinstance(fid, str) or not fid:
        raise SafeError("Missing resource ID.")
    name = safe_name(item.get("name"))
    size = item.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise SafeError("Resource lacks a valid byte size; collection stopped.")
    md5 = item.get("md5")
    if md5 is not None:
        if not isinstance(md5, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", md5):
            raise SafeError("Invalid MD5 metadata.")
        md5 = md5.lower()
    # An arbitrary ETag is not an MD5 checksum.
    return (fid, cluster, name, size, md5)


def fetch_cluster(client, snapshot, cluster):
    cid, count = cluster["id"], cluster["size"]
    if count == 0:
        return []
    result = client.api("intapi/photo-get-clusters-with-resources", {
        "photosliceId": snapshot, "clusters": {cid: {"range": [0, count - 1]}},
        "hideScreenshots": False})
    group = result.get("clusters")
    fetched = group.get("fetched") if isinstance(group, dict) else None
    if (not isinstance(fetched, list) or len(fetched) != 1 or not isinstance(fetched[0], dict)
            or fetched[0].get("id") != cid or not isinstance(fetched[0].get("items"), list)):
        raise SafeError("Cluster missing or response shape changed; inventory incomplete.")
    records = [parse_resource(item, cid) for item in fetched[0]["items"]]
    if len(records) != count or len({row[0] for row in records}) != count:
        raise SafeError("Partial/duplicate cluster resources; inventory incomplete.")
    return records


def collect(conn, client):
    meta(conn, "collection_complete", "0")
    conn.commit()
    snapshot = client.api("intapi/photo-init-snapshot").get("photoslice_id")
    if not isinstance(snapshot, str) or not snapshot:
        raise SafeError("Missing snapshot ID.")
    clusters = get_all_clusters(client, snapshot)
    print(f"Snapshot clusters: {len(clusters)}; expected resources: {sum(cl['size'] for cl in clusters)}", flush=True)
    with conn:
        conn.execute("DELETE FROM unlim_clusters")
        conn.executemany("INSERT INTO unlim_clusters(cluster_id, size) VALUES (?, ?)",
                         [(cl["id"], cl["size"]) for cl in clusters])
    seen = set()
    for index, cluster in enumerate(clusters):
        rows = fetch_cluster(client, snapshot, cluster)
        if any(row[0] in seen for row in rows):
            raise SafeError("Resource appears in more than one cluster; inventory ambiguous.")
        seen.update(row[0] for row in rows)
        with conn:
            for row in rows:
                old = conn.execute("SELECT name,size,md5 FROM unlim_files WHERE file_id=?", (row[0],)).fetchone()
                if old and tuple(old) != (row[2], row[3], row[4]):
                    raise SafeError("Previously listed resource changed. Use a new state directory for a new snapshot.")
                conn.execute("INSERT INTO unlim_files(file_id,cluster_id,name,size,md5) VALUES (?,?,?,?,?) "
                             "ON CONFLICT(file_id) DO UPDATE SET cluster_id=excluded.cluster_id", row)
            conn.execute("UPDATE unlim_clusters SET fetched=1 WHERE cluster_id=?", (cluster["id"],))
        print(f"Clusters checked: {index + 1}/{len(clusters)}; resources: {len(seen)}", flush=True)
    # Never silently include stale entries from a changed snapshot.
    existing = {row[0] for row in conn.execute("SELECT file_id FROM unlim_files")}
    if existing != seen:
        raise SafeError("Snapshot differs from existing manifest. Use a new state directory; no files were deleted.")
    with conn:
        meta(conn, "collection_complete", "1")
        meta(conn, "collected_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def print_status(conn):
    row = conn.execute("SELECT COUNT(*),COALESCE(SUM(size),0),SUM(md5 IS NULL) FROM unlim_files").fetchone()
    print(f"Listed resources: {row[0]}; bytes: {row[1]} ({row[1] / 2**30:.2f} GiB)")
    print(f"Without upstream MD5: {row[2] or 0}")
    print("Inventory complete for returned snapshot: " + ("yes" if meta(conn, "collection_complete") == "1" else "NO"))
    for status in conn.execute("SELECT status,COUNT(*) FROM unlim_files GROUP BY status"):
        print(f"  {status[0]}: {status[1]}")


def base_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--cookies", type=Path, help="Private JSON cookie export, used only for network operations")
    return parser


def configure_runtime():
    if os.name != "posix":
        raise SafeError("This hardened CLI currently supports Linux/macOS only.")
    os.umask(0o077)


def main():
    parser = base_parser(__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--collect", action="store_true")
    modes.add_argument("--status", action="store_true")
    args = parser.parse_args()
    configure_runtime()
    state = private_dir(args.state_dir)
    with state_lock(state):
        conn = connect_db(state)
        try:
            if args.collect:
                client = YandexClient(load_cookies(args.cookies or state / "cookies.json"))
                client.login()
                bind_account(conn, client.uid)
                collect(conn, client)
            print_status(conn)
        finally:
            conn.close()
    return 0


def run_cli(main_fn):
    try:
        return main_fn()
    except KeyboardInterrupt:
        print("Stopped; completed batches remain recorded.", file=sys.stderr)
        return 130
    except SafeError as exc:
        print(f"Stopped: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Stopped by an OS error (errno={exc.errno}); paths and details omitted.", file=sys.stderr)
        return 1
    except Exception:
        # No traceback: arbitrary exceptions may contain signed URLs or response content.
        print("Stopped by an unexpected error. Details suppressed to protect credentials.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_cli(main))
