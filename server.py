#!/usr/bin/env python3
"""
FileVault local server.

Listens only on the loopback interfaces (127.0.0.1 and, when available, ::1).
Every API call must come from this machine, carry this launch's secret, and
present an Origin and Host for this server. The secret is injected into the
page when it is served; other websites cannot read it, and a missing Origin
is rejected.

The page is the only file served. The action log lives outside the project
directory and is not served.

File tools (used by Safari/Firefox, and by Trash from every browser):
  POST /api/write/rename   {root, path, newName}
  POST /api/write/move     {root, path, destDir}
  POST /api/write/copy     {root, path, destDir}
  POST /api/trash          {root, items:[{path, isDir, size, mtimeMs}]}
  POST /api/log            {action, detail}
  GET  /api/find-dir?name=

Rename and same-volume move use os.rename, so timestamps and extended
attributes stay with the file. Copy checks SHA-256, not just size, and
refuses when the destination name already exists. Nothing is overwritten.
On macOS the copy uses copyfile(3), which keeps extended attributes
(Finder tags and comments included) and the creation time. Elsewhere the
copy uses shutil.copy2.

On macOS, Trash goes through NSFileManager.trashItemAtURL (via osascript)
so Finder's Put Back still works. That call reads no file bytes. If it
cannot run, the original is left where it is. On other systems the file is
renamed into the desktop trash folder; Put Back is macOS-only.
"""
import errno
import hashlib
import hmac
import http.server
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PREFERRED_PORT = 8765
PORT_FILE = Path.home() / '.filevault_port'
TOKEN_PLACEHOLDER = '__FILEVAULT_TOKEN__'
MAX_JSON_BYTES = 1_048_576
LOOPBACK_HOSTS = ('127.0.0.1', '::1')

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' blob: data:; "
    "media-src 'self' blob:; "
    "object-src blob:; "
    "connect-src 'self' https://cdn.jsdelivr.net; "
    "worker-src 'self' blob:; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

_MAC_TRASH_SCRIPT = r'''
ObjC.import("Foundation");
function run() {
  var env = $.NSProcessInfo.processInfo.environment;
  var path = ObjC.unwrap(env.objectForKey("FILEVAULT_TRASH_PATH"));
  if (!path) throw new Error("path required");
  var url = $.NSURL.fileURLWithPath(path);
  var fm = $.NSFileManager.defaultManager;
  var resulting = $();
  var err = $();
  var ok = fm.trashItemAtURLResultingItemURLError(url, resulting, err);
  if (!ok) {
    var msg = "Trash failed";
    try { msg = ObjC.unwrap(err.localizedDescription); } catch (e) {}
    throw new Error(String(msg));
  }
  return "ok";
}
'''


def default_action_log():
    return Path.home() / '.filevault' / 'actions.log'


def default_trash_dir():
    data_home = os.environ.get('XDG_DATA_HOME')
    base = Path(data_home) if data_home else Path.home() / '.local' / 'share'
    path = base / 'Trash' / 'files'
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_action(action, detail, log_path):
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(log_path.parent, 0o700)
    except OSError:
        pass
    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'action': str(action)[:80],
        'detail': str(detail)[:4000],
    }
    line = (json.dumps(entry) + '\n').encode('utf-8')
    fd = os.open(log_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
    try:
        os.chmod(log_path, 0o600)
    except OSError:
        pass
    return entry


def find_free_port(start=PREFERRED_PORT):
    for port in range(start, start + 20):
        if _port_free(port):
            return port
    raise RuntimeError(f'No free port found in range {start}–{start + 19}')


def _port_free(port):
    socks = []
    try:
        ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ipv4.bind(('127.0.0.1', port))
        socks.append(ipv4)
        try:
            ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            ipv6.bind(('::1', port))
            socks.append(ipv6)
        except OSError:
            pass
        return True
    except OSError:
        return False
    finally:
        for sock in socks:
            sock.close()


def stream_hash(path, algo='sha256', chunk_size=1024 * 1024):
    """Hash a file in chunks so multi-gigabyte files are not loaded at once."""
    digest = hashlib.new(algo)
    with open(path, 'rb') as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def resolve_under_root(root_str, path_str):
    """Resolve path_str and require it to be root_str or a descendant of it.

    Symlinks are resolved, so a link inside root cannot point an operation
    at something outside root.
    """
    if not root_str or not isinstance(root_str, str):
        raise ValueError('root is required')
    if not isinstance(path_str, str) or not path_str:
        raise ValueError('path is required')
    root = Path(root_str).expanduser()
    if not root.is_dir():
        raise ValueError(f'root does not exist or is not a directory: {root_str}')
    root_r = Path(os.path.realpath(root))
    target = Path(path_str).expanduser()
    if not target.is_absolute():
        target = root / target
    target_r = Path(os.path.realpath(target))
    if target_r != root_r and root_r not in target_r.parents:
        raise ValueError(f'path escapes root: {path_str}')
    return target_r


def resolve_dest_dir(dest_dir):
    if not dest_dir or not isinstance(dest_dir, str):
        raise ValueError('destination directory is required')
    dest = Path(dest_dir).expanduser()
    if not dest.is_dir():
        raise ValueError('destination directory does not exist')
    return Path(os.path.realpath(dest))


def _same_dir(src, dest_dir):
    return os.path.realpath(src.parent) == os.path.realpath(dest_dir)


def _is_within(parent, child):
    parent_r = Path(os.path.realpath(parent))
    child_r = Path(os.path.realpath(child))
    return child_r == parent_r or parent_r in child_r.parents


def _valid_name(name):
    if not name or name in ('.', '..'):
        return False
    if '/' in name or '\\' in name or ':' in name:
        return False
    if any(ord(ch) < 32 for ch in name):
        return False
    if len(name.encode('utf-8')) > 255:
        return False
    return True


def _bytes_match(src, dst):
    if src.stat().st_size != dst.stat().st_size:
        return False
    return stream_hash(src) == stream_hash(dst)


# copyfile(3) flags from <copyfile.h>. CPython on macOS does not provide
# os.listxattr, so shutil.copy2 leaves Finder tags behind. copyfile is what
# /bin/cp uses to copy data and metadata together.
_COPYFILE_METADATA = (1 << 1) | (1 << 0) | (1 << 2)  # STAT | ACL | XATTR
_COPYFILE_ALL = _COPYFILE_METADATA | (1 << 3)  # plus DATA
_COPYFILE_EXCL = 1 << 17
_COPYFILE_NOFOLLOW = (1 << 18) | (1 << 19)
_DARWIN_FILE_FLAGS = _COPYFILE_ALL | _COPYFILE_EXCL | _COPYFILE_NOFOLLOW
_DARWIN_DIR_FLAGS = _COPYFILE_METADATA | _COPYFILE_EXCL | _COPYFILE_NOFOLLOW
_ATTR_BIT_MAP_COUNT = 5
_ATTR_CMN_CRTIME = 0x00000200
_ATTR_CMN_MODTIME = 0x00000400
_ATTR_CMN_ACCTIME = 0x00001000
_FSOPT_NOFOLLOW = 0x00000001

_darwin_lib = None


def _load_darwin_lib():
    """libc with copyfile(3) and setattrlist prototypes set once."""
    global _darwin_lib
    if _darwin_lib is not None:
        return _darwin_lib
    import ctypes

    class AttrList(ctypes.Structure):
        _fields_ = [
            ('bitmapcount', ctypes.c_ushort),
            ('reserved', ctypes.c_uint16),
            ('commonattr', ctypes.c_uint32),
            ('volattr', ctypes.c_uint32),
            ('dirattr', ctypes.c_uint32),
            ('fileattr', ctypes.c_uint32),
            ('forkattr', ctypes.c_uint32),
        ]

    class TimeSpec(ctypes.Structure):
        _fields_ = [('tv_sec', ctypes.c_long), ('tv_nsec', ctypes.c_long)]

    class TimeBuf(ctypes.Structure):
        # setattrlist writes values in ascending attribute-bit order.
        _fields_ = [('cr', TimeSpec), ('mod', TimeSpec), ('acc', TimeSpec)]

    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.copyfile.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32,
    ]
    lib.copyfile.restype = ctypes.c_int
    lib.setattrlist.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(AttrList), ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_ulong,
    ]
    lib.setattrlist.restype = ctypes.c_int
    lib.AttrList = AttrList
    lib.TimeSpec = TimeSpec
    lib.TimeBuf = TimeBuf
    _darwin_lib = lib
    return lib


def _split_ns(ns):
    sec, nsec = divmod(int(ns), 1_000_000_000)
    if nsec < 0:
        sec -= 1
        nsec += 1_000_000_000
    return sec, nsec


def _darwin_copyfile(src, dst, flags):
    import ctypes
    lib = _load_darwin_lib()
    result = lib.copyfile(os.fsencode(src), os.fsencode(dst), None, flags)
    if result == 0:
        return
    err = ctypes.get_errno()
    message = os.strerror(err) if err else 'copyfile failed'
    raise OSError(err, message, str(src), None, str(dst))


def _timestamp_ns(st, name):
    """Nanoseconds for st_mtime, st_atime, or st_birthtime.

    CPython 3.14 on macOS has st_birthtime and not st_birthtime_ns.
    """
    if hasattr(st, name + '_ns'):
        return getattr(st, name + '_ns')
    seconds = getattr(st, name, None)
    if seconds is None:
        return None
    return int(round(seconds * 1_000_000_000))


def _restore_darwin_times(src, dst):
    """Copy creation, modification, and access times. Failure leaves the copy.

    copyfile(3) keeps mtime but not birth time. A directory's mtime is also
    bumped while its children are created, so both are written back here.
    """
    import ctypes
    src_stat = os.lstat(src)
    birth_ns = _timestamp_ns(src_stat, 'st_birthtime')
    mtime_ns = _timestamp_ns(src_stat, 'st_mtime')
    atime_ns = _timestamp_ns(src_stat, 'st_atime')
    if mtime_ns is None or atime_ns is None:
        return
    if birth_ns is None:
        try:
            os.utime(dst, ns=(atime_ns, mtime_ns))
        except OSError:
            pass
        return
    lib = _load_darwin_lib()
    attrs = lib.AttrList()
    attrs.bitmapcount = _ATTR_BIT_MAP_COUNT
    attrs.commonattr = _ATTR_CMN_CRTIME | _ATTR_CMN_MODTIME | _ATTR_CMN_ACCTIME
    buf = lib.TimeBuf()

    def timespec(ns):
        # Nested ctypes structures are copied on read, so build a new one
        # and assign it back onto the buffer.
        sec, nsec = _split_ns(ns)
        spec = lib.TimeSpec(sec, nsec)
        return spec

    buf.cr = timespec(birth_ns)
    buf.mod = timespec(mtime_ns)
    buf.acc = timespec(atime_ns)
    result = lib.setattrlist(
        os.fsencode(dst), ctypes.byref(attrs), ctypes.byref(buf),
        ctypes.sizeof(buf), _FSOPT_NOFOLLOW,
    )
    if result == 0:
        return
    try:
        os.utime(dst, ns=(atime_ns, mtime_ns))
    except OSError:
        pass


def _remove_copy(dst):
    if dst.is_dir() and not dst.is_symlink():
        shutil.rmtree(dst, ignore_errors=True)
    else:
        dst.unlink(missing_ok=True)


def _remove_failed_copy(dst, exc):
    """Drop a partial copy. EEXIST means some other file already has that name."""
    if exc.errno == errno.EEXIST:
        return
    _remove_copy(dst)


def copy_path(src, dst):
    """Copy src to dst. dst must not exist. File bytes are checked with SHA-256.

    Symlinks are copied as symlinks and are not followed. A copy is a new
    file: the inode changes. Mode, mtime, and extended attributes are kept.
    On macOS, copyfile(3) also keeps Finder tags, Finder comments, and the
    creation time. Other platforms use shutil.copy2.
    """
    src = Path(src)
    dst = Path(dst)
    if dst.exists() or dst.is_symlink():
        raise FileExistsError(f'destination already exists: {dst}')
    if src.is_symlink():
        os.symlink(os.readlink(src), dst)
        if os.readlink(dst) != os.readlink(src):
            dst.unlink()
            raise OSError('symlink copy mismatch')
        return
    if src.is_dir():
        if sys.platform == 'darwin':
            try:
                _darwin_copyfile(src, dst, _DARWIN_DIR_FLAGS)
            except OSError as exc:
                _remove_failed_copy(dst, exc)
                raise
        else:
            dst.mkdir()
            try:
                shutil.copystat(src, dst, follow_symlinks=False)
            except OSError:
                pass
        try:
            for child in src.iterdir():
                copy_path(child, dst / child.name)
            if sys.platform == 'darwin':
                _restore_darwin_times(src, dst)
        except Exception:
            shutil.rmtree(dst, ignore_errors=True)
            raise
        return
    if not src.is_file():
        raise OSError(f'unsupported file type: {src}')
    if sys.platform == 'darwin':
        try:
            _darwin_copyfile(src, dst, _DARWIN_FILE_FLAGS)
        except OSError as exc:
            _remove_failed_copy(dst, exc)
            raise
    else:
        shutil.copy2(src, dst, follow_symlinks=False)
    if not _bytes_match(src, dst):
        dst.unlink(missing_ok=True)
        raise OSError('copy verification failed (hash mismatch)')
    if sys.platform == 'darwin':
        _restore_darwin_times(src, dst)


def move_path(src, dst):
    """Move src to dst, preferring a real rename so metadata stays put.

    Across devices, fall back to a verified copy and only then remove src.
    """
    src = Path(src)
    dst = Path(dst)
    if dst.exists() or dst.is_symlink():
        raise FileExistsError(f'destination already exists: {dst}')
    try:
        os.rename(src, dst)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    copy_path(src, dst)
    if src.is_dir() and not src.is_symlink():
        shutil.rmtree(src)
    else:
        src.unlink()


def write_rename(root, rel_path, new_name):
    new_name = (new_name or '').strip() if isinstance(new_name, str) else ''
    if not _valid_name(new_name):
        return {'ok': False, 'error': 'invalid new name'}
    try:
        src = resolve_under_root(root, rel_path)
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    if not src.exists():
        return {'ok': False, 'error': 'source not found'}
    dst = src.parent / new_name
    try:
        if (dst.exists() or dst.is_symlink()) and not os.path.samefile(src, dst):
            return {'ok': False, 'error': 'destination already exists'}
        os.rename(src, dst)
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True, 'path': str(dst)}


def write_move(root, rel_path, dest_dir):
    try:
        src = resolve_under_root(root, rel_path)
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    if not src.exists():
        return {'ok': False, 'error': 'source not found'}
    try:
        dest = resolve_dest_dir(dest_dir)
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    if _same_dir(src, dest):
        return {'ok': False, 'error': 'already in this folder'}
    if src.is_dir() and _is_within(src, dest):
        return {'ok': False, 'error': 'cannot move a folder into itself'}
    target = dest / src.name
    if target.exists() or target.is_symlink():
        return {'ok': False, 'error': 'destination already exists'}
    try:
        move_path(src, target)
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True, 'path': str(target)}


def write_copy(root, rel_path, dest_dir):
    try:
        src = resolve_under_root(root, rel_path)
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    if not src.exists():
        return {'ok': False, 'error': 'source not found'}
    try:
        dest = resolve_dest_dir(dest_dir)
    except ValueError as exc:
        return {'ok': False, 'error': str(exc)}
    if src.is_dir() and _is_within(src, dest):
        return {'ok': False, 'error': 'cannot copy a folder into itself'}
    target = dest / src.name
    if target.exists() or target.is_symlink():
        return {'ok': False, 'error': 'destination already exists'}
    try:
        copy_path(src, target)
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True, 'path': str(target)}


def _unique_dest(directory, name):
    candidate = directory / name
    if not candidate.exists() and not candidate.is_symlink():
        return candidate
    stem, suffix = Path(name).stem, Path(name).suffix
    for i in range(1, 10001):
        candidate = directory / f'{stem} ({i}){suffix}'
        if not candidate.exists() and not candidate.is_symlink():
            return candidate
    raise OSError('too many name collisions in the trash')


def _trash_by_rename(src, trash_dir):
    trash_dir = Path(trash_dir)
    trash_dir.mkdir(parents=True, exist_ok=True)
    dest = _unique_dest(trash_dir, src.name)
    try:
        move_path(src, dest)
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}
    return {'ok': True, 'trashedPath': str(dest)}


def trash_via_macos(src):
    """Move src to the macOS Trash with NSFileManager so Put Back works.

    The path is passed in the environment, not spliced into the script.
    If osascript cannot run, src is left in place.
    """
    src = Path(src)
    if not src.exists():
        return {'ok': False, 'error': 'Not found'}
    env = os.environ.copy()
    env['FILEVAULT_TRASH_PATH'] = str(src)
    try:
        proc = subprocess.run(
            ['osascript', '-l', 'JavaScript', '-e', _MAC_TRASH_SCRIPT],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return {
            'ok': False,
            'error': 'macOS Trash needs osascript, which was not found. The file was left in place.',
        }
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'macOS Trash timed out. The file was left in place.'}
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout or 'Trash failed').strip()
        return {'ok': False, 'error': msg}
    if src.exists():
        return {'ok': False, 'error': 'Trash reported success but the original is still there.'}
    return {'ok': True}


def move_to_trash(src, trash_dir=None):
    src = Path(src)
    if trash_dir is not None:
        return _trash_by_rename(src, trash_dir)
    if sys.platform == 'darwin':
        return trash_via_macos(src)
    return _trash_by_rename(src, default_trash_dir())


def _expectation_error(src, item):
    is_dir = item.get('isDir')
    if is_dir is True and not src.is_dir():
        return 'expected a folder'
    if is_dir is False and not src.is_file():
        return 'expected a file'
    if src.is_file():
        if item.get('size') is None:
            return 'size is required'
        try:
            expected = int(item.get('size'))
        except (TypeError, ValueError):
            return 'size is required'
        if src.stat().st_size != expected:
            return 'size does not match the selected file; check the absolute folder path'
        if item.get('mtimeMs') is not None:
            try:
                delta = abs(src.stat().st_mtime * 1000 - float(item['mtimeMs']))
            except (TypeError, ValueError):
                return 'modification time does not match the selected file; check the absolute folder path'
            if delta > 5000:
                return 'modification time does not match the selected file; check the absolute folder path'
    return None


def trash_items(root, items, trash_dir=None):
    if not isinstance(items, list):
        return [{'path': '', 'ok': False, 'error': 'items must be a list'}]
    results = []
    for item in items:
        if not isinstance(item, dict):
            results.append({'path': '', 'ok': False, 'error': 'invalid item'})
            continue
        path = item.get('path', '')
        try:
            src = resolve_under_root(root, path)
        except ValueError as exc:
            results.append({'path': path, 'ok': False, 'error': str(exc)})
            continue
        if not src.exists():
            results.append({'path': path, 'ok': False, 'error': 'Not found'})
            continue
        mismatch = _expectation_error(src, item)
        if mismatch:
            results.append({'path': path, 'ok': False, 'error': mismatch})
            continue
        outcome = move_to_trash(src, trash_dir=trash_dir)
        outcome['path'] = path
        results.append(outcome)
    return results


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_HEAD(self):
        self.close_connection = True
        self.do_GET()

    def do_GET(self):
        try:
            path = urlparse(self.path).path
            if path == '/api/find-dir':
                if not self._authorized():
                    self._forbid()
                    return
                self._find_dir()
                return
            if path in ('/', '/FileVault.html'):
                if not self._page_ok():
                    self._forbid()
                    return
                self._serve_html()
                return
            self.send_error(404)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        if not (self._peer_ok() and self._host_ok() and self._origin_ok()):
            self._forbid()
            return
        origin = self.headers.get('Origin')
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-FileVault-Token')
        self.send_header('Access-Control-Max-Age', '600')
        self.send_header('Vary', 'Origin')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        try:
            self._dispatch_post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self._json({'ok': False, 'error': 'internal error'}, 500)
            except Exception:
                pass

    def _dispatch_post(self):
        path = urlparse(self.path).path
        known = {
            '/api/trash',
            '/api/write/rename',
            '/api/write/move',
            '/api/write/copy',
            '/api/log',
        }
        if not self._authorized():
            self._forbid()
            return
        if path not in known:
            self.send_error(404)
            return
        body = self._read_json()
        if body is None:
            self._json({'ok': False, 'error': 'malformed json'}, 400)
            return
        if path == '/api/trash':
            results = trash_items(body.get('root', ''), body.get('items'), self.server.trash_dir)
            for result in results:
                if result.get('ok'):
                    log_action('delete', result.get('path', ''), self.server.action_log)
            self._json({'results': results})
        elif path == '/api/write/rename':
            result = write_rename(body.get('root', ''), body.get('path', ''), body.get('newName', ''))
            if result.get('ok'):
                log_action('rename', f"{body.get('path')} -> {result.get('path')}", self.server.action_log)
            self._json(result)
        elif path == '/api/write/move':
            result = write_move(body.get('root', ''), body.get('path', ''), body.get('destDir', ''))
            if result.get('ok'):
                log_action('move', f"{body.get('path')} -> {result.get('path')}", self.server.action_log)
            self._json(result)
        elif path == '/api/write/copy':
            result = write_copy(body.get('root', ''), body.get('path', ''), body.get('destDir', ''))
            if result.get('ok'):
                log_action('copy', f"{body.get('path')} -> {result.get('path')}", self.server.action_log)
            self._json(result)
        elif path == '/api/log':
            entry = log_action(body.get('action', 'unknown'), body.get('detail', ''), self.server.action_log)
            self._json({'ok': True, 'entry': entry})

    def _read_json(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return None
        if length < 0 or length > MAX_JSON_BYTES:
            self.close_connection = True
            return None
        raw = self.rfile.read(length) if length else b''
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        return data

    def _peer_ok(self):
        host = self.client_address[0]
        return host in ('127.0.0.1', '::1', '::ffff:127.0.0.1')

    def _allowed_hosts(self):
        port = self.server.server_address[1]
        return {
            f'localhost:{port}',
            f'127.0.0.1:{port}',
            f'[::1]:{port}',
        }

    def _allowed_origins(self):
        port = self.server.server_address[1]
        return {
            f'http://localhost:{port}',
            f'http://127.0.0.1:{port}',
            f'http://[::1]:{port}',
        }

    def _host_ok(self):
        return self.headers.get('Host', '').lower() in self._allowed_hosts()

    def _origin_ok(self):
        origin = self.headers.get('Origin')
        return bool(origin) and origin in self._allowed_origins()

    def _token_ok(self):
        presented = self.headers.get('X-FileVault-Token', '')
        expected = getattr(self.server, 'token', '') or ''
        if not presented or not expected or len(presented) != len(expected):
            return False
        return hmac.compare_digest(presented, expected)

    def _authorized(self):
        return self._peer_ok() and self._host_ok() and self._origin_ok() and self._token_ok()

    def _page_ok(self):
        return self._peer_ok() and self._host_ok()

    def _forbid(self):
        self.close_connection = True
        self.send_error(403, 'Forbidden')

    def _find_dir(self):
        name = parse_qs(urlparse(self.path).query).get('name', [''])[0]
        if not name or '/' in name or '\\' in name or name in ('.', '..'):
            self._json({'error': 'no name'}, 400)
            return
        roots = self.server.search_roots
        if roots is None:
            roots = []
            volumes = Path('/Volumes')
            if volumes.is_dir():
                try:
                    roots.extend(str(entry) for entry in volumes.iterdir())
                except OSError:
                    pass
            roots.append(str(Path.home()))
        found = None
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, _ in os.walk(root):
                depth = dirpath.count(os.sep) - root.count(os.sep)
                if depth >= 8:
                    dirnames.clear()
                    continue
                dirnames[:] = [entry for entry in dirnames if not entry.startswith('.')]
                if os.path.basename(dirpath) == name:
                    found = dirpath
                    break
            if found:
                break
        if found:
            self._json({'path': found})
        else:
            self._json({'error': 'not found'}, 404)

    def _serve_html(self):
        html_path = Path(__file__).with_name('FileVault.html')
        html = html_path.read_text(encoding='utf-8')
        token = self.server.token
        if TOKEN_PLACEHOLDER not in html:
            self.send_error(500, 'token placeholder missing')
            return
        if not token or TOKEN_PLACEHOLDER in token:
            self.send_error(500, 'server token is not set')
            return
        html = html.replace(TOKEN_PLACEHOLDER, token)
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', CSP)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        origin = self.headers.get('Origin')
        if origin and origin in self._allowed_origins():
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def create_server(host, port, token, action_log=None, trash_dir=None, search_roots=None):
    if host not in LOOPBACK_HOSTS:
        raise ValueError(f'refusing to bind a non-loopback address: {host!r}')
    family = socket.AF_INET6 if host == '::1' else socket.AF_INET

    class _Server(http.server.ThreadingHTTPServer):
        address_family = family
        allow_reuse_address = False
        daemon_threads = True

    httpd = _Server((host, port), Handler)
    httpd.token = token
    httpd.action_log = Path(action_log) if action_log else default_action_log()
    httpd.trash_dir = None if trash_dir is None else Path(trash_dir)
    httpd.search_roots = None if search_roots is None else list(search_roots)
    return httpd


def start_loopback(port, token, action_log=None, trash_dir=None, search_roots=None):
    """Bind 127.0.0.1 and, when the OS allows it, ::1 on the same port."""
    kwargs = {
        'action_log': action_log,
        'trash_dir': trash_dir,
        'search_roots': search_roots,
    }
    servers = [create_server('127.0.0.1', port, token, **kwargs)]
    actual = servers[0].server_address[1]
    try:
        servers.append(create_server('::1', actual, token, **kwargs))
    except OSError:
        pass
    return servers


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    token = secrets.token_urlsafe(32)
    if '--port' in argv:
        port = int(argv[argv.index('--port') + 1])
    else:
        port = find_free_port()
    servers = start_loopback(port, token)
    actual = servers[0].server_address[1]
    PORT_FILE.write_text(str(actual))
    try:
        os.chmod(PORT_FILE, 0o600)
    except OSError:
        pass
    if actual != PREFERRED_PORT:
        print(f'Port {PREFERRED_PORT} was busy — using {actual} instead.')
    print(f'FileVault server → http://127.0.0.1:{actual}/FileVault.html')
    print('Listening on this computer only (127.0.0.1 and ::1).')
    print('Press Ctrl+C to stop.\n')
    for extra in servers[1:]:
        threading.Thread(target=extra.serve_forever, daemon=True).start()
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()
        PORT_FILE.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
