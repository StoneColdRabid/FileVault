#!/usr/bin/env python3
"""
FileVault local server.
- Finds a free port starting at 8765; writes chosen port to ~/.filevault_port
- Serves FileVault.html with the actual port injected (for the trash API URL)
- POST /api/trash  { "root": "/abs/root", "paths": ["/abs/path/to/file", ...] }
  Moves each path to ~/.Trash, handling name collisions. Every path must
  resolve under `root` (see _resolve_under_root) — this is the Safari
  read-only-mode delete fallback, used when there's no writable directory
  handle to remove the original via the browser.
- POST /api/write/rename  { "root", "path", "newName" }
- POST /api/write/move    { "root", "path", "destDir" }
- POST /api/write/copy    { "root", "path", "destDir" }
  Safari fallback for rename/move/copy — same rationale as /api/trash above.
- POST /api/log  { "action": "rename"|"move"|"delete", "detail": "...", "path": "..." }
  Appends a JSON line with an ISO timestamp to filevault-actions.log.

Security note: this server has no auth and binds to localhost, so any of the
write endpoints above must reject requests whose Origin doesn't match this
server (see _origin_ok) — otherwise any webpage open in any tab could POST to
localhost and rename/move/delete/copy files on this machine. Origin-checking
is the actual gate (it happens before any filesystem call); the removal of
wildcard CORS headers is a secondary layer that also stops a cross-origin
caller from reading the response.
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PREFERRED_PORT = 8765
TRASH = Path.home() / '.Trash'
PORT_FILE = Path.home() / '.filevault_port'
ACTION_LOG = Path(__file__).with_name('filevault-actions.log')


def log_action(action, detail):
    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'action': action,
        'detail': detail,
    }
    with ACTION_LOG.open('a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')
    return entry


def find_free_port(start=PREFERRED_PORT):
    for port in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('', port))
                return port
            except OSError:
                continue
    raise RuntimeError(f'No free port found in range {start}–{start + 19}')


def trash_item(src_str):
    src = Path(src_str)
    if not src.exists():
        return {'path': src_str, 'ok': False, 'error': 'Not found'}
    dst = TRASH / src.name
    n = 1
    while dst.exists():
        dst = TRASH / f"{src.stem} {n}{src.suffix}"
        n += 1
    try:
        shutil.move(str(src), str(dst))
        return {'path': src_str, 'ok': True}
    except Exception as e:
        return {'path': src_str, 'ok': False, 'error': str(e)}


def resolve_under_root(root_str, path_str):
    """Resolve `path_str` (absolute, or relative to root) and confirm it is
    `root_str` itself or a descendant of it. Symlinks are resolved via
    realpath so a symlink inside root can't be used to point outside it.
    Raises ValueError if root is invalid or the path escapes it."""
    if not root_str:
        raise ValueError('root is required')
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


def dedupe_dest(dest_dir, name):
    dst = dest_dir / name
    stem, suffix = dst.stem, dst.suffix
    i = 1
    while dst.exists():
        dst = dest_dir / f'{stem} ({i}){suffix}'
        i += 1
    return dst


def write_rename(root, rel_path, new_name):
    new_name = (new_name or '').strip()
    if not new_name or '/' in new_name or '\\' in new_name or new_name in ('.', '..'):
        return {'ok': False, 'error': 'invalid new name'}
    try:
        src = resolve_under_root(root, rel_path)
    except ValueError as e:
        return {'ok': False, 'error': str(e)}
    if not src.exists():
        return {'ok': False, 'error': 'source not found'}
    dst = src.parent / new_name
    if dst.exists():
        return {'ok': False, 'error': 'destination already exists'}
    try:
        os.rename(src, dst)
        return {'ok': True, 'path': str(dst)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def write_move(root, rel_path, dest_dir):
    try:
        src = resolve_under_root(root, rel_path)
    except ValueError as e:
        return {'ok': False, 'error': str(e)}
    if not src.exists():
        return {'ok': False, 'error': 'source not found'}
    dest = Path(dest_dir).expanduser()
    if not dest.is_dir():
        return {'ok': False, 'error': 'destination directory does not exist'}
    dst = dedupe_dest(dest, src.name)
    try:
        shutil.move(str(src), str(dst))
        return {'ok': True, 'path': str(dst)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def write_copy(root, rel_path, dest_dir):
    try:
        src = resolve_under_root(root, rel_path)
    except ValueError as e:
        return {'ok': False, 'error': str(e)}
    if not src.exists():
        return {'ok': False, 'error': 'source not found'}
    dest = Path(dest_dir).expanduser()
    if not dest.is_dir():
        return {'ok': False, 'error': 'destination directory does not exist'}
    dst = dedupe_dest(dest, src.name)
    try:
        shutil.copy2(str(src), str(dst))
        return {'ok': True, 'path': str(dst)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/api/find-dir'):
            from urllib.parse import urlparse, parse_qs
            import os
            name = parse_qs(urlparse(self.path).query).get('name', [''])[0]
            if not name:
                self._json({'error': 'no name'}); return
            # Walk up to 8 levels deep in likely roots, skipping hidden dirs
            search_roots = []
            for v in Path('/Volumes').iterdir() if Path('/Volumes').exists() else []:
                search_roots.append(str(v))
            search_roots.append(str(Path.home()))
            found = None
            for root in search_roots:
                for dirpath, dirnames, _ in os.walk(root):
                    depth = dirpath.count(os.sep) - root.count(os.sep)
                    if depth >= 8:
                        dirnames.clear(); continue
                    dirnames[:] = [d for d in dirnames if not d.startswith('.')]
                    if os.path.basename(dirpath) == name:
                        found = dirpath; break
                if found:
                    break
            if found:
                self._json({'path': found})
            else:
                self._json({'error': 'not found'})
            return
        if self.path in ('/', '/FileVault.html'):
            html = Path(__file__).with_name('FileVault.html').read_text(encoding='utf-8')
            port = self.server.port
            if port != PREFERRED_PORT:
                html = html.replace(f'localhost:{PREFERRED_PORT}', f'localhost:{port}')
            body = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()

    def do_OPTIONS(self):
        self._cors()

    def _allowed_origins(self):
        port = self.server.port
        return {f'http://localhost:{port}', f'http://127.0.0.1:{port}'}

    def _origin_ok(self):
        """Gate for every write endpoint. Real browsers always attach an
        Origin header to fetch/XHR POST requests (same-origin or not) and it
        cannot be spoofed by page JS, so this is the actual security boundary
        — it runs before any filesystem call. A missing Origin header (e.g. a
        plain curl request) is allowed through, since that's how this server
        is verified/tested locally and no browser omits it for POST."""
        origin = self.headers.get('Origin')
        if origin is None:
            return True
        return origin in self._allowed_origins()

    def do_POST(self):
        if self.path == '/api/trash':
            if not self._origin_ok():
                self.send_error(403, 'Origin not allowed'); return
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            root = body.get('root', '')
            raw_paths = body.get('paths', [])
            results = []
            for p in raw_paths:
                try:
                    resolved = resolve_under_root(root, p)
                    r = trash_item(str(resolved))
                except ValueError as e:
                    r = {'path': p, 'ok': False, 'error': str(e)}
                results.append(r)
                if r.get('ok'):
                    log_action('delete', p)
            self._json({'results': results})
        elif self.path.startswith('/api/trash-upload'):
            from urllib.parse import urlparse, parse_qs
            name = parse_qs(urlparse(self.path).query).get('name', [''])[0]
            if not name:
                self._json({'ok': False, 'error': 'no name'}); return
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)
            dst = TRASH / Path(name).name
            stem, suffix = dst.stem, dst.suffix
            i = 1
            while dst.exists():
                dst = TRASH / f'{stem} ({i}){suffix}'
                i += 1
            dst.write_bytes(data)
            log_action('delete', name)
            self._json({'ok': True})
        elif self.path == '/api/write/rename':
            if not self._origin_ok():
                self.send_error(403, 'Origin not allowed'); return
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            result = write_rename(body.get('root', ''), body.get('path', ''), body.get('newName', ''))
            if result.get('ok'):
                log_action('rename', f"{body.get('path')} -> {result.get('path')}")
            self._json(result)
        elif self.path == '/api/write/move':
            if not self._origin_ok():
                self.send_error(403, 'Origin not allowed'); return
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            result = write_move(body.get('root', ''), body.get('path', ''), body.get('destDir', ''))
            if result.get('ok'):
                log_action('move', f"{body.get('path')} -> {result.get('path')}")
            self._json(result)
        elif self.path == '/api/write/copy':
            if not self._origin_ok():
                self.send_error(403, 'Origin not allowed'); return
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            result = write_copy(body.get('root', ''), body.get('path', ''), body.get('destDir', ''))
            self._json(result)
        elif self.path == '/api/log':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            entry = log_action(body.get('action', 'unknown'), body.get('detail', ''))
            self._json({'ok': True, 'entry': entry})
        else:
            self.send_error(404)

    def _cors(self):
        origin = self.headers.get('Origin')
        self.send_response(200)
        if origin in self._allowed_origins():
            self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def _json(self, data):
        body = json.dumps(data).encode()
        origin = self.headers.get('Origin')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        if origin in self._allowed_origins():
            self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class FileVaultHTTPServer(http.server.ThreadingHTTPServer):
    pass


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    port = PREFERRED_PORT
    if '--port' in sys.argv:
        port = int(sys.argv[sys.argv.index('--port') + 1])
    else:
        port = find_free_port()

    server = FileVaultHTTPServer(('', port), Handler)
    server.port = port

    PORT_FILE.write_text(str(port))

    if port != PREFERRED_PORT:
        print(f'Port {PREFERRED_PORT} was busy — using {port} instead.')
    print(f'FileVault server → http://localhost:{port}/FileVault.html')
    print('Press Ctrl+C to stop.\n')

    try:
        server.serve_forever()
    finally:
        PORT_FILE.unlink(missing_ok=True)
