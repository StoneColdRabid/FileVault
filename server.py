#!/usr/bin/env python3
"""
FileVault local server.
- Finds a free port starting at 8765; writes chosen port to ~/.filevault_port
- Serves FileVault.html with the actual port injected (for the trash API URL)
- POST /api/trash  { "paths": ["/abs/path/to/file", ...] }
  Moves each path to ~/.Trash, handling name collisions.
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

PREFERRED_PORT = 8765
TRASH = Path.home() / '.Trash'
PORT_FILE = Path.home() / '.filevault_port'


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

    def do_POST(self):
        if self.path == '/api/trash':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            results = [trash_item(p) for p in body.get('paths', [])]
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
            self._json({'ok': True})
        else:
            self.send_error(404)

    def _cors(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
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
