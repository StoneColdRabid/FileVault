#!/usr/bin/env python3
"""
FileVault local server.
- Serves FileVault.html at http://localhost:8765/FileVault.html
- POST /api/trash  { "paths": ["/abs/path/to/file", ...] }
  Moves each path to ~/.Trash, handling name collisions.
"""
import http.server
import json
import os
import shutil
from pathlib import Path

PORT = 8765
TRASH = Path.home() / '.Trash'


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
    def do_OPTIONS(self):
        self._cors()

    def do_POST(self):
        if self.path == '/api/trash':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            results = [trash_item(p) for p in body.get('paths', [])]
            self._json({'results': results})
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
        pass  # suppress per-request noise


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print(f'FileVault server → http://localhost:{PORT}/FileVault.html')
    print('Press Ctrl+C to stop.\n')
    http.server.HTTPServer(('', PORT), Handler).serve_forever()
