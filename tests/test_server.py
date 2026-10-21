"""Security and file-operation tests for the FileVault helper.

These exercise the real server: loopback binding, per-launch token, origin
and Host checks, and copy/move/rename/trash behavior on throwaway files.
"""
import hashlib
import http.client
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

import server


def listening_v4(port):
    """Return raw local IPv4 addresses that are LISTEN on port.

    On Linux these are the little-endian hex addresses from /proc/net/tcp
    (127.0.0.1 is 0100007F, 0.0.0.0 is 00000000). macOS has no /proc, so the
    same two values are derived from lsof. Other addresses are returned as
    text so a non-loopback listener still fails the assertion.
    """
    if Path('/proc/net/tcp').exists():
        hexport = f'{port:04X}'
        found = []
        text = Path('/proc/net/tcp').read_text().splitlines()[1:]
        for line in text:
            parts = line.split()
            local, state = parts[1], parts[3]
            ip, pt = local.split(':')
            if pt.upper() == hexport and state == '0A':
                found.append(ip.upper())
        return found
    proc = subprocess.run(
        ['lsof', '-nP', f'-iTCP:{port}', '-sTCP:LISTEN'],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise OSError(proc.stderr.strip() or f'lsof exited {proc.returncode}')
    found = []
    for line in proc.stdout.splitlines()[1:]:
        for part in line.split():
            host, sep, port_s = part.rpartition(':')
            if not sep or port_s != str(port):
                continue
            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            if ':' in host:
                continue  # IPv6; /proc/net/tcp does not list it either
            if host == '127.0.0.1':
                found.append('0100007F')
            elif host in ('*', '0.0.0.0'):
                found.append('00000000')
            else:
                found.append(host)
            break
    return found


class ServerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.token = 'test-token-0123456789abcdef'
        self.log_path = self.root / 'log' / 'actions.log'
        self.trash_dir = self.root / 'trash'
        self.httpd = server.create_server(
            '127.0.0.1',
            0,
            self.token,
            action_log=self.log_path,
            trash_dir=self.trash_dir,
            search_roots=[str(self.root / 'search')],
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def request(self, method, path, body=None, *, host=None, origin=None, token=None, extra_headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        headers = {}
        if host is not False:
            headers['Host'] = f'127.0.0.1:{self.port}' if host is None else host
        if origin is not False:
            headers['Origin'] = f'http://127.0.0.1:{self.port}' if origin is None else origin
        if token is not False:
            headers['X-FileVault-Token'] = self.token if token is None else token
        data = None
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        elif isinstance(body, str):
            data = body.encode()
            headers.setdefault('Content-Type', 'application/json')
        elif isinstance(body, bytes):
            data = body
        if extra_headers:
            headers.update(extra_headers)
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        status = resp.status
        hdrs = dict(resp.getheaders())
        conn.close()
        return status, raw, hdrs

    def json(self, method, path, body=None, **kwargs):
        status, raw, hdrs = self.request(method, path, body, **kwargs)
        try:
            parsed = json.loads(raw.decode() or 'null')
        except json.JSONDecodeError:
            parsed = None
        return status, parsed, hdrs


class BindAndAuthTests(ServerTestCase):
    def test_refuses_to_bind_all_interfaces(self):
        with self.assertRaises(ValueError):
            server.create_server('0.0.0.0', 0, self.token)
        with self.assertRaises(ValueError):
            server.create_server('', 0, self.token)
        addrs = listening_v4(self.port)
        self.assertIn('0100007F', addrs)  # 127.0.0.1
        self.assertNotIn('00000000', addrs)  # 0.0.0.0

    def test_loopback_servers_do_not_listen_on_every_interface(self):
        token = 'loop-token'
        servers = server.start_loopback(
            0,
            token,
            action_log=self.root / 'loop.log',
            trash_dir=self.root / 'loop-trash',
        )
        threads = [threading.Thread(target=srv.serve_forever, daemon=True) for srv in servers]
        for thread in threads:
            thread.start()
        try:
            port = servers[0].server_address[1]
            self.assertNotIn('00000000', listening_v4(port))
            self.assertTrue(any(s.server_address[0] in ('127.0.0.1', '::1') for s in servers))
            # The page is reachable on IPv4 loopback with the shared token.
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            conn.request('GET', '/FileVault.html', headers={'Host': f'127.0.0.1:{port}'})
            resp = conn.getresponse()
            body = resp.read().decode()
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertIn(token, body)
            self.assertNotIn('__FILEVAULT_TOKEN__', body)
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_page_requires_a_loopback_host_header(self):
        status, raw, hdrs = self.request(
            'GET', '/FileVault.html', token=False, origin=False, host='evil.example'
        )
        self.assertEqual(status, 403)
        self.assertNotIn(self.token.encode(), raw)
        self.assertNotIn(b'__FILEVAULT_TOKEN__', raw)

    def test_served_page_has_token_and_csp(self):
        status, raw, hdrs = self.request('GET', '/FileVault.html', token=False, origin=False)
        self.assertEqual(status, 200)
        text = raw.decode()
        self.assertIn(self.token, text)
        self.assertNotIn('__FILEVAULT_TOKEN__', text)
        csp = hdrs.get('Content-Security-Policy') or hdrs.get('content-security-policy')
        self.assertTrue(csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertNotIn('trash-upload', text)

    def test_project_files_and_action_log_are_not_served(self):
        for path in ('/server.py', '/filevault-actions.log', '/README.md', '/.gitignore'):
            status, raw, _ = self.request('GET', path, token=False, origin=False)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b'import http.server', raw)

    def test_missing_origin_is_rejected(self):
        src = self._file('note.txt', 'hello')
        status, parsed, _ = self.json(
            'POST',
            '/api/write/rename',
            {'root': str(self.root), 'path': str(src), 'newName': 'renamed.txt'},
            origin=False,
        )
        self.assertEqual(status, 403)
        self.assertTrue(src.exists())
        self.assertFalse((src.parent / 'renamed.txt').exists())

    def test_evil_origin_is_rejected_even_with_the_token(self):
        src = self._file('note.txt', 'hello')
        status, _, _ = self.json(
            'POST',
            '/api/write/rename',
            {'root': str(self.root), 'path': str(src), 'newName': 'renamed.txt'},
            origin='https://evil.example',
        )
        self.assertEqual(status, 403)
        self.assertTrue(src.exists())

    def test_missing_or_wrong_token_is_rejected(self):
        src = self._file('note.txt', 'hello')
        body = {'root': str(self.root), 'path': str(src), 'newName': 'renamed.txt'}
        for token in (False, 'not-the-token'):
            status, _, _ = self.json('POST', '/api/write/rename', body, token=token)
            self.assertEqual(status, 403)
        self.assertEqual(src.read_text(), 'hello')

    def test_wrong_host_header_is_rejected(self):
        src = self._file('note.txt', 'hello')
        status, _, _ = self.json(
            'POST',
            '/api/log',
            {'action': 'delete', 'detail': 'forged'},
            host='evil.example:8765',
        )
        self.assertEqual(status, 403)
        self.assertFalse(self.log_path.exists())

    def test_log_and_find_dir_require_auth_and_do_not_forge(self):
        status, _, _ = self.json(
            'POST', '/api/log', {'action': 'delete', 'detail': 'forged'}, token=False, origin=False
        )
        self.assertEqual(status, 403)
        self.assertFalse(self.log_path.exists())

        status, _, _ = self.request('GET', '/api/find-dir?name=Anything', token=False, origin=False)
        self.assertEqual(status, 403)

    def test_find_dir_with_auth_returns_a_match(self):
        folder = self.root / 'search' / 'Photos'
        folder.mkdir(parents=True)
        status, parsed, _ = self.json('GET', '/api/find-dir?name=Photos')
        self.assertEqual(status, 200)
        self.assertEqual(parsed.get('path'), str(folder))

    def test_malformed_json_returns_400_and_server_stays_up(self):
        status, _, _ = self.request('POST', '/api/log', '{')
        self.assertEqual(status, 400)
        status, raw, _ = self.request('GET', '/FileVault.html', token=False, origin=False)
        self.assertEqual(status, 200)
        self.assertIn(self.token.encode(), raw)

    def test_trash_upload_endpoint_is_gone(self):
        status, _, _ = self.request(
            'POST',
            '/api/trash-upload?name=evil.txt',
            b'junk',
            extra_headers={'Content-Type': 'text/plain'},
        )
        self.assertIn(status, (403, 404))
        self.assertFalse((self.trash_dir / 'evil.txt').exists())

    def test_symlink_cannot_escape_root(self):
        outside = self.root / 'outside-secret.txt'
        outside.write_text('secret')
        inside = self.root / 'work'
        inside.mkdir()
        link = inside / 'link.txt'
        link.symlink_to(outside)
        dest = self.root / 'dest'
        dest.mkdir()
        status, parsed, _ = self.json(
            'POST',
            '/api/write/move',
            {'root': str(inside), 'path': str(link), 'destDir': str(dest)},
        )
        self.assertEqual(status, 200)
        self.assertFalse(parsed['ok'])
        self.assertEqual(outside.read_text(), 'secret')
        self.assertFalse((dest / 'link.txt').exists())
        self.assertFalse((dest / 'outside-secret.txt').exists())

    def _file(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


class FileOperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / 'root'
        self.root.mkdir()
        self.trash = Path(self.tmp.name) / 'trash'
        self.trash.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_copy_does_not_overwrite_and_verifies_bytes(self):
        src = self.root / 'a.txt'
        src.write_bytes(b'source-bytes')
        os.chmod(src, 0o640)
        os.utime(src, (1_700_000_000, 1_700_000_000))
        os.setxattr(src, 'user.test', b'tag')
        dest_dir = self.root / 'dest'
        dest_dir.mkdir()
        existing = dest_dir / 'a.txt'
        existing.write_text('keep-me')

        result = server.write_copy(str(self.root), str(src), str(dest_dir))
        self.assertFalse(result['ok'])
        self.assertEqual(existing.read_text(), 'keep-me')
        self.assertEqual(src.read_bytes(), b'source-bytes')

        existing.unlink()
        result = server.write_copy(str(self.root), str(src), str(dest_dir))
        self.assertTrue(result['ok'], result)
        copied = Path(result['path'])
        self.assertEqual(copied.read_bytes(), b'source-bytes')
        self.assertEqual(stream_hash(src), stream_hash(copied))
        self.assertNotEqual(src.stat().st_ino, copied.stat().st_ino)
        self.assertEqual(src.stat().st_mtime, copied.stat().st_mtime)
        self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o640)
        self.assertEqual(os.getxattr(copied, 'user.test'), b'tag')
        self.assertTrue(src.exists())

    def test_copy_same_folder_does_not_truncate_the_file(self):
        src = self.root / 'only.txt'
        src.write_text('do-not-lose')
        ino = src.stat().st_ino
        result = server.write_copy(str(self.root), str(src), str(self.root))
        self.assertFalse(result['ok'])
        self.assertEqual(src.read_text(), 'do-not-lose')
        self.assertEqual(src.stat().st_ino, ino)
        self.assertEqual(list(self.root.iterdir()), [src])

    def test_copy_folder_and_refuse_to_copy_into_itself(self):
        folder = self.root / 'dir'
        nested = folder / 'sub'
        nested.mkdir(parents=True)
        (nested / 'n.txt').write_text('nested')
        (folder / 'top.txt').write_bytes(os.urandom(256 * 1024))
        dest = self.root / 'out'
        dest.mkdir()
        result = server.write_copy(str(self.root), str(folder), str(dest))
        self.assertTrue(result['ok'], result)
        copied = Path(result['path'])
        self.assertEqual((copied / 'sub' / 'n.txt').read_text(), 'nested')
        self.assertEqual((copied / 'top.txt').read_bytes(), (folder / 'top.txt').read_bytes())
        self.assertEqual(stream_hash(folder / 'top.txt'), stream_hash(copied / 'top.txt'))

        before = sorted(p.relative_to(folder).as_posix() for p in folder.rglob('*'))
        into = server.write_copy(str(self.root), str(folder), str(nested))
        self.assertFalse(into['ok'])
        after = sorted(p.relative_to(folder).as_posix() for p in folder.rglob('*'))
        self.assertEqual(before, after)

    def test_move_same_folder_does_not_delete_or_rename(self):
        src = self.root / 'keep.txt'
        src.write_text('keepme')
        os.setxattr(src, 'user.tag', b'blue')
        ino = src.stat().st_ino
        result = server.write_move(str(self.root), str(src), str(self.root))
        self.assertFalse(result['ok'])
        self.assertTrue(src.exists())
        self.assertEqual(src.read_text(), 'keepme')
        self.assertEqual(src.stat().st_ino, ino)
        self.assertEqual(os.getxattr(src, 'user.tag'), b'blue')
        self.assertFalse(list(self.root.glob('keep (*).txt')))

    def test_move_refuses_existing_name_and_preserves_metadata(self):
        src = self.root / 'move-me.txt'
        src.write_text('payload')
        os.utime(src, (1_700_000_000, 1_711_111_111))
        os.setxattr(src, 'user.tag', b'green')
        dest = self.root / 'dest'
        dest.mkdir()
        (dest / 'move-me.txt').write_text('already')
        blocked = server.write_move(str(self.root), str(src), str(dest))
        self.assertFalse(blocked['ok'])
        self.assertEqual(src.read_text(), 'payload')
        self.assertEqual((dest / 'move-me.txt').read_text(), 'already')

        (dest / 'move-me.txt').unlink()
        ino = src.stat().st_ino
        moved = server.write_move(str(self.root), str(src), str(dest))
        self.assertTrue(moved['ok'], moved)
        target = Path(moved['path'])
        self.assertFalse(src.exists())
        self.assertEqual(target.read_text(), 'payload')
        self.assertEqual(target.stat().st_ino, ino)
        self.assertEqual(target.stat().st_mtime, 1_711_111_111)
        self.assertEqual(os.getxattr(target, 'user.tag'), b'green')

    def test_move_folder_into_itself_is_refused(self):
        folder = self.root / 'tree'
        child = folder / 'child'
        child.mkdir(parents=True)
        (folder / 'f.txt').write_text('safe')
        result = server.write_move(str(self.root), str(folder), str(child))
        self.assertFalse(result['ok'])
        self.assertEqual((folder / 'f.txt').read_text(), 'safe')
        self.assertTrue(folder.is_dir())

    def test_rename_preserves_inode_xattrs_and_refuses_collisions(self):
        src = self.root / 'old.txt'
        src.write_text('body')
        os.setxattr(src, 'user.tag', b'red')
        other = self.root / 'taken.txt'
        other.write_text('taken')
        ino = src.stat().st_ino
        blocked = server.write_rename(str(self.root), str(src), 'taken.txt')
        self.assertFalse(blocked['ok'])
        self.assertEqual(src.read_text(), 'body')
        self.assertEqual(other.read_text(), 'taken')

        renamed = server.write_rename(str(self.root), str(src), 'new.txt')
        self.assertTrue(renamed['ok'], renamed)
        target = Path(renamed['path'])
        self.assertEqual(target.stat().st_ino, ino)
        self.assertEqual(os.getxattr(target, 'user.tag'), b'red')
        self.assertFalse(src.exists())

    def test_rename_rejects_path_separators_and_overlong_names(self):
        src = self.root / 'old.txt'
        src.write_text('body')
        for bad in ('../x', 'a/b', 'a\\b', 'a:b', 'a\x00b', 'x' * 300):
            result = server.write_rename(str(self.root), str(src), bad)
            self.assertFalse(result['ok'], bad)
        self.assertEqual(src.read_text(), 'body')

    def test_trash_renames_files_and_folders_without_reading_them_into_a_new_inode(self):
        big = self.root / 'big.bin'
        # A few megabytes is enough to show this is a rename: the inode is kept
        # and the operation does not depend on loading the bytes in Python.
        big.write_bytes(b'x' * (3 * 1024 * 1024))
        os.setxattr(big, 'user.tag', b'keep')
        ino = big.stat().st_ino
        result = server.trash_items(
            str(self.root),
            [{'path': str(big), 'isDir': False, 'size': big.stat().st_size, 'mtimeMs': big.stat().st_mtime * 1000}],
            trash_dir=self.trash,
        )[0]
        self.assertTrue(result['ok'], result)
        self.assertFalse(big.exists())
        trashed = Path(result['trashedPath'])
        self.assertEqual(trashed.stat().st_ino, ino)
        self.assertEqual(trashed.stat().st_size, 3 * 1024 * 1024)
        self.assertEqual(os.getxattr(trashed, 'user.tag'), b'keep')

        folder = self.root / 'box'
        folder.mkdir()
        (folder / 'inner.txt').write_text('inside')
        dir_ino = folder.stat().st_ino
        result = server.trash_items(
            str(self.root),
            [{'path': str(folder), 'isDir': True}],
            trash_dir=self.trash,
        )[0]
        self.assertTrue(result['ok'], result)
        trashed_dir = Path(result['trashedPath'])
        self.assertEqual(trashed_dir.stat().st_ino, dir_ino)
        self.assertEqual((trashed_dir / 'inner.txt').read_text(), 'inside')

    def test_trash_name_collision_does_not_overwrite(self):
        first = self.root / 'same.txt'
        first.write_text('one')
        server.trash_items(
            str(self.root),
            [{'path': str(first), 'isDir': False, 'size': first.stat().st_size, 'mtimeMs': first.stat().st_mtime * 1000}],
            trash_dir=self.trash,
        )
        second = self.root / 'same.txt'
        second.write_text('two')
        result = server.trash_items(
            str(self.root),
            [{'path': str(second), 'isDir': False, 'size': second.stat().st_size, 'mtimeMs': second.stat().st_mtime * 1000}],
            trash_dir=self.trash,
        )[0]
        self.assertTrue(result['ok'], result)
        names = sorted(p.name for p in self.trash.iterdir())
        self.assertEqual(names, ['same (1).txt', 'same.txt'])
        texts = sorted(p.read_text() for p in self.trash.iterdir())
        self.assertEqual(texts, ['one', 'two'])

    def test_trash_refuses_size_or_mtime_mismatch_and_paths_outside_root(self):
        src = self.root / 'real.txt'
        src.write_text('abc')
        mismatch = server.trash_items(
            str(self.root),
            [{'path': str(src), 'isDir': False, 'size': 999, 'mtimeMs': src.stat().st_mtime * 1000}],
            trash_dir=self.trash,
        )[0]
        self.assertFalse(mismatch['ok'])
        self.assertTrue(src.exists())

        stale = server.trash_items(
            str(self.root),
            [{'path': str(src), 'isDir': False, 'size': src.stat().st_size, 'mtimeMs': 0}],
            trash_dir=self.trash,
        )[0]
        self.assertFalse(stale['ok'])
        self.assertEqual(src.read_text(), 'abc')

        outside = Path(self.tmp.name) / 'outside.txt'
        outside.write_text('nope')
        escaped = server.trash_items(
            str(self.root),
            [{'path': str(outside), 'isDir': False, 'size': outside.stat().st_size, 'mtimeMs': outside.stat().st_mtime * 1000}],
            trash_dir=self.trash,
        )[0]
        self.assertFalse(escaped['ok'])
        self.assertTrue(outside.exists())

    def test_stream_hash_matches_hashlib_for_a_multi_chunk_file(self):
        path = self.root / 'chunked.bin'
        blob = b''.join(bytes([i % 251]) * 1000 for i in range(80))  # 80_000 bytes, not one read
        path.write_bytes(blob)
        self.assertEqual(server.stream_hash(path), hashlib.sha256(blob).hexdigest())
        self.assertEqual(server.stream_hash(path, 'sha512'), hashlib.sha512(blob).hexdigest())

    def test_authenticated_http_trash_and_move(self):
        # Full request path, not just the helper functions.
        token = 'http-token'
        log_path = Path(self.tmp.name) / 'actions.log'
        httpd = server.create_server(
            '127.0.0.1', 0, token, action_log=log_path, trash_dir=self.trash
        )
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            src = self.root / 'via-http.txt'
            src.write_text('http-body')
            body = json.dumps({
                'root': str(self.root),
                'items': [{
                    'path': str(src),
                    'isDir': False,
                    'size': src.stat().st_size,
                    'mtimeMs': src.stat().st_mtime * 1000,
                }],
            }).encode()
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            conn.request('POST', '/api/trash', body=body, headers={
                'Host': f'127.0.0.1:{port}',
                'Origin': f'http://127.0.0.1:{port}',
                'X-FileVault-Token': token,
                'Content-Type': 'application/json',
            })
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode())
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertTrue(payload['results'][0]['ok'])
            self.assertFalse(src.exists())
            self.assertTrue(any(p.name == 'via-http.txt' for p in self.trash.iterdir()))
        finally:
            httpd.shutdown()
            httpd.server_close()


def stream_hash(path):
    return server.stream_hash(path)


def _user_trash():
    return Path.home() / '.Trash'


def _find_in_user_trash(token, payload):
    """Return the Trash entry this test created, matched by name and bytes."""
    trash = _user_trash()
    if not trash.is_dir():
        return None
    matches = []
    for child in trash.iterdir():
        if token not in child.name or not child.is_file():
            continue
        try:
            data = child.read_bytes()
        except OSError:
            continue
        if data == payload:
            matches.append(child)
    if len(matches) == 1:
        return matches[0]
    return None


def _delete_trash_named(token):
    trash = _user_trash()
    if not trash.is_dir():
        return
    for child in list(trash.iterdir()):
        if token not in child.name:
            continue
        if child.is_file() or child.is_symlink():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            shutil.rmtree(child, ignore_errors=True)


def _put_back_blob(filename):
    """Return the ~/.Trash/.DS_Store `ptbL` blob for filename, if recorded.

    Finder's Put Back reads this bookmark of the original folder. A plain
    rename into ~/.Trash does not write it. The record is not a public API;
    callers that cannot see it should say so instead of assuming Put Back.
    """
    ds_path = _user_trash() / '.DS_Store'
    if not ds_path.is_file():
        return None
    data = ds_path.read_bytes()
    encoded = filename.encode('utf-16-be')
    marker = struct.pack('>I', len(filename)) + encoded + b'ptbL'
    idx = data.find(marker)
    if idx < 0:
        return None
    type_at = idx + len(marker)
    if data[type_at:type_at + 4] != b'blob':
        return None
    if type_at + 8 > len(data):
        return None
    length = struct.unpack('>I', data[type_at + 4:type_at + 8])[0]
    end = type_at + 8 + length
    if length > 1_000_000 or end > len(data):
        return None
    return data[type_at + 8:end]


def _put_back_diagnostic(filename):
    ds_path = _user_trash() / '.DS_Store'
    if not ds_path.is_file():
        return f'{ds_path} does not exist'
    data = ds_path.read_bytes()
    encoded = filename.encode('utf-16-be')
    snippets = []
    start = 0
    while len(snippets) < 4:
        i = data.find(encoded, start)
        if i < 0:
            break
        snippets.append(data[max(0, i - 4):i + len(encoded) + 12].hex())
        start = i + 1
    return f'{ds_path} is {len(data)} bytes; filename windows: {snippets or "none"}'


class MacTrashTests(unittest.TestCase):
    def test_macos_helper_leaves_the_file_alone_when_osascript_cannot_run(self):
        # On Linux, osascript is absent. The helper must not delete the file
        # or fall back to a copy that would drop Finder Put Back metadata.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'stay.txt'
            path.write_text('stay')
            result = server.trash_via_macos(path)
            if shutil.which('osascript'):
                self.skipTest('osascript is available; Put Back can only be checked on macOS')
            self.assertFalse(result['ok'])
            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(), 'stay')
            self.assertNotIn(str(path), result.get('argv_script', ''))

    @unittest.skipUnless(sys.platform == 'darwin', 'Finder Trash only exists on macOS')
    def test_macos_trash_moves_throwaway_file_into_user_trash(self):
        # Home is the same volume as ~/.Trash, so NSFileManager does not
        # divert the file to another volume's .Trashes folder.
        token = uuid.uuid4().hex
        folder = Path(tempfile.mkdtemp(prefix=f'filevault-ci-{token}-', dir=Path.home()))
        try:
            src = folder / f'{token}.txt'
            payload = f'filevault-trash-{token}\n'.encode()
            src.write_bytes(payload)
            result = server.trash_items(
                str(folder),
                [{
                    'path': str(src),
                    'isDir': False,
                    'size': src.stat().st_size,
                    'mtimeMs': src.stat().st_mtime * 1000,
                }],
            )[0]
            self.assertTrue(result['ok'], result)
            self.assertFalse(src.exists(), 'file is still in the folder it was trashed from')
            trashed = _find_in_user_trash(token, payload)
            self.assertIsNotNone(trashed, f'{token} is not in {_user_trash()}')
            self.assertEqual(trashed.read_bytes(), payload)
            # Put Back is a Finder action. What a script can see is the
            # ptbL bookmark trashItemAtURL writes into ~/.Trash/.DS_Store.
            blob = _put_back_blob(trashed.name)
            self.assertIsNotNone(
                blob,
                'no Put Back record for the trashed name; ' + _put_back_diagnostic(trashed.name),
            )
            self.assertIn(token.encode(), blob, 'Put Back bookmark does not name the original folder')
        finally:
            _delete_trash_named(token)
            shutil.rmtree(folder, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
