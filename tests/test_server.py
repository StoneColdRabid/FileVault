"""Security and file-operation tests for the FileVault helper.

These exercise the real server: loopback binding, per-launch token, origin
and Host checks, and copy/move/rename/trash behavior on throwaway files.
"""
import errno
import hashlib
import http.client
import json
import os
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock
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


def set_xattr(path, name, value):
    """Set an extended attribute.

    Linux CPython has os.setxattr. macOS CPython does not, so those checks
    use /usr/bin/xattr. A failure fails the test; it is not skipped.
    """
    if hasattr(os, 'setxattr'):
        os.setxattr(path, name, value)
        return
    if sys.platform == 'darwin':
        xattr_set(path, name, value)


def assert_xattr(test, path, name, value):
    if hasattr(os, 'getxattr'):
        test.assertEqual(os.getxattr(path, name), value)
        return
    if sys.platform == 'darwin':
        test.assertEqual(xattr_get(path, name), value)


# Finder stores a tag as a binary plist on this attribute. The value is a
# list of strings, each a tag name, a newline, and a color number (6 is Red).
# A Finder comment is a binary plist string on the second attribute. Both are
# ordinary extended attributes; stock macOS can read and write them with
# /usr/bin/xattr. CPython on macOS does not ship os.setxattr, so the test
# cannot use the os module for this.
FINDER_TAG_ATTR = 'com.apple.metadata:_kMDItemUserTags'
FINDER_COMMENT_ATTR = 'com.apple.metadata:kMDItemFinderComment'


def xattr_set(path, name, value):
    """Write one extended attribute with the macOS xattr command."""
    proc = subprocess.run(
        ['/usr/bin/xattr', '-wx', name, value.hex(), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise OSError(detail or f'xattr -wx exited {proc.returncode}')


def xattr_get(path, name):
    """Return an attribute's bytes, or None when it is not set.

    `xattr -px` prints hexadecimal. Missing attributes are a copy failure,
    not a reason to skip the test.
    """
    proc = subprocess.run(
        ['/usr/bin/xattr', '-px', name, str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        missing = (
            'No such xattr' in detail
            or 'Attribute not found' in detail
            or 'Errno 93' in detail
        )
        if missing:
            return None
        raise OSError(detail or f'xattr -px exited {proc.returncode}')
    hex_chars = ''.join(ch for ch in proc.stdout if ch in '0123456789abcdefABCDEF')
    if not hex_chars:
        return b''
    if len(hex_chars) % 2:
        raise ValueError(f'xattr -px returned odd-length hex: {proc.stdout!r}')
    return bytes.fromhex(hex_chars)


def set_birthtime_ns(path, birth_ns):
    """Set the creation time of a file or folder. macOS only."""
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

    sec, nsec = divmod(int(birth_ns), 1_000_000_000)
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    lib.setattrlist.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(AttrList), ctypes.c_void_p,
        ctypes.c_size_t, ctypes.c_ulong,
    ]
    lib.setattrlist.restype = ctypes.c_int
    attrs = AttrList()
    attrs.bitmapcount = 5
    attrs.commonattr = 0x00000200  # ATTR_CMN_CRTIME
    spec = TimeSpec(sec, nsec)
    result = lib.setattrlist(
        os.fsencode(path), ctypes.byref(attrs), ctypes.byref(spec),
        ctypes.sizeof(spec), 1,
    )
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err) or 'setattrlist failed', str(path))


def birthtime_ns(path):
    """Creation time in nanoseconds.

    The macOS CPython build in CI exposes st_birthtime and not st_birthtime_ns.
    """
    st = os.lstat(path)
    if hasattr(st, 'st_birthtime_ns'):
        return st.st_birthtime_ns
    return int(round(st.st_birthtime * 1_000_000_000))


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
        set_xattr(src, 'user.test', b'tag')
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
        assert_xattr(self, copied, 'user.test', b'tag')
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

    @unittest.skipUnless(sys.platform == 'darwin', 'Finder tags are macOS extended attributes')
    def test_macos_copy_keeps_finder_tags_on_file_and_folder(self):
        """A helper copy must keep a real Finder tag, including inside a folder.

        The tag is the binary plist Finder writes on
        com.apple.metadata:_kMDItemUserTags. The comment is the plist Finder
        writes on com.apple.metadata:kMDItemFinderComment. Both are set with
        /usr/bin/xattr, then copied through write_copy (the /api/write/copy path).
        Creation time is set to a fixed past instant so it cannot match by chance.
        """
        tag = plistlib.dumps(['Red\n6'], fmt=plistlib.FMT_BINARY)
        comment = plistlib.dumps('Quarterly receipt', fmt=plistlib.FMT_BINARY)
        src = self.root / 'tagged.txt'
        src.write_bytes(b'tagged-bytes')
        xattr_set(src, FINDER_TAG_ATTR, tag)
        xattr_set(src, FINDER_COMMENT_ATTR, comment)
        # Whole seconds stay exact in st_birthtime, which is a float on macOS.
        # Set the creation time after mtime so a later utime cannot clear it.
        os.utime(src, ns=(1_700_000_000_000_000_000, 1_700_000_100_000_000_000))
        set_birthtime_ns(src, 1_000_000_000 * 1_000_000_000)
        stored_tag = xattr_get(src, FINDER_TAG_ATTR)
        stored_comment = xattr_get(src, FINDER_COMMENT_ATTR)
        self.assertIsNotNone(stored_tag, 'Finder tag was not stored on the source')
        self.assertEqual(plistlib.loads(stored_tag), ['Red\n6'])
        self.assertEqual(plistlib.loads(stored_comment), 'Quarterly receipt')
        self.assertEqual(birthtime_ns(src) // 1_000_000_000, 1_000_000_000)
        self.assertEqual(src.stat().st_mtime_ns, 1_700_000_100_000_000_000)

        dest = self.root / 'dest'
        dest.mkdir()
        result = server.write_copy(str(self.root), str(src), str(dest))
        self.assertTrue(result['ok'], result)
        copied = Path(result['path'])
        self.assertEqual(copied.read_bytes(), b'tagged-bytes')
        self.assertNotEqual(src.stat().st_ino, copied.stat().st_ino)
        with self.subTest('file tag'):
            self.assertEqual(xattr_get(copied, FINDER_TAG_ATTR), stored_tag)
        with self.subTest('finder comment'):
            self.assertEqual(xattr_get(copied, FINDER_COMMENT_ATTR), stored_comment)
        with self.subTest('file creation time'):
            self.assertEqual(birthtime_ns(copied), birthtime_ns(src))
        self.assertEqual(copied.stat().st_mtime_ns, src.stat().st_mtime_ns)

        folder = self.root / 'tagged-dir'
        folder.mkdir()
        inner = folder / 'inner.txt'
        inner.write_text('inside')
        xattr_set(inner, FINDER_TAG_ATTR, tag)
        xattr_set(folder, FINDER_TAG_ATTR, tag)
        os.utime(inner, ns=(1_600_000_000_000_000_000, 1_600_000_060_000_000_000))
        os.utime(folder, ns=(1_600_000_000_000_000_000, 1_600_000_050_000_000_000))
        set_birthtime_ns(inner, 1_000_000_001 * 1_000_000_000)
        set_birthtime_ns(folder, 1_000_000_002 * 1_000_000_000)
        inner_tag = xattr_get(inner, FINDER_TAG_ATTR)
        folder_tag = xattr_get(folder, FINDER_TAG_ATTR)
        self.assertEqual(plistlib.loads(inner_tag), ['Red\n6'])
        self.assertEqual(plistlib.loads(folder_tag), ['Red\n6'])
        folder_dest = self.root / 'folder-dest'
        folder_dest.mkdir()
        folder_result = server.write_copy(str(self.root), str(folder), str(folder_dest))
        self.assertTrue(folder_result['ok'], folder_result)
        copied_folder = Path(folder_result['path'])
        copied_inner = copied_folder / 'inner.txt'
        self.assertEqual(copied_inner.read_text(), 'inside')
        with self.subTest('tagged file inside a copied folder'):
            self.assertEqual(xattr_get(copied_inner, FINDER_TAG_ATTR), inner_tag)
        with self.subTest('tag on the copied folder'):
            self.assertEqual(xattr_get(copied_folder, FINDER_TAG_ATTR), folder_tag)
        with self.subTest('creation time inside a copied folder'):
            self.assertEqual(birthtime_ns(copied_inner), birthtime_ns(inner))
        with self.subTest('creation time of the copied folder'):
            self.assertEqual(birthtime_ns(copied_folder), birthtime_ns(folder))
        self.assertEqual(copied_inner.stat().st_mtime_ns, inner.stat().st_mtime_ns)
        self.assertEqual(copied_folder.stat().st_mtime_ns, folder.stat().st_mtime_ns)

    def test_copyfile_eexist_leaves_the_destination_that_won_the_race(self):
        """COPYFILE_EXCL lost the race: do not delete the file that appeared.

        copy_path sees no destination, then copyfile fails with EEXIST because
        that name was created in between. The loser must leave the winner alone.
        """
        src_file = self.root / 'src.txt'
        src_file.write_text('source')
        src_dir = self.root / 'srcdir'
        src_dir.mkdir()
        (src_dir / 'child.txt').write_text('child')

        def occupy_then_eexist(kind):
            def race(_src, dst, _flags):
                target = Path(dst)
                if kind == 'folder':
                    target.mkdir()
                    (target / 'kept.txt').write_text('preexisting')
                else:
                    target.write_text('preexisting')
                raise OSError(errno.EEXIST, os.strerror(errno.EEXIST))
            return race

        cases = (
            ('file', src_file, self.root / 'raced.txt'),
            ('folder', src_dir, self.root / 'raced-dir'),
        )
        for kind, src, dst in cases:
            with self.subTest(kind):
                with unittest.mock.patch.object(server.sys, 'platform', 'darwin'), \
                     unittest.mock.patch.object(
                         server, '_darwin_copyfile', side_effect=occupy_then_eexist(kind),
                     ):
                    with self.assertRaises(OSError) as caught:
                        server.copy_path(src, dst)
                self.assertEqual(caught.exception.errno, errno.EEXIST)
                self.assertTrue(dst.exists(), 'existing destination was removed')
                if kind == 'folder':
                    self.assertEqual((dst / 'kept.txt').read_text(), 'preexisting')
                else:
                    self.assertEqual(dst.read_text(), 'preexisting')
                self.assertTrue(src.exists())

    def test_move_same_folder_does_not_delete_or_rename(self):
        src = self.root / 'keep.txt'
        src.write_text('keepme')
        set_xattr(src, 'user.tag', b'blue')
        ino = src.stat().st_ino
        result = server.write_move(str(self.root), str(src), str(self.root))
        self.assertFalse(result['ok'])
        self.assertTrue(src.exists())
        self.assertEqual(src.read_text(), 'keepme')
        self.assertEqual(src.stat().st_ino, ino)
        assert_xattr(self, src, 'user.tag', b'blue')
        self.assertFalse(list(self.root.glob('keep (*).txt')))

    def test_move_refuses_existing_name_and_preserves_metadata(self):
        src = self.root / 'move-me.txt'
        src.write_text('payload')
        os.utime(src, (1_700_000_000, 1_711_111_111))
        set_xattr(src, 'user.tag', b'green')
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
        assert_xattr(self, target, 'user.tag', b'green')

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
        set_xattr(src, 'user.tag', b'red')
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
        assert_xattr(self, target, 'user.tag', b'red')
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
        set_xattr(big, 'user.tag', b'keep')
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
        assert_xattr(self, trashed, 'user.tag', b'keep')

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


def _put_back_location(filename):
    """Return the original folder Finder recorded for a Trash filename.

    `trashItemAtURL` writes a `ptbL` record into ~/.Trash/.DS_Store. On
    current macOS that value is a `ustr` (UTF-16-BE path of the original
    folder). Older stores may use a `blob` bookmark; those bytes are
    returned unchanged. A plain rename into ~/.Trash does not write `ptbL`.
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
    if type_at + 8 > len(data):
        return None
    dtype = data[type_at:type_at + 4]
    length = struct.unpack('>I', data[type_at + 4:type_at + 8])[0]
    if dtype == b'ustr':
        nbytes = length * 2
        end = type_at + 8 + nbytes
        if length > 100_000 or end > len(data):
            return None
        return data[type_at + 8:end].decode('utf-16-be')
    if dtype == b'blob':
        end = type_at + 8 + length
        if length > 1_000_000 or end > len(data):
            return None
        return data[type_at + 8:end]
    return None


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
            # Put Back itself is a Finder menu. The script-visible record is
            # the original folder path in ~/.Trash/.DS_Store (ptbL / ustr).
            location = _put_back_location(trashed.name)
            self.assertIsNotNone(
                location,
                'no Put Back record for the trashed name; ' + _put_back_diagnostic(trashed.name),
            )
            if isinstance(location, str):
                # The record is the original folder. Current macOS writes it
                # without a leading slash (Users/name/...), so root it before
                # comparing. A relative Path.resolve() would use the cwd.
                text = location.split('\x00', 1)[0]
                rooted = Path(text if text.startswith('/') else '/' + text)
                self.assertEqual(rooted.resolve(), folder.resolve(), f'Put Back record was {location!r}')
            else:
                self.assertIn(token.encode(), location)
        finally:
            _delete_trash_named(token)
            shutil.rmtree(folder, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
