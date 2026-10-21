# FileVault — Local File Manager

A single-page, local file manager that runs in your browser and works on your
**real files**. No accounts and no telemetry. You point it at a folder. It lists
the files, filters them, previews them, hashes them, and can copy, move, rename,
and trash them.

![status](https://img.shields.io/badge/status-personal%20project-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **Test on a copy first.** Rename, move, copy, and delete change the real files
> in the folder you open. Try the operation on a copy of anything you cannot
> afford to lose. This project is shared as-is, is not actively maintained, and
> comes with no warranty.

FileVault does **not** encrypt files and it is not a disk-encryption tool.

---

## Features

- **Browse a folder** with adjustable scan depth (1–10 subdirectory levels). Navigate into subfolders and back.
- **File-type sidebar** — filter by category (Documents, Images, Video, Audio, Code, Archives…) and drill into a single extension.
- **Hashing and duplicate detection** — SHA-256, SHA-512, SHA-1, or MD5, per file or in bulk. Matching hashes are color-grouped. Large files are read in chunks so they are not loaded all at once.
- **Preview** — PDF, DOCX, XLSX, RTF, plain text and code, common images, audio, and video, in a resizable side panel.
- **Sorting and columns** — sort by up to 4 columns; drag to reorder and resize columns.
- **Copy, move, rename, and trash.** Name collisions are refused (nothing is overwritten). Move and rename keep timestamps and extended attributes when the operating system can do a real rename.
- **Grid view** and a right-click menu.

HEIC/HEIF preview is the exception to “nothing leaves the machine”: the first time you preview one, the page loads `heic2any` from jsDelivr. No file you open is uploaded.

## Requirements

- **Python 3**, for the helper that serves the page and performs Trash (and, in Safari/Firefox, the other writes).
- **Google Chrome, Microsoft Edge, or Brave** for full read/write access in the page.
- **Safari or Firefox** can browse, preview, and hash. Rename, move, copy, and trash work through the helper once you type the folder’s absolute path into the header.
- **macOS** is what Trash’s Finder “Put Back” is written for. On other systems, trash is a real move into the desktop trash folder and Put Back is not available. Browsing, hashing, copy, and move still work.

## Running it

From the project folder:

```bash
python3 server.py
```

The terminal prints a URL, usually **http://127.0.0.1:8765/FileVault.html**. Open that in Chrome, Edge, or Brave and click **Open Directory**. If port 8765 is already in use, the server picks the next free port and prints it.

On macOS you can double-click **Launch FileVault.command**. It finds `python3` on your `PATH` (it does not assume a Homebrew path), starts the server, and opens a Chromium browser if one is installed.

The helper listens only on this computer (`127.0.0.1` and `::1`). Each launch has its own secret, injected into the page. Other machines on the network, and other websites, cannot call it.

Don’t open `FileVault.html` as a `file://` URL. The browser will sandbox the page, and the helper will not recognize it.

## How it works

| File | Role |
|------|------|
| `FileVault.html` | The whole app: HTML, CSS, and JavaScript. |
| `server.py` | Python standard-library helper. Serves the page, and renames, moves, copies, and trashes files when the page asks it to. |
| `Launch FileVault.command` | macOS shortcut that starts the helper and opens a browser. |

No build step and no package install. Reload the browser to see edits to the HTML.

```bash
python3 -m unittest discover -s tests -v
node tests/page_logic_test.mjs
```

GitHub Actions runs those checks, plus `node --check` on the page script, on Linux and macOS.

## Data safety

These are real filesystem operations.

- **Copy and move do not overwrite.** If the destination already has that name, the operation is skipped and the existing file is left as it is. Copying or moving an item into the folder it is already in does not rewrite or delete it.
- **Copy is checked with SHA-256**, not just file size. If the check fails, the new copy is removed and the original stays.
- A **copy is a new file**. Its creation time and inode change. When the helper does the copy, modification time, permissions, and extended attributes (including Finder tags, when the filesystem supports them) are kept. A copy done inside Chrome, Edge, or Brave cannot set Finder tags or the original creation time; that is a limit of the browser file API. The bytes are still checked.
- **Rename, and move on the same disk**, use a real rename (`os.rename`, or the browser’s `FileSystemHandle.move` in Chrome, Edge, and Brave). Timestamps and extended attributes stay. A move onto another disk may have to copy and then delete; tags can be lost in that case, and the original is removed only after the copy checks out.
- **Trash does not read the file into the browser.** The helper moves it. On macOS it uses the system Trash API so Finder’s Put Back still works. If that API cannot run, the file is left where it is. On Linux the file is renamed into the desktop trash folder (`~/.local/share/Trash/files` unless `XDG_DATA_HOME` is set), which does not provide Put Back.
- **Trash checks the path you typed.** For a file, the size and modification time must match the row you selected. If the absolute folder path is wrong, the helper refuses instead of taking a different file. Set that path in the header (Chrome can try to detect it). There is no default guess.
- **Hashing streams the file** in chunks (about 2 MB in the page, 1 MB in the helper). A multi-gigabyte file should not crash the tab from being loaded whole. It can still take a long time. Previewing a huge file can still use a lot of memory; office and image previews read the file they display.
- The browser drops folder permission on reload. You pick the folder again each session. That is the browser’s rule.

The action log is a JSON-lines file at `~/.filevault/actions.log` on this computer. It is not served over HTTP.

## License

MIT — see [LICENSE](LICENSE).
