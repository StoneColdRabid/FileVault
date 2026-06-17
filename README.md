# FileVault — Local File Manager

A single-page, local-first file manager that runs in your browser and works on
your **real files** through the [File System Access API](https://developer.mozilla.org/en-US/docs/Web/API/File_System_API).
No accounts, no cloud, no telemetry — it talks only to the folder you point it at.

Built for sifting through large, messy directories: finding duplicates by hash,
renaming cryptically-named files while previewing them, and copying/moving/trashing
in bulk.

![status](https://img.shields.io/badge/status-personal%20project-blue)
![license](https://img.shields.io/badge/license-MIT-green)

> **Heads up:** This is a personal project shared as-is. It works well for what it
> was built to do, but it is not actively maintained and comes with no warranty.
> Use it, fork it, change it — just don't blame me if something breaks. See the
> data-safety note below before using rename/move/delete on files you care about.

---

## Features

- **Browse any folder or drive** with adjustable scan depth (1–10 subdirectory levels). Navigate into subfolders and back.
- **File-type sidebar** — filter by category (Documents, Images, Video, Audio,
  Code, Archives…) and drill into a single extension (e.g. just PDFs) in one click.
- **Hashing & duplicate detection** — compute SHA-256 / SHA-1 / MD5 per file or in
  bulk; matching hashes are color-grouped so duplicates jump out. Sort by hash to
  cluster them.
- **Document preview** — PDF, DOCX, XLSX, RTF, plain text/code, images (PNG, JPG,
  WebP, BMP, GIF, SVG, AVIF, and more, with rotation), audio, and video — all
  rendered in a resizable side panel.
- **Multi-level sorting** — sort by up to 4 columns (Shift-click headers to add
  levels); drag to reorder and resize columns.
- **File operations** — copy, move, inline rename, and delete (delete routes to the
  macOS Trash via the helper server, not a permanent wipe).
- **Safe rename** — validates the new name, writes-and-verifies the copy, and only
  then removes the original; on any error the original is left untouched.
- **Grid view** — toggle between list and thumbnail grid layouts.
- **Right-click context menu** — quick access to rename, preview, copy, and delete.

## Requirements

- **A Chromium-based browser**: Google Chrome, Microsoft Edge, or Brave.
  Safari and Firefox do **not** support the File System Access API and will not work.
- **Python 3** (only for the small helper server, which enables Trash support and
  avoids browser `file://` restrictions).

## Running it

```bash
# from the project folder
python3 server.py
```

Then open **http://localhost:8765/FileVault.html** in Chrome/Edge/Brave and click
**Open Directory**.

On macOS you can also double-click **Launch FileVault.command** — it starts the
server and opens the browser in one step.

> Don't open `FileVault.html` directly from the filesystem (`file://…`). Browsers
> sandbox local pages and most previews (and Trash) won't work. Always go through
> the local server URL above.

## How it works

Everything lives in two files:

| File             | Role                                                                              |
|------------------|-----------------------------------------------------------------------------------|
| `FileVault.html` | The entire app — HTML, CSS, and JavaScript in one file.                           |
| `server.py`      | ~70-line Python stdlib server: serves the file and moves deleted items to `~/.Trash` via a tiny `POST /api/trash` route. |

No framework, no build step, no dependencies. Open `FileVault.html` in any editor
and reload the browser to see changes.

## A note on data safety

This tool performs **real file operations** (rename, move, delete) on the directory
you grant it access to. Rename is implemented defensively (validate → write → verify
→ delete original), and delete moves to the Trash rather than wiping. Even so:

- Test on a copy of important data first.
- The browser revokes file-system access on every page reload, so you'll re-pick the
  folder each session. That's a deliberate browser privacy protection, not a bug.

## License

MIT — see [LICENSE](LICENSE).
