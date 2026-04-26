# RemoteTail

A Windows desktop app for tailing log files on remote Linux servers over SSH. Built with **Tauri v2 + Rust** — installer is ~8 MB instead of the ~77 MB Electron version. I didn't find any app that could do exactly what I wanted, so I built it myself using Claude Code.

## Features

- **SSH connection management** — save multiple server connections (password or private key / PPK)
- **Remote file browser** — browse the server's filesystem via SFTP and click a file to start tailing
- **Multi-tab** — tail multiple files simultaneously, each in its own tab
- **Live tail** — new lines stream in real-time and are highlighted as they arrive
- **Find in log** — search panel with click-to-jump, resizable (Ctrl+F)
- **Filter** — filter visible lines by keyword without losing the full log
- **Light / dark theme** — Discord-inspired dark theme by default, switchable

## Requirements

- Windows 10/11 (WebView2 / Microsoft Edge must be installed — it is on all modern Windows)
- Target server must run Linux with `bash` available

## Development

Requires [Rust](https://rustup.rs) and Node.js.

```bash
npm install
npm run dev        # first build takes ~10 min (compiling Rust deps); subsequent runs ~30 s
```

## Build

Produces an NSIS installer in `src-tauri/target/release/bundle/`:

```bash
npm run build
```

## SSH Key Support

| Format | Support |
|--------|---------|
| OpenSSH PEM (RSA, Ed25519) | ✅ |
| PuTTY PPK v2 (RSA, Ed25519) | ✅ Auto-converted in Rust |
| PuTTY PPK v3 | ⚠️ Convert via PuTTYgen → Conversions → Export OpenSSH key |

## Data Storage

Saved connections are stored in:
```
%APPDATA%\com.remotetail.app\configs.json
```

Passwords and private keys are stored in plain text — keep the file secure.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| UI shell | [Tauri v2](https://tauri.app) (uses system WebView2) |
| Backend | Rust (async via Tokio) |
| SSH / SFTP | [russh](https://github.com/warp-tech/russh) (pure Rust, no OpenSSL) |
| Frontend | Vanilla HTML/CSS/JS (no framework) |
