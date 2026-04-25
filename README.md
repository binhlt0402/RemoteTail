# RemoteTail

A Windows desktop app for tailing log files on remote Linux servers over SSH. Built with Electron + Node.js.

## Features

- **SSH connection management** — save multiple server connections (password or private key / PPK)
- **Remote file browser** — browse the server's file system via SFTP and click a file to start tailing
- **Multi-tab** — tail multiple files simultaneously, each in its own tab
- **Live tail** — new lines are highlighted as they arrive
- **Find in log** — search panel with click-to-jump, resizable (Ctrl+F)
- **Filter** — filter visible lines by keyword without losing the full log
- **Light / dark theme** — Discord-inspired dark theme by default, switchable

## Requirements

- Windows 10/11
- Target server must run Linux with `bash` available

## Development

```bash
npm install
npm start
```

> **Note:** If you have `ELECTRON_RUN_AS_NODE=1` set in your environment (common in VSCode), the start script clears it automatically.

## Build

Produces an NSIS installer and a portable `.exe` in `dist/`:

```bash
npm run build
```

## SSH Key Support

| Format | Support |
|--------|---------|
| OpenSSH PEM (RSA, Ed25519) | ✅ |
| PuTTY PPK v2 (RSA, Ed25519) | ✅ Auto-converted |
| PuTTY PPK v3 | ⚠️ Convert via PuTTYgen → Export OpenSSH key |

## Data Storage

Saved connections are stored in:
```
%APPDATA%\remotetail\configs.json
```

Passwords and private keys are stored in plain text — keep the file secure.
