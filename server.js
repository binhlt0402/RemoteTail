const express = require('express');
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Convert PPK v2 private key (RSA or Ed25519) to OpenSSH format.
// Throws descriptive errors for PPK v3 or unsupported key types.
function convertPpkToOpenSSH(ppkContent, passphrase) {
  // ── Parse PPK file ────────────────────────────────────────────────────────
  const lines = ppkContent.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const info = { pubLines: [], privLines: [] };
  let state = 'header', linesLeft = 0;

  for (const line of lines) {
    if (state === 'pub')  { info.pubLines.push(line);  if (--linesLeft === 0) state = 'header'; continue; }
    if (state === 'priv') { info.privLines.push(line); if (--linesLeft === 0) state = 'header'; continue; }
    const m = line.match(/^([^:]+):\s*(.*)/);
    if (!m) continue;
    const [, k, v] = m;
    if      (k === 'PuTTY-User-Key-File-2') { info.version = 2; info.keyType = v; }
    else if (k === 'PuTTY-User-Key-File-3') { info.version = 3; }
    else if (k === 'Encryption')   info.encryption = v;
    else if (k === 'Comment')      info.comment = v || '';
    else if (k === 'Public-Lines')  { state = 'pub';  linesLeft = parseInt(v); }
    else if (k === 'Private-Lines') { state = 'priv'; linesLeft = parseInt(v); }
  }

  if (!info.version) throw new Error('Not a PPK file.');
  if (info.version === 3) throw new Error(
    'PPK v3 (PuTTY ≥ 0.75) is not supported.\n' +
    'Fix: PuTTYgen → Conversions → Export OpenSSH key → select that file.'
  );

  // ── Decrypt private blob if encrypted ─────────────────────────────────────
  let privBytes = Buffer.from(info.privLines.join(''), 'base64');
  if (info.encryption && info.encryption !== 'none') {
    if (!passphrase) throw new Error('Key is passphrase-protected but no passphrase was provided.');
    const pass = Buffer.from(passphrase, 'utf8');
    const k1 = crypto.createHash('sha1').update(Buffer.concat([Buffer.from([0,0,0,0]), pass])).digest();
    const k2 = crypto.createHash('sha1').update(Buffer.concat([Buffer.from([0,0,0,1]), pass])).digest();
    const aesKey = Buffer.concat([k1, k2]).slice(0, 32);
    const dec = crypto.createDecipheriv('aes-256-cbc', aesKey, Buffer.alloc(16, 0));
    dec.setAutoPadding(false);
    privBytes = Buffer.concat([dec.update(privBytes), dec.final()]);
  }

  // ── Parse SSH wire-format fields (uint32-length-prefixed) ─────────────────
  function readFields(buf) {
    const out = []; let i = 0;
    while (i + 4 <= buf.length) { const l = buf.readUInt32BE(i); i += 4; out.push(buf.slice(i, i + l)); i += l; }
    return out;
  }

  const pub  = readFields(Buffer.from(info.pubLines.join(''), 'base64'));
  const priv = readFields(privBytes);

  // ── Build output by key type ──────────────────────────────────────────────
  if (info.keyType === 'ssh-rsa') {
    return buildRsaPem(pub, priv);
  } else if (info.keyType === 'ssh-ed25519') {
    return buildEd25519OpenSSH(pub, priv, info.comment);
  } else {
    throw new Error(
      `PPK key type "${info.keyType}" is not supported for auto-conversion.\n` +
      'Fix: PuTTYgen → Conversions → Export OpenSSH key → select that file.'
    );
  }
}

// RSA: pub=[type,e,n]  priv=[d,p,q,iqmp]  → PKCS#1 PEM
function buildRsaPem(pub, priv) {
  const [, e, n] = pub;
  const [d, p, q, iqmp] = priv;
  const bi = b => BigInt('0x' + (b.toString('hex') || '0'));
  const bb = v => { let h = v.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); };
  const dp = bb(bi(d) % (bi(p) - 1n));
  const dq = bb(bi(d) % (bi(q) - 1n));
  const asnLen = n => n < 0x80 ? Buffer.from([n]) : n < 0x100 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  const asnInt = b => {
    while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.slice(1);
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return Buffer.concat([Buffer.from([0x02]), asnLen(b.length), b]);
  };
  const body = Buffer.concat([asnInt(Buffer.from([0])), asnInt(n), asnInt(e), asnInt(d), asnInt(p), asnInt(q), asnInt(dp), asnInt(dq), asnInt(iqmp)]);
  const der  = Buffer.concat([Buffer.from([0x30]), asnLen(body.length), body]);
  return `-----BEGIN RSA PRIVATE KEY-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END RSA PRIVATE KEY-----\n`;
}

// Ed25519: pub=[type,pubkey32]  priv=[seed32]  → OpenSSH new format
function buildEd25519OpenSSH(pub, priv, comment) {
  const pubkey  = pub[1];                          // 32 bytes
  const seed    = priv[0];                         // 32 bytes (PPK stores seed only)
  const privkey = Buffer.concat([seed, pubkey]);   // OpenSSH needs seed‖pubkey = 64 bytes

  const str = s => { const b = Buffer.isBuffer(s) ? s : Buffer.from(s); const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };
  const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };

  const pubBlob = Buffer.concat([str('ssh-ed25519'), str(pubkey)]);

  const check = Math.floor(Math.random() * 0x100000000);
  let privSection = Buffer.concat([
    u32(check), u32(check),
    str('ssh-ed25519'),
    str(pubkey),
    str(privkey),
    str(Buffer.from(comment || '', 'utf8')),
  ]);
  // Pad to multiple of cipher block size (8 for "none")
  const pad = (8 - (privSection.length % 8)) % 8;
  privSection = Buffer.concat([privSection, Buffer.from(Array.from({ length: pad }, (_, i) => i + 1))]);

  const full = Buffer.concat([
    Buffer.from('openssh-key-v1\0'),
    str('none'), str('none'), str(''),
    u32(1),
    str(pubBlob),
    str(privSection),
  ]);
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${full.toString('base64').match(/.{1,70}/g).join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

const sessions = new Map();

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function handleDisconnect(ws) {
  const session = sessions.get(ws);
  if (session) {
    try { session.end(); } catch {}
    sessions.delete(ws);
  }
}

function handleConnect(ws, msg) {
  handleDisconnect(ws);

  const { host, port, username, authType, password, privateKey, passphrase, filePath, lines } = msg;

  const conn = new Client();
  sessions.set(ws, conn);

  send(ws, { type: 'status', text: `Connecting to ${username}@${host}:${port || 22}...` });

  const authConfig = {
    host,
    port: port || 22,
    username,
    readyTimeout: 10000,
  };

  if (authType === 'password') {
    authConfig.password = password;
  } else {
    const keyStr = String(privateKey || '');
    if (keyStr.includes('PuTTY-User-Key-File-')) {
      try {
        authConfig.privateKey = convertPpkToOpenSSH(keyStr, passphrase);
      } catch (e) {
        send(ws, { type: 'error', text: e.message });
        sessions.delete(ws);
        return;
      }
    } else {
      authConfig.privateKey = privateKey;
      if (passphrase) authConfig.passphrase = passphrase;
    }
  }

  conn.on('ready', () => {
    send(ws, { type: 'status', text: `Connected! Tailing ${filePath}` });

    const tailLines = lines || 100;
    const escaped = filePath.replace(/'/g, `'\\''`);
    const cmd = `bash -c 'tail -n ${tailLines} "${escaped}"; sz=$(wc -c < "${escaped}"); while true; do sleep 0.5; nsz=$(wc -c < "${escaped}"); if [ "$nsz" -gt "$sz" ] 2>/dev/null; then tail -c +$((sz+1)) "${escaped}"; sz=$nsz; elif [ "$nsz" -lt "$sz" ] 2>/dev/null; then sz=0; fi; done'`;

    conn.exec(cmd, { pty: false }, (err, stream) => {
      if (err) {
        send(ws, { type: 'error', text: `Exec error: ${err.message}` });
        conn.end();
        return;
      }

      stream.on('data', (chunk) => {
        const text = chunk.toString('utf8');
        if (text) send(ws, { type: 'log', text });
      });

      stream.stderr.on('data', (chunk) => {
        const text = chunk.toString('utf8');
        if (text) send(ws, { type: 'error', text });
      });

      stream.on('close', () => {
        send(ws, { type: 'status', text: 'Stream closed.' });
        conn.end();
      });
    });
  });

  conn.on('error', (err) => {
    send(ws, { type: 'error', text: `SSH Error: ${err.message}` });
    sessions.delete(ws);
  });

  conn.on('end', () => {
    send(ws, { type: 'status', text: 'SSH connection ended.' });
    sessions.delete(ws);
  });

  conn.connect(authConfig);
}

function start(configDir) {
  const configFile = path.join(configDir || __dirname, 'configs.json');
  const prefsFile  = path.join(configDir || __dirname, 'prefs.json');

  function readConfigs() {
    try { return JSON.parse(fs.readFileSync(configFile, 'utf8')); } catch { return {}; }
  }
  function writeConfigs(data) {
    fs.writeFileSync(configFile, JSON.stringify(data, null, 2), 'utf8');
  }
  function readPrefs() {
    try { return JSON.parse(fs.readFileSync(prefsFile, 'utf8')); } catch { return {}; }
  }
  function writePrefs(data) {
    fs.writeFileSync(prefsFile, JSON.stringify(data, null, 2), 'utf8');
  }

  return new Promise((resolve) => {
    const app = express();
    const server = http.createServer(app);
    const wss = new WebSocketServer({ server });

    app.use(express.static(__dirname));
    app.get('/api/configs', (_req, res) => res.json(readConfigs()));
    app.post('/api/configs', express.json(), (req, res) => {
      writeConfigs(req.body);
      res.json({ ok: true });
    });
    app.get('/api/prefs', (_req, res) => res.json(readPrefs()));
    app.post('/api/prefs', express.json(), (req, res) => {
      writePrefs(req.body);
      res.json({ ok: true });
    });

    app.post('/api/browse', express.json(), (req, res) => {
      const { host, port: sshPort, username, authType, password, privateKey, passphrase, path: browsePath } = req.body;
      const targetPath = (browsePath || '/').replace(/\/+$/, '') || '/';

      const conn = new Client();

      conn.on('ready', () => {
        conn.sftp((err, sftp) => {
          if (err) { conn.end(); return res.status(500).json({ error: `SFTP: ${err.message}` }); }

          sftp.readdir(targetPath, (err, list) => {
            conn.end();
            if (err) return res.status(500).json({ error: err.message });

            const entries = list
              .filter(f => f.filename !== '.' && f.filename !== '..')
              .map(f => {
                const mode = f.attrs.mode || 0;
                const isDir = (mode & 0o170000) === 0o040000;
                return { name: f.filename, isDir, size: f.attrs.size || 0, mtime: f.attrs.mtime || 0 };
              })
              .sort((a, b) => {
                if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
                return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
              });

            res.json({ path: targetPath, entries });
          });
        });
      });

      conn.on('error', err => { if (!res.headersSent) res.status(500).json({ error: err.message }); });

      const authConfig = { host, port: sshPort || 22, username, readyTimeout: 8000 };
      if (authType === 'password') {
        authConfig.password = password;
      } else {
        const keyStr = String(privateKey || '');
        if (keyStr.includes('PuTTY-User-Key-File-')) {
          try { authConfig.privateKey = convertPpkToOpenSSH(keyStr, passphrase); }
          catch (e) { return res.status(400).json({ error: e.message }); }
        } else {
          authConfig.privateKey = privateKey;
          if (passphrase) authConfig.passphrase = passphrase;
        }
      }
      conn.connect(authConfig);
    });

    wss.on('connection', (ws) => {
      ws.on('message', (data) => {
        let msg;
        try { msg = JSON.parse(data); } catch { return; }
        if (msg.type === 'connect') handleConnect(ws, msg);
        else if (msg.type === 'disconnect') handleDisconnect(ws);
      });
      ws.on('close', () => handleDisconnect(ws));
    });

    // port 0 = OS picks a free port
    server.listen(0, '127.0.0.1', () => {
      resolve(server.address().port);
    });
  });
}

module.exports = { start };

if (require.main === module) {
  start().then(port => console.log(`Log Tailer running at http://localhost:${port}`));
}
