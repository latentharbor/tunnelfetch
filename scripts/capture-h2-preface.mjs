// Record what a REAL client sends over HTTP/2, once a TLS handshake has actually completed.
//
// The sibling script, capture-clienthello.mjs, needs no server: a ClientHello is the first thing on
// the wire. Everything ABOVE the handshake — the h2 preface, SETTINGS, the connection WINDOW_UPDATE,
// and the HPACK representation of the request headers — only exists after a handshake succeeds, and
// a real client will not complete one with a socket that hangs up.
//
// So this runs a real TLS server. Node's own, deliberately: what is being recorded is what the
// CLIENT sends, so the server's implementation is irrelevant as long as the handshake completes,
// and Node's OpenSSL stack completes handshakes with curl and Chromium that a minimal hand-written
// server would not (Chromium offers X25519MLKEM768 first, among other things).
//
//   node scripts/capture-h2-preface.mjs <out.json> -- curl --http2 -sk https://localhost:PORT/
//
// PORT is substituted into the command. The certificate is generated on the fly into a temp dir and
// never committed — the client is run with verification off, so the certificate is scaffolding.

import tls from 'node:tls';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';

const [outPath, sep, ...cmd] = process.argv.slice(2);
if (!outPath || sep !== '--' || cmd.length === 0) {
  console.error('usage: capture-h2-preface.mjs <out.json> -- <command with PORT>');
  process.exit(2);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tf-capture-'));
const keyPath = path.join(dir, 'k.pem');
const certPath = path.join(dir, 'c.pem');
execFileSync('openssl', [
  'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', keyPath, '-out', certPath, '-days', '1',
  '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
], { stdio: 'ignore' });

const PREFACE = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';

/** Frame walker. Own implementation on purpose — sharing src/ would make the capture circular. */
function parseFrames(buf) {
  const frames = [];
  let p = 0;
  while (p + 9 <= buf.length) {
    const len = (buf[p] << 16) | (buf[p + 1] << 8) | buf[p + 2];
    if (p + 9 + len > buf.length) break;
    frames.push({
      type: buf[p + 3],
      flags: buf[p + 4],
      streamId: ((buf[p + 5] & 0x7f) << 24) | (buf[p + 6] << 16) | (buf[p + 7] << 8) | buf[p + 8],
      payload: buf.subarray(p + 9, p + 9 + len),
    });
    p += 9 + len;
  }
  return frames;
}

/**
 * The field block inside a HEADERS frame, past whatever optional fields the flags put in front of
 * it (RFC 9113 s6.2): a pad-length byte under PADDED, and five bytes of stream dependency and
 * weight under PRIORITY. Handing the raw payload straight to an HPACK reader desynchronises it from
 * the very first byte and yields confident nonsense — index 0, indices in the thousands — instead
 * of an error. That is exactly what happened the first time this ran against Chromium, and it is
 * the reason this function exists rather than a subarray at the call site.
 */
function fieldBlock(frame) {
  let start = 0;
  let end = frame.payload.length;
  if (frame.flags & 0x8) {
    end -= frame.payload[0];
    start += 1;
  }
  if (frame.flags & 0x20) start += 5;
  return frame.payload.subarray(start, end);
}

/**
 * Classify every field in an HPACK block by its REPRESENTATION, which is the thing the profile
 * system calls `http2HpackIndexing` and the one h2 fingerprint field this repository never captured.
 * The prefix byte says it outright (RFC 7541 s6): the top bits select indexed / incremental /
 * without / never, so this needs no header table and no decoder — only the ability to walk lengths.
 */
function hpackRepresentations(block) {
  const out = [];
  let p = 0;
  const int = (prefixBits) => {
    const mask = (1 << prefixBits) - 1;
    let v = block[p] & mask;
    p += 1;
    if (v < mask) return v;
    let m = 0;
    for (;;) {
      const b = block[p++];
      v += (b & 0x7f) * 2 ** m;
      if ((b & 0x80) === 0) break;
      m += 7;
    }
    return v;
  };
  const str = () => {
    const huffman = (block[p] & 0x80) !== 0;
    const len = int(7);
    const raw = block.subarray(p, p + len);
    p += len;
    return { huffman, len, raw: huffman ? null : Buffer.from(raw).toString('latin1') };
  };
  while (p < block.length) {
    const b = block[p];
    if (b & 0x80) {
      out.push({ kind: 'indexed', index: int(7) });
    } else if (b & 0x40) {
      const index = int(6);
      const name = index === 0 ? str() : null;
      out.push({ kind: 'incremental', index, name: name?.raw ?? null, value: str().raw });
    } else if ((b & 0xf0) === 0x10) {
      const index = int(4);
      const name = index === 0 ? str() : null;
      out.push({ kind: 'never', index, name: name?.raw ?? null, value: str().raw });
    } else if ((b & 0xe0) === 0x20) {
      out.push({ kind: 'tableSizeUpdate', size: int(5) });
    } else {
      const index = int(4);
      const name = index === 0 ? str() : null;
      out.push({ kind: 'without', index, name: name?.raw ?? null, value: str().raw });
    }
  }
  return out;
}

const server = tls.createServer(
  {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    ALPNProtocols: ['h2', 'http/1.1'],
  },
  (sock) => {
    const chunks = [];
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      const buf = Buffer.concat(chunks);
      const sawPreface = buf.subarray(0, 24).toString('latin1') === PREFACE;
      const frames = sawPreface ? parseFrames(buf.subarray(24)) : [];
      const settings = frames.find((f) => f.type === 0x4);
      const windowUpdate = frames.find((f) => f.type === 0x8 && f.streamId === 0);
      const headers = frames.find((f) => f.type === 0x1);
      const settingsPairs = [];
      if (settings) {
        for (let i = 0; i + 6 <= settings.payload.length; i += 6) {
          settingsPairs.push([
            (settings.payload[i] << 8) | settings.payload[i + 1],
            settings.payload.readUInt32BE(i + 2),
          ]);
        }
      }
      fs.writeFileSync(
        outPath,
        JSON.stringify(
          {
            capturedBy: cmd.join(' '),
            alpn: sock.alpnProtocol,
            tlsVersion: sock.getProtocol(),
            cipher: sock.getCipher()?.name ?? null,
            sawPreface,
            firstFlightBase64: buf.toString('base64'),
            frameTypesInOrder: frames.map((f) => f.type),
            settings: settingsPairs,
            connectionWindowIncrement: windowUpdate ? windowUpdate.payload.readUInt32BE(0) & 0x7fffffff : null,
            headersFlags: headers ? headers.flags : null,
            headerBlockBase64: headers ? fieldBlock(headers).toString('base64') : null,
            hpack: headers ? hpackRepresentations(fieldBlock(headers)) : null,
          },
          null,
          2,
        ) + '\n',
      );
      console.log(`alpn=${sock.alpnProtocol} preface=${sawPreface} frames=${frames.length} -> ${outPath}`);
      try { sock.destroy(); } catch {}
      server.close();
      process.exit(0);
    };
    sock.on('data', (d) => {
      chunks.push(d);
      // The client's opening flight is preface + SETTINGS + WINDOW_UPDATE + HEADERS. Give it a beat
      // to arrive whole rather than guessing a byte count.
      clearTimeout(sock._t);
      sock._t = setTimeout(finish, 400);
    });
    sock.on('error', () => {});
  },
);

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  const argv = cmd.map((a) => a.replaceAll('PORT', String(port)));
  console.log(`listening on ${port}; running: ${argv.join(' ')}`);
  const child = spawn(argv[0], argv.slice(1), { stdio: 'inherit' });
  child.on('exit', () => setTimeout(() => {
    console.error('client exited without a capture');
    process.exit(1);
  }, 2000));
});
