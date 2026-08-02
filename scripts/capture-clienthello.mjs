// Record the raw ClientHello a REAL client puts on the wire.
//
// A ClientHello is the first thing sent on a TCP connection, before the server says anything, so
// capturing one needs no TLS server at all — just a socket that accepts, reads the first record,
// writes it down and hangs up. The client will fail its handshake; that is fine and expected, the
// bytes we want are already past.
//
// This exists because every "captured off the wire" claim in this repository had no artifact behind
// it. The fingerprint tests asserted our builder against constants in `src/`, which catches drift
// and cannot catch the constants being wrong about the client they name. A recorded capture is an
// INDEPENDENT witness: it comes from a program we did not write.
//
//   node scripts/capture-clienthello.mjs <out.json> -- curl -sk https://localhost:PORT/
//
// The port is substituted into the command wherever the literal PORT appears.

import net from 'node:net';
import fs from 'node:fs';
import { spawn } from 'node:child_process';

const [outPath, sep, ...cmd] = process.argv.slice(2);
if (!outPath || sep !== '--' || cmd.length === 0) {
  console.error('usage: capture-clienthello.mjs <out.json> -- <command with PORT>');
  process.exit(2);
}

/** Split a ClientHello into the parts a fingerprint is read from. Deliberately a SEPARATE parser
 *  from the package's own: reusing `src/` here would reintroduce the circularity this whole file
 *  exists to break. */
function parseClientHello(rec) {
  if (rec[0] !== 0x16) throw new Error(`not a handshake record: type ${rec[0]}`);
  const body = rec.subarray(5);
  if (body[0] !== 0x01) throw new Error(`not a ClientHello: handshake type ${body[0]}`);
  let p = 4; // handshake header
  const legacyVersion = (body[p] << 8) | body[p + 1];
  p += 2;
  const random = [...body.subarray(p, p + 32)];
  p += 32;
  const sessionIdLen = body[p];
  p += 1 + sessionIdLen;
  const csLen = (body[p] << 8) | body[p + 1];
  p += 2;
  const ciphers = [];
  for (let i = 0; i < csLen; i += 2) ciphers.push((body[p + i] << 8) | body[p + i + 1]);
  p += csLen;
  const compLen = body[p];
  p += 1 + compLen;
  const extTotal = (body[p] << 8) | body[p + 1];
  p += 2;
  const end = p + extTotal;
  const extensions = [];
  while (p < end) {
    const type = (body[p] << 8) | body[p + 1];
    const len = (body[p + 2] << 8) | body[p + 3];
    extensions.push({ type, len, body: [...body.subarray(p + 4, p + 4 + len)] });
    p += 4 + len;
  }
  return { legacyVersion, sessionIdLen, ciphers, extensionOrder: extensions.map((e) => e.type), extensions, random };
}

const server = net.createServer((sock) => {
  const chunks = [];
  let total = 0;
  sock.on('data', (d) => {
    chunks.push(d);
    total += d.length;
    const buf = Buffer.concat(chunks);
    if (buf.length < 5) return;
    const recLen = (buf[3] << 8) | buf[4];
    if (buf.length < 5 + recLen) return;
    const rec = buf.subarray(0, 5 + recLen);
    let parsed = null;
    let error = null;
    try {
      parsed = parseClientHello(rec);
    } catch (e) {
      error = String(e.message);
    }
    fs.writeFileSync(
      outPath,
      JSON.stringify({ capturedBy: cmd.join(' '), bytes: rec.toString('base64'), parsed, error }, null, 2) + '\n',
    );
    console.log(`captured ${rec.length} bytes -> ${outPath}`);
    sock.destroy();
    server.close();
    process.exit(0);
  });
  sock.on('error', () => {});
});

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  const argv = cmd.map((a) => a.replaceAll('PORT', String(port)));
  console.log(`listening on ${port}; running: ${argv.join(' ')}`);
  const child = spawn(argv[0], argv.slice(1), { stdio: 'inherit' });
  child.on('exit', () => setTimeout(() => {
    console.error('client exited without a capture');
    process.exit(1);
  }, 500));
});
