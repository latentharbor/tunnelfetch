// Regenerate src/warmup-fixture.js: a recorded, fully deterministic TLS 1.3 handshake plus one
// HTTP/1.1 exchange, captured by running the package's OWN client (connectTls with injected
// randomness) against the offline suite's honest test server over an in-memory pipe.
//
// warmup() replays the server->client bytes through the real parsers, key schedule, AEAD and
// trust layer. Determinism rests on: fixed client random/session id, a fixed client X25519 key
// pair (private half baked into the fixture — see the security note in warmup-fixture.js), and
// the recorded server flight. If any ClientHello default changes (ciphers, groups, extensions),
// the recording no longer matches and test/warmup.test.js fails with instructions to rerun this.
//
// node:crypto is fine HERE (a dev-time script); src/ itself stays WebCrypto-only.

import { generateKeyPairSync, sign as nodeSign, constants as nodeConstants, webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { connectTls } = await import(join(ROOT, 'src/tls/connect.js'));
const { verifyChain } = await import(join(ROOT, 'src/trust/index.js'));
const { serializeRequestHead } = await import(join(ROOT, 'src/http1/request.js'));
const { SIG_SCHEME } = await import(join(ROOT, 'src/tls/constants.js'));
const { startServer } = await import(join(ROOT, 'test/tls/_server.js'));
const { duplexPair } = await import(join(ROOT, 'test/_harness.js'));

const HOSTNAME = 'warmup.invalid'; // RFC 2606 reserved; can never be a real site
const FIXED_NOW = Date.UTC(2030, 0, 1); // inside the chain's fixed 2025..2035 validity

// ---------------------------------------------------------------- tiny DER writer (as _testca)
const concatU8 = (parts) => {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.byteLength; }
  return out;
};
function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}
const tlv = (tag, body) => concatU8([Uint8Array.of(tag), derLen(body.byteLength), body]);
const seq = (...parts) => tlv(0x30, concatU8(parts));
const set = (...parts) => tlv(0x31, concatU8(parts));
const int = (n) => tlv(0x02, Uint8Array.of(n));
const bool = (v) => tlv(0x01, Uint8Array.of(v ? 0xff : 0x00));
const octetstr = (b) => tlv(0x04, b);
const nul = () => tlv(0x05, new Uint8Array(0));
const utf8str = (s) => tlv(0x0c, new TextEncoder().encode(s));
const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const utctime = (s) => tlv(0x17, ascii(s));
const ctx = (n, body) => tlv(0xa0 | n, body);
const ctxPrim = (n, body) => tlv(0x80 | n, body);
const bitstr = (b) => tlv(0x03, concatU8([Uint8Array.of(0), b]));
const rawBitstr = (unused, bytes) => tlv(0x03, concatU8([Uint8Array.of(unused), bytes]));
function oid(dotted) {
  const arcs = dotted.split('.').map(Number);
  const body = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const vlq = [arc & 0x7f];
    let v = Math.floor(arc / 128);
    while (v > 0) { vlq.unshift(0x80 | (v & 0x7f)); v = Math.floor(v / 128); }
    body.push(...vlq);
  }
  return tlv(0x06, Uint8Array.from(body));
}
const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), nul());
const cn = (name) => seq(set(seq(oid('2.5.4.3'), utf8str(name))));
const ext = (o, critical, valueDer) =>
  seq(oid(o), ...(critical ? [bool(true)] : []), octetstr(valueDer));
function makeCert({ serial, subjectName, issuerName, spkiDer, issuerKey, extensions }) {
  const tbs = seq(
    ctx(0, int(2)), int(serial), SHA256_RSA, issuerName,
    seq(utctime('250101000000Z'), utctime('350101000000Z')),
    subjectName, spkiDer, ctx(3, seq(...extensions)),
  );
  return seq(tbs, SHA256_RSA, bitstr(new Uint8Array(nodeSign('sha256', tbs, issuerKey))));
}

// ---------------------------------------------------------------- chain + server identity
const rootKp = generateKeyPairSync('rsa', { modulusLength: 2048 });
const intKp = generateKeyPairSync('rsa', { modulusLength: 2048 });
const leafKp = generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = (kp) => new Uint8Array(kp.publicKey.export({ type: 'spki', format: 'der' }));
const caExts = [
  ext('2.5.29.19', true, seq(bool(true))),
  ext('2.5.29.15', true, rawBitstr(2, Uint8Array.of(0x04))),
];
const rootName = cn('Warmup Fixture Root');
const intName = cn('Warmup Fixture Intermediate');
const rootDer = makeCert({ serial: 1, subjectName: rootName, issuerName: rootName,
  spkiDer: spki(rootKp), issuerKey: rootKp.privateKey, extensions: caExts });
const intDer = makeCert({ serial: 2, subjectName: intName, issuerName: rootName,
  spkiDer: spki(intKp), issuerKey: rootKp.privateKey, extensions: caExts });
const leafDer = makeCert({
  serial: 3, subjectName: cn(HOSTNAME), issuerName: intName,
  spkiDer: spki(leafKp), issuerKey: intKp.privateKey,
  extensions: [
    ext('2.5.29.19', true, seq()),
    ext('2.5.29.15', true, rawBitstr(7, Uint8Array.of(0x80))),
    ext('2.5.29.37', false, seq(oid('1.3.6.1.5.5.7.3.1'))),
    ext('2.5.29.17', false, seq(ctxPrim(2, ascii(HOSTNAME)))),
  ],
});
const identity = {
  certDer: leafDer,
  scheme: SIG_SCHEME.rsa_pss_rsae_sha256,
  sign: (content) => new Uint8Array(nodeSign('sha256', content, {
    key: leafKp.privateKey, padding: nodeConstants.RSA_PKCS1_PSS_PADDING, saltLength: 32,
  })),
};

// ---------------------------------------------------------------- fixed client key + randoms
const subtle = webcrypto.subtle;
const clientPair = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
const clientPrivPkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', clientPair.privateKey));
const clientPubRaw = new Uint8Array(await subtle.exportKey('raw', clientPair.publicKey));
const clientRandom = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
const sessionId = new Uint8Array(32).map((_, i) => (i * 11 + 5) & 0xff);

// ---------------------------------------------------------------- record one exchange
const { a, b } = duplexPair();
const s2c = [];
const c2s = [];
const aw = a.writable.getWriter();
const tapped = {
  readable: a.readable.pipeThrough(new TransformStream({
    transform(chunk, ctrl) { s2c.push(chunk.slice()); ctrl.enqueue(chunk); },
  })),
  writable: new WritableStream({
    write(chunk) { c2s.push(chunk.slice()); return aw.write(chunk); },
    close() { return aw.close(); },
    abort(r) { return aw.abort(r); },
  }),
};

const srv = startServer(b, identity, { alpn: 'http/1.1', extraChain: [intDer] });

const session = await connectTls({
  transport: tapped,
  hostname: HOSTNAME,
  verifyPeer: (chain, host) => verifyChain({
    chain, hostname: host, trust: { mode: 'anchors', anchors: [rootDer] }, now: FIXED_NOW,
  }),
  options: { clientRandom, legacySessionId: sessionId },
  deps: {
    generateKeyPair: async () => clientPair,
  },
});
await srv.done;

const BODY = '<!doctype html><html><head><title>warmup</title></head><body>' +
  'recorded fixture body: parsed, framed and decoded during warmup, never sent anywhere.' +
  '</body></html>';
const responseBytes = new TextEncoder().encode(
  `HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: ${BODY.length}\r\n` +
  `connection: keep-alive\r\n\r\n${BODY}`);

const reqBytes = serializeRequestHead({
  method: 'GET', target: '/',
  headers: [['host', HOSTNAME], ['accept', '*/*'], ['accept-encoding', 'gzip, deflate'],
    ['connection', 'keep-alive']],
});
const w = session.writable.getWriter();
await Promise.all([
  w.write(reqBytes),
  (async () => {
    const got = await srv.record.readAppData();
    if (!got || got.byteLength !== reqBytes.byteLength) {
      throw new Error(`server saw ${got?.byteLength} request bytes, expected ${reqBytes.byteLength}`);
    }
    await srv.record.writeAppData(responseBytes);
    await srv.record.close();
  })(),
]);
const rd = session.readable.getReader();
const gotBody = [];
for (;;) {
  const { value, done } = await rd.read();
  if (done) break;
  gotBody.push(value);
}
const echoed = concatU8(gotBody);
if (echoed.byteLength !== responseBytes.byteLength) {
  throw new Error(`client read ${echoed.byteLength} response bytes, expected ${responseBytes.byteLength}`);
}
await session.close();

// The client's very first write is the plaintext ClientHello record: 5-byte header + message.
const firstWrite = c2s[0];
const clientHelloMsg = firstWrite.subarray(5);
const serverBytes = concatU8(s2c);

// ---------------------------------------------------------------- emit
const b64 = (u) => Buffer.from(u).toString('base64');
const wrap = (s) => s.match(/.{1,100}/g).join('" +\n  "');
const out = `// GENERATED by scripts/gen-warmup-fixture.mjs — do not edit by hand; rerun the script.
//
// A recorded TLS 1.3 handshake + one HTTP/1.1 exchange between this package's own client and the
// offline suite's honest test server, over an in-memory pipe. warmup() replays the server's bytes
// through the real parsers, key schedule, AEAD, trust layer and HTTP head parser.
//
// SECURITY NOTE — on the private key below: CLIENT_PRIV_PKCS8 is the fixture client's ephemeral
// X25519 key, and the chain here is synthetic with a reserved-name subject (warmup.invalid,
// RFC 2606). Nothing trusts any of this material: the chain anchors only to its own baked root,
// which is passed explicitly as an anchors-mode trust config inside warmup() and never enters the
// bundled store; the "traffic" it decrypts is this fixture itself. Possession of the key or chain
// grants exactly nothing. It exists so the replay is deterministic without calling
// getRandomValues/generateKey, which the target runtime forbids at module (global) scope.

const B = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const WARMUP_HOSTNAME = ${JSON.stringify(HOSTNAME)};
export const WARMUP_NOW = ${FIXED_NOW}; // fixed epoch ms inside the chain's validity window

const CLIENT_PRIV =
  "${wrap(b64(clientPrivPkcs8))}";
const CLIENT_PUB =
  "${wrap(b64(clientPubRaw))}";
const CLIENT_RANDOM =
  "${wrap(b64(clientRandom))}";
const SESSION_ID =
  "${wrap(b64(sessionId))}";
const CLIENT_HELLO =
  "${wrap(b64(clientHelloMsg))}";
const SERVER_BYTES =
  "${wrap(b64(serverBytes))}";
const ROOT_DER =
  "${wrap(b64(rootDer))}";

export const WARMUP_FIXTURE = {
  clientPrivPkcs8: () => B(CLIENT_PRIV),
  clientPubRaw: () => B(CLIENT_PUB),
  clientRandom: () => B(CLIENT_RANDOM),
  legacySessionId: () => B(SESSION_ID),
  clientHello: () => B(CLIENT_HELLO),
  serverBytes: () => B(SERVER_BYTES),
  rootDer: () => B(ROOT_DER),
};
`;
writeFileSync(join(ROOT, 'src/warmup-fixture.js'), out);
console.log('wrote src/warmup-fixture.js', {
  clientHello: clientHelloMsg.length, serverBytes: serverBytes.length, root: rootDer.length,
});
