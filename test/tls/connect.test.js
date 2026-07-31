// Version negotiation end to end: connectTls offering {1.3, 1.2} in ONE ClientHello against the
// scripted 1.3 server (_server.js) and the independent node:crypto 1.2 server (_server12.js),
// all over duplexPair().
//
// Three claims carry the security weight here, and each gets its own proof:
//
//  * It is one hello, not two attempts: the combined ClientHello is parsed off the wire byte by
//    byte and shown to carry supported_versions [1.3, 1.2], both cipher-suite sets, a key_share
//    AND the 1.2 compatibility extensions together.
//  * The RFC 8446 s4.1.3 downgrade sentinel — dead code while only one version could ever be
//    offered — is reachable and fatal now that landing on 1.2 is a real outcome.
//  * There is no fallback. A mid-flight failure (bad Finished, or the handshake_failure alert
//    that the historical insecure-fallback dance retried on) rejects; the socket factory is
//    shown to have run exactly once.

import test from 'node:test';
import assert from 'node:assert/strict';

import { connectTls } from '../../src/tls/connect.js';
import { openConnection } from '../../src/transport.js';
import {
  CIPHER,
  DOWNGRADE_SENTINEL_11,
  DOWNGRADE_SENTINEL_12,
  EXTENSION,
  GROUP,
  HELLO_RETRY_REQUEST_RANDOM,
  TLS12,
  TLS12_CIPHERS,
  TLS13,
  TLS13_CIPHERS,
} from '../../src/tls/constants.js';
import { Cursor } from '../../src/tls/wire.js';
import { decodeExtensionBlock } from '../../src/tls/extensions.js';
import { codes } from '../../src/errors.js';
import { concat, readU16, toHex, u16, utf8 } from '../../src/util/bytes.js';
import { collect, duplexPair, rejectsWithCode } from '../_harness.js';
import { startServer } from './_server.js';
import { serverIdentity, startServer12 } from './_server12.js';
import { testIdentity } from './_testca.js';

const HOST = 'server.test';
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);

/** verifyPeer stub for _testca identities: accept, return the real SPKI. */
const accept = (identity) => async () => ({ spki: { spkiDer: identity.spkiDer }, stub: true });
/** verifyPeer stub for _server12 identities, exactly as the real trust layer would resolve. */
const trust12 = (identity) => async () => ({ spki: { spkiDer: identity.spkiDer } });

// ------------------------------------------------------------------ plumbing

/** Byte tap on the client side of a duplex: pull-based pass-through that remembers everything. */
function tapTransport(inner) {
  const sent = [];
  const writer = inner.writable.getWriter();
  const reader = inner.readable.getReader();
  return {
    get sentBytes() {
      return concat(sent);
    },
    transport: {
      readable: new ReadableStream({
        async pull(c) {
          const { value, done } = await reader.read();
          if (done) return c.close();
          c.enqueue(value);
        },
        cancel: (r) => reader.cancel(r),
      }),
      writable: new WritableStream({
        write(chunk) {
          sent.push(chunk.slice());
          return writer.write(chunk);
        },
        close: () => writer.close(),
        abort: (r) => writer.abort(r),
      }),
    },
  };
}

/** Split a raw byte stream into TLS record headers. Trailing partial records are an error. */
function recordHeads(bytes) {
  const out = [];
  let o = 0;
  while (o + 5 <= bytes.byteLength) {
    const len = readU16(bytes, o + 3);
    out.push({ type: bytes[o], len });
    o += 5 + len;
  }
  assert.equal(o, bytes.byteLength, 'tap ended mid-record; snapshot taken at a non-quiescent point');
  return out;
}

/**
 * Decode the ClientHello out of the FIRST record of a captured client byte stream, using the
 * package's own strict cursor so a malformed hello fails the test rather than the assertion.
 */
function parseClientHelloRecord(bytes) {
  assert.equal(bytes[0], 22, 'the first record the client sends is a handshake record');
  const record = bytes.subarray(5, 5 + readU16(bytes, 3));
  assert.equal(record[0], 1, 'the record opens with a ClientHello');
  const declared = (record[1] << 16) | (record[2] << 8) | record[3];
  assert.equal(declared, record.byteLength - 4, 'the record holds exactly one handshake message');
  const c = new Cursor(record.subarray(4), 'ClientHello');
  const legacyVersion = c.u16('legacy_version');
  c.take(32, 'random');
  const sessionId = c.vector(1, 'legacy_session_id');
  const suites = c.sub(2, 'cipher_suites');
  const ciphers = [];
  while (!suites.done) ciphers.push(suites.u16('cipher_suite'));
  const compression = c.vector(1, 'legacy_compression_methods');
  const extensions = decodeExtensionBlock(c.vector(2, 'extensions'), 'ClientHello');
  c.end('ClientHello');
  return { legacyVersion, sessionId, ciphers, compression, extensions };
}

async function readN(reader, n) {
  const parts = [];
  let total = 0;
  while (total < n) {
    const { value, done } = await reader.read();
    if (done) throw new Error(`client stream ended after ${total} of ${n} bytes`);
    parts.push(value);
    total += value.byteLength;
  }
  return concat(parts, total);
}

async function serverReadN(record, n) {
  const parts = [];
  let total = 0;
  while (total < n) {
    const chunk = await record.readAppData();
    if (chunk === null) throw new Error(`server saw EOF after ${total} of ${n} bytes`);
    parts.push(chunk);
    total += chunk.byteLength;
  }
  return concat(parts, total);
}

/** One application round trip against the 1.3 test server, writes and reads overlapped. */
async function exchange13(tls, srv, clientPayload, serverPayload) {
  const writer = tls.writable.getWriter();
  const reader = tls.readable.getReader();
  const wp = writer.write(clientPayload);
  const atServer = await serverReadN(srv.record, clientPayload.byteLength);
  await wp;
  const sp = srv.record.writeAppData(serverPayload);
  const atClient = await readN(reader, serverPayload.byteLength);
  await sp;
  writer.releaseLock();
  reader.releaseLock();
  eq(atServer, clientPayload, 'client->server application bytes arrive intact');
  eq(atClient, serverPayload, 'server->client application bytes arrive intact');
}

/** Full happy path against the 1.2 echo server: handshake, one payload each way, clean close. */
async function roundTrip12(serverOpts = {}, clientOptions = {}, payload = utf8('negotiated down to 1.2')) {
  const { a, b } = duplexPair();
  const identity = serverOpts.identity ?? serverIdentity('ec-p256');
  const server = startServer12(b, serverOpts);
  const tls = await connectTls({
    transport: a,
    hostname: HOST,
    verifyPeer: trust12(identity),
    options: clientOptions,
  });
  const echoedP = collect(tls.readable);
  const w = tls.writable.getWriter();
  await w.write(payload);
  await w.close();
  const echoed = await echoedP;
  const summary = await server.done;
  return { tls, echoed, summary };
}

function assertClean12(summary) {
  assert.equal(summary.error, null, `server saw: ${JSON.stringify(summary.error)}`);
  assert.equal(summary.clientFinishedVerified, true, 'server verified the client Finished');
  assert.equal(summary.sawCloseNotify, true, 'shutdown ended with close_notify');
}

// ================================================================ both offered, server picks

test('offer both, a 1.3 server answers: full 1.3 handshake and data on the one connection', async () => {
  const identity = testIdentity('rsa-pss');
  const { a, b } = duplexPair();
  const tap = tapTransport(a);
  const srv = startServer(b, identity, { alpn: 'http/1.1' });
  const tls = await connectTls({ transport: tap.transport, hostname: HOST, verifyPeer: accept(identity) });
  const state = await srv.done;

  assert.equal(tls.info.version, TLS13);
  assert.equal(tls.info.cipherSuite, CIPHER.TLS_AES_128_GCM_SHA256);
  assert.equal(tls.info.alpnProtocol, 'http/1.1');
  assert.equal(tls.info.hostname, HOST);
  assert.deepEqual(state.clientHellos[0].versions, [TLS13, TLS12],
    'the server was answering a hello that offered both versions');
  assert.equal(state.finishedVerified, true, 'the server checked our Finished, not just read it');
  // Same wire shape as the 1.3-only driver: one plaintext hello, the compatibility CCS, one
  // encrypted flight. Nothing about offering 1.2 as well added a record or a round trip.
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 20, 23]);

  await exchange13(tls, srv, utf8('GET / HTTP/1.1\r\nHost: server.test\r\n\r\n'), utf8('1.3 answer'));
});

test('offer both, a 1.2 server answers: full 1.2 handshake and data on the one connection', async () => {
  const payload = utf8('ping through the negotiated 1.2 session');
  const { tls, echoed, summary } = await roundTrip12({ alpn: 'http/1.1' }, {}, payload);

  assert.equal(tls.info.version, TLS12);
  assert.equal(tls.info.cipherSuite, CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
  assert.equal(tls.info.extendedMasterSecret, true, 'EMS was negotiated and is reported');
  assert.equal(tls.info.alpnProtocol, 'http/1.1');
  eq(echoed, payload, 'echo made the round trip');
  eq(summary.appDataReceived, payload, 'the server decrypted what we sent');
  assertClean12(summary);

  // The server's own parse confirms it answered the COMBINED hello — 1.3 extensions and all —
  // and still reached a clean 1.2 session on this same connection.
  const ch = summary.clientHello;
  assert.equal(ch.hasSupportedVersions, true);
  assert.equal(ch.hasKeyShare, true);
  assert.equal(ch.hasPskModes, true);
  assert.equal(ch.hasEms, true);
  assert.equal(ch.hasRenegotiationInfo, true);
  assert.equal(ch.hasEcPointFormats, true);
  assert.deepEqual(ch.ciphers, [...TLS13_CIPHERS, ...TLS12_CIPHERS]);
});

test('the combined offer is ONE ClientHello: supported_versions [1.3, 1.2], both suite sets, ' +
     'a key share, and the 1.2 armour, all in the same bytes', async () => {
  const identity = testIdentity('rsa-pss');
  const { a, b } = duplexPair();
  const tap = tapTransport(a);
  const srv = startServer(b, identity, {});
  await connectTls({ transport: tap.transport, hostname: HOST, verifyPeer: accept(identity) });
  await srv.done;

  // Every plaintext handshake record the client ever sent is this one hello. A "try 1.3 then
  // try 1.2" implementation cannot pass this: it would either show a second ClientHello or a
  // second connection (see the socket-factory test below for the latter).
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 20, 23],
    'exactly one plaintext handshake record left the client');

  const ch = parseClientHelloRecord(tap.sentBytes);
  assert.equal(ch.legacyVersion, 0x0303, 'legacy_version stays 1.2-shaped; supported_versions decides');
  assert.deepEqual(ch.ciphers, [...TLS13_CIPHERS, ...TLS12_CIPHERS],
    'both cipher-suite sets, 1.3 first');
  assert.deepEqual([...ch.compression], [0]);
  assert.equal(ch.sessionId.byteLength, 32, 'throwaway session id for middlebox camouflage');

  eq(ch.extensions.get(EXTENSION.supported_versions), Uint8Array.of(4, 0x03, 0x04, 0x03, 0x03),
    'supported_versions lists 0x0304 then 0x0303');
  const kc = new Cursor(ch.extensions.get(EXTENSION.key_share), 'key_share');
  const shares = kc.sub(2, 'client_shares');
  assert.equal(shares.u16('group'), GROUP.x25519, 'a real 1.3 key share rides the same hello');
  assert.equal(shares.vector(2, 'key_exchange').byteLength, 32, 'a full x25519 public key');
  assert.ok(shares.done, 'one share by default');
  eq(ch.extensions.get(EXTENSION.extended_master_secret), new Uint8Array(0),
    'extended_master_secret offered for the 1.2 outcome');
  eq(ch.extensions.get(EXTENSION.ec_point_formats), Uint8Array.of(1, 0),
    'ec_point_formats: uncompressed only');
  eq(ch.extensions.get(EXTENSION.renegotiation_info), Uint8Array.of(0),
    'renegotiation_info: empty, initial handshake');
  eq(ch.extensions.get(EXTENSION.psk_key_exchange_modes), Uint8Array.of(1, 1), 'psk_dhe_ke');
  for (const type of [EXTENSION.server_name, EXTENSION.supported_groups, EXTENSION.signature_algorithms]) {
    assert.ok(ch.extensions.has(type), `extension 0x${type.toString(16)} present`);
  }
});

// ================================================================ downgrade protection, now live

test('a 1.2 server planting the RFC 8446 downgrade sentinel in ServerHello.random is fatal', async () => {
  // This is the protection the combined offer exists to enable: only a client that offered 1.3
  // and landed on 1.2 can see the sentinel, and until now no reachable configuration could.
  for (const [name, sentinel] of [
    ['DOWNGRD\\x01 (1.2 sentinel)', DOWNGRADE_SENTINEL_12],
    ['DOWNGRD\\x00 (1.1 sentinel)', DOWNGRADE_SENTINEL_11],
  ]) {
    const { a, b } = duplexPair();
    const identity = serverIdentity('ec-p256');
    const serverRandom = Uint8Array.from({ length: 32 }, (_, i) => (i * 7) & 0xff);
    serverRandom.set(sentinel, 24);
    const server = startServer12(b, { serverRandom });
    const err = await rejectsWithCode(
      () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
      codes.TLS_VERSION_UNSUPPORTED, /downgrade sentinel/,
    );
    assert.equal(err.detail.sentinel, true, name);
    assert.match(err.message, /tampered ClientHello/, `${name}: the message explains the attack`);
    const summary = await server.done;
    assert.deepEqual(summary.clientMessageTypes, [1],
      `${name}: nothing but the ClientHello ever left the client`);
    assert.equal(summary.clientFinishedVerified, false, name);
  }
});

test('a server selecting TLS 1.1 is refused, naming the version and why it is absent', async () => {
  const { a, b } = duplexPair();
  const identity = serverIdentity('ec-p256');
  const server = startServer12(b, { claimVersion: 0x0302 });
  const err = await rejectsWithCode(
    () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
    codes.TLS_VERSION_UNSUPPORTED, /0x0302 \(TLS 1\.1\)/,
  );
  assert.match(err.message, /not offered/);
  assert.match(err.message, /TLS 1\.0 and 1\.1 are not implemented/);
  await server.done;
});

test('a ServerHello using supported_versions to select anything but 1.3 is refused', async () => {
  // RFC 8446 s4.2.1: in a ServerHello that extension may only ever say 1.3. A 1.2 selection
  // must travel as a bare legacy_version so the sentinel check still has something to bite on.
  const { a, b } = duplexPair();
  const identity = serverIdentity('ec-p256');
  const server = startServer12(b, { extraExtensions: [[43, u16(0x0303)]] });
  await rejectsWithCode(
    () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
    codes.TLS_VERSION_UNSUPPORTED, /may only select TLS 1\.3/,
  );
  await server.done;
});

// ================================================================ suite family × version

test('cipher-suite families cannot cross versions, in either direction', async () => {
  // Both suites ARE in the combined offer, so the "not offered" guard cannot catch these; the
  // family-vs-version check is the only thing standing and must fire on its own.
  {
    const { a, b } = duplexPair();
    const identity = serverIdentity('ec-p256');
    const server = startServer12(b, { selectCipher: 0x1301 }); // TLS_AES_128_GCM_SHA256
    await rejectsWithCode(
      () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
      codes.TLS_CIPHER_UNSUPPORTED, /TLS 1\.3 cipher suite 0x1301 under TLS 1\.2/,
    );
    await server.done;
  }
  {
    const identity = testIdentity('rsa-pss');
    const { a, b } = duplexPair();
    // Tap on purpose: this server barrels ahead writing its flight while the client is busy
    // refusing the suite, and the tap's one-chunk pull buffer stands in for the network buffer
    // a real transport has (duplexPair alone has none — same discipline as failPair elsewhere).
    const tap = tapTransport(a);
    startServer(b, identity, { wireCipher: 0xc02f }); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    await rejectsWithCode(
      () => connectTls({ transport: tap.transport, hostname: HOST, verifyPeer: accept(identity) }),
      codes.TLS_CIPHER_UNSUPPORTED, /TLS 1\.2 cipher suite 0xc02f under TLS 1\.3/,
    );
  }
  {
    // A 1.2 server dressing itself up as 1.3 via supported_versions gets judged BY 1.3 rules
    // and dies on its own 1.2 suite — claiming the version does not buy the ciphers.
    const { a, b } = duplexPair();
    const identity = serverIdentity('ec-p256');
    const server = startServer12(b, { extraExtensions: [[43, u16(0x0304)]] });
    await rejectsWithCode(
      () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
      codes.TLS_CIPHER_UNSUPPORTED, /TLS 1\.2 cipher suite 0xc02b under TLS 1\.3/,
    );
    await server.done;
  }
});

test('a 1.2 ServerHello echoing a 1.3-only extension is refused even though it was offered', async () => {
  // With the combined offer, key_share WAS offered, so rejectUnofferedExtensions can no longer
  // see anything wrong — this is the check the combined offer newly requires.
  const { a, b } = duplexPair();
  const identity = serverIdentity('ec-p256');
  const server = startServer12(b, { extraExtensions: [[51, u16(GROUP.x25519)]] });
  const err = await rejectsWithCode(
    () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
    codes.TLS_HANDSHAKE, /TLS 1\.3-only extension 0x0033/,
  );
  assert.equal(err.detail.extension, EXTENSION.key_share);
  await server.done;
});

// ================================================================ HelloRetryRequest

test('HelloRetryRequest still works when both versions were offered, and ClientHello2 keeps ' +
     'the full offer', async () => {
  const identity = testIdentity('rsa-pss');
  const cookie = Uint8Array.from({ length: 48 }, (_, i) => i ^ 0x5a);
  const { a, b } = duplexPair();
  const srv = startServer(b, identity, { hrr: { group: GROUP.secp256r1, cookie } });
  const tls = await connectTls({ transport: a, hostname: HOST, verifyPeer: accept(identity) });
  const state = await srv.done;

  assert.equal(tls.info.version, TLS13);
  assert.equal(tls.info.group, GROUP.secp256r1);
  assert.equal(state.finishedVerified, true);

  const [ch1, ch2] = state.clientHellos;
  assert.deepEqual(ch1.versions, [TLS13, TLS12]);
  assert.deepEqual(ch2.versions, [TLS13, TLS12],
    'RFC 8446 s4.1.2: ClientHello2 changes only what the HRR demanded — the offer stays whole');
  eq(ch2.random, ch1.random, 'ClientHello2 reuses the random');
  assert.deepEqual(ch2.keyShares.map((k) => k.group), [GROUP.secp256r1]);
  for (const type of [
    EXTENSION.extended_master_secret, EXTENSION.ec_point_formats, EXTENSION.renegotiation_info,
  ]) {
    assert.ok(ch2.extensions.has(type),
      `ClientHello2 still carries the 1.2 compatibility extension 0x${type.toString(16)}`);
  }
  eq(ch2.cookie, state.hrrCookieSent, 'the cookie is echoed verbatim');

  await exchange13(tls, srv, utf8('post-HRR ping'), utf8('post-HRR pong'));
});

test('a 1.2 server faking the HelloRetryRequest random gets the 1.3 rules, and fails closed', async () => {
  // HRR is 1.3 by definition, so the dispatch goes to the 1.3 driver no matter what the sender
  // intended — and an "HRR" from a server that does not actually speak 1.3 cannot survive the
  // 1.3 rules, whichever it trips first.
  {
    // With its usual 1.2 suite, the fake dies on the family check: an HRR may only name 1.3 suites.
    const { a, b } = duplexPair();
    const identity = serverIdentity('ec-p256');
    const server = startServer12(b, { serverRandom: HELLO_RETRY_REQUEST_RANDOM });
    await rejectsWithCode(
      () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
      codes.TLS_CIPHER_UNSUPPORTED, /TLS 1\.2 cipher suite 0xc02b under TLS 1\.3/,
    );
    await server.done;
  }
  {
    // Even naming a 1.3 suite only gets it as far as the missing key_share an HRR must carry.
    const { a, b } = duplexPair();
    const identity = serverIdentity('ec-p256');
    const server = startServer12(b, {
      serverRandom: HELLO_RETRY_REQUEST_RANDOM, selectCipher: 0x1301,
    });
    await rejectsWithCode(
      () => connectTls({ transport: a, hostname: HOST, verifyPeer: trust12(identity) }),
      codes.TLS_HANDSHAKE, /HelloRetryRequest has no key_share/,
    );
    await server.done;
  }
});

// ================================================================ single-version offers

test('versions [TLS13] offers exactly what the 1.3 driver always offered', async () => {
  const identity = testIdentity('rsa-pss');
  const { a, b } = duplexPair();
  const srv = startServer(b, identity, {});
  const tls = await connectTls({
    transport: a, hostname: HOST, verifyPeer: accept(identity), options: { versions: [TLS13] },
  });
  const state = await srv.done;
  assert.equal(tls.info.version, TLS13);
  const ch = state.clientHellos[0];
  assert.deepEqual(ch.versions, [TLS13], 'supported_versions lists 1.3 alone');
  assert.deepEqual(ch.cipherSuites, TLS13_CIPHERS, 'no 1.2 suites in a 1.3-only offer');
  for (const type of [
    EXTENSION.extended_master_secret, EXTENSION.ec_point_formats, EXTENSION.renegotiation_info,
  ]) {
    assert.ok(!ch.extensions.has(type), 'no 1.2 compatibility extension rides a 1.3-only offer');
  }
  await exchange13(tls, srv, utf8('1.3-only ping'), utf8('1.3-only pong'));
});

test('versions [TLS12] offers exactly what the 1.2 driver always offered', async () => {
  const { tls, echoed, summary } = await roundTrip12({}, { versions: [TLS12] });
  assert.equal(tls.info.version, TLS12);
  eq(echoed, utf8('negotiated down to 1.2'));
  assertClean12(summary);
  const ch = summary.clientHello;
  assert.equal(ch.hasSupportedVersions, false, 'supported_versions would make this a 1.3 hello');
  assert.equal(ch.hasKeyShare, false);
  assert.equal(ch.hasPskModes, false);
  assert.equal(ch.hasEms, true);
  assert.deepEqual(ch.ciphers, TLS12_CIPHERS, 'exactly the 1.2 AEAD suites');
});

test('versions [TLS12] keeps the 1.2 driver\'s HelloRetryRequest-random refusal', async () => {
  const { a, b } = duplexPair();
  const identity = serverIdentity('ec-p256');
  const server = startServer12(b, { serverRandom: HELLO_RETRY_REQUEST_RANDOM });
  await rejectsWithCode(
    () => connectTls({
      transport: a, hostname: HOST, verifyPeer: trust12(identity), options: { versions: [TLS12] },
    }),
    codes.TLS_HANDSHAKE, /HelloRetryRequest sentinel/,
  );
  await server.done;
});

test('a legacy 1.2 server declining EMS and renegotiation_info still completes, visibly', async () => {
  const { tls, echoed, summary } = await roundTrip12({ ems: false, renegotiationInfo: false });
  assert.equal(tls.info.version, TLS12);
  assert.equal(tls.info.extendedMasterSecret, false, 'the EMS downgrade is reported, not hidden');
  eq(echoed, utf8('negotiated down to 1.2'));
  assertClean12(summary);
});

// ================================================================ configuration

test('the offer list is validated before any byte is written, and canonicalised after', async () => {
  const dead = () => duplexPair().a;
  const vp = async () => ({});
  await rejectsWithCode(
    () => connectTls({ transport: dead(), hostname: HOST, verifyPeer: vp, options: { versions: [] } }),
    codes.CONFIG_INVALID, /non-empty/,
  );
  await rejectsWithCode(
    () => connectTls({ transport: dead(), hostname: HOST, verifyPeer: vp, options: { versions: 'both' } }),
    codes.CONFIG_INVALID,
  );
  const err = await rejectsWithCode(
    () => connectTls({
      transport: dead(), hostname: HOST, verifyPeer: vp, options: { versions: [0x0302] },
    }),
    codes.TLS_VERSION_UNSUPPORTED, /cannot offer 0x0302 \(TLS 1\.1\)/,
  );
  assert.equal(err.detail.version, 0x0302);

  // Order and duplicates normalise: the offer is a set, and preference among what we are
  // willing to speak is fixed at newest-first.
  const identity = testIdentity('rsa-pss');
  const { a, b } = duplexPair();
  const srv = startServer(b, identity, {});
  await connectTls({
    transport: a, hostname: HOST, verifyPeer: accept(identity),
    options: { versions: [TLS12, TLS13, TLS12] },
  });
  const state = await srv.done;
  assert.deepEqual(state.clientHellos[0].versions, [TLS13, TLS12], 'newest first, deduplicated');
});

test('connectTls without verifyPeer refuses to start: there is no unverified mode', async () => {
  await rejectsWithCode(
    () => connectTls({ transport: duplexPair().a, hostname: HOST }),
    codes.CONFIG_INVALID, /verifyPeer/,
  );
});

// ================================================================ no fallback, ever

test('no fallback: a mid-flight 1.3 failure rejects; the socket factory ran exactly once', async () => {
  // The insecure-fallback dance ("1.3 failed, reconnect and try 1.2") is what lets an attacker
  // who can inject a reset or an alert choose the client's version. Prove the absence of the
  // whole mechanism at the layer that owns sockets: openConnection is handed a counting factory
  // and a server scripted to fail after the ClientHello, in the two shapes the historical
  // fallback logic retried on.
  const identity = testIdentity('ecdsa-p256');
  const cases = [
    ['corrupt server Finished', { corruptFinished: true },
      codes.TLS_HANDSHAKE, /verify_data does not match/],
    ['fatal handshake_failure alert', { alertAfter: 'encryptedExtensions', alertDesc: 40 },
      codes.TLS_ALERT, /handshake_failure/],
  ];
  for (const [name, serverOpts, code, msgMatch] of cases) {
    let dials = 0;
    const servers = [];
    const connect = () => {
      dials += 1;
      const { a, b } = duplexPair();
      servers.push(startServer(b, identity, serverOpts));
      return {
        readable: a.readable, writable: a.writable,
        opened: Promise.resolve({}), close: async () => {},
      };
    };
    await rejectsWithCode(
      () => openConnection({
        url: 'https://server.test/',
        connect,
        // Trust policy is irrelevant to fallback behaviour; 'none' keeps the failure under test
        // (the TLS one) the only failure in play.
        trust: { mode: 'none', insecureAcceptAnyCertificate: true },
      }),
      code, msgMatch,
    );
    assert.equal(dials, 1, `${name}: the socket factory ran once — a failure is a failure`);
    assert.equal(servers[0].state.clientHellos.length, 1,
      `${name}: and the one socket saw exactly one ClientHello`);
  }
});
