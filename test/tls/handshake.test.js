// End-to-end TLS 1.3 handshakes over a loopback pipe: the client under test against the
// scripted server in _server.js, with certificates minted by _testca.js. Hermetic — the only
// "network" is duplexPair() — and deterministic where it matters.
//
// Two ideas do most of the policing here:
//
//  * The server VERIFIES the client Finished against its own independently-built transcript, so
//    the positive tests prove interop, not self-consistency. A client whose transcript is off by
//    one message, or whose keys go on one flight early, fails on the server side even when its
//    own bookkeeping is internally coherent.
//  * A byte tap sits under the client, so tests can assert what actually crossed the wire —
//    most importantly that on a failed chain validation the client never emitted one encrypted
//    record: no Finished, no application data, nothing an attacker could use.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';

import { handshakeTls13 } from '../../src/tls/handshake.js';
import { connectTls } from '../../src/tls/connect.js';
import { generateKeyShare, negotiateVersion } from '../../src/tls/handshake-messages.js';
import {
  CIPHER, DOWNGRADE_SENTINEL_12, EXTENSION, GROUP, TLS12, TLS13,
} from '../../src/tls/constants.js';
import { CertificateError, codes } from '../../src/errors.js';
import { concat, readU16, toHex, utf8 } from '../../src/util/bytes.js';
import {
  duplexPair, readableFrom, recordingWritable, rejectsWithCode, rng,
} from '../_harness.js';
import { rawExtension, startServer } from './_server.js';
import { makeIdentity, testIdentity } from './_testca.js';
import { fakeMlKem768 } from './_mlkem.js';
import { nodeChacha20 } from './_chacha.js';

const HOST = 'server.test';
const AES128 = CIPHER.TLS_AES_128_GCM_SHA256;
const AES256 = CIPHER.TLS_AES_256_GCM_SHA384;
const pattern = (n) => Uint8Array.from({ length: n }, (_, i) => i & 0xff);
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);

// ------------------------------------------------------------------ plumbing

/**
 * Interpose a byte tap on one side of a duplex. Pull-based pass-through, so it changes no
 * backpressure behaviour; it only remembers what crossed, for wire-shape assertions.
 */
function tapTransport(inner) {
  const sent = [];
  const received = [];
  const writer = inner.writable.getWriter();
  const reader = inner.readable.getReader();
  return {
    sent,
    received,
    get sentBytes() {
      return concat(sent);
    },
    get receivedBytes() {
      return concat(received);
    },
    transport: {
      readable: new ReadableStream({
        async pull(c) {
          const { value, done } = await reader.read();
          if (done) return c.close();
          received.push(value.slice());
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

/** verifyPeer stub: records calls, accepts, returns the identity's real SPKI. */
function acceptStub(identity) {
  const verifyPeer = async (chain, hostname) => {
    verifyPeer.calls.push({ hostname, chain: chain.map((c) => c.slice()) });
    return { spki: { spkiDer: identity.spkiDer }, stub: true };
  };
  verifyPeer.calls = [];
  return verifyPeer;
}

/** Deterministic byte source for deps.randomBytes: same seed, same stream, every run. */
function seededBytes(seed) {
  const next = rng(seed);
  return (n) => Uint8Array.from({ length: n }, () => Math.floor(next() * 256));
}

/** Loopback handshake that must SUCCEED. Resolves client result and settled server state. */
async function connectPair({ identity, clientOptions, deps, verifyPeer, server = {} }) {
  const { a, b } = duplexPair();
  const tap = tapTransport(a);
  const srv = startServer(b, identity, server);
  const vp = verifyPeer ?? acceptStub(identity);
  const tls = await handshakeTls13({
    transport: tap.transport, hostname: HOST, verifyPeer: vp, options: clientOptions, deps,
  });
  const state = await srv.done;
  return { tls, srv, state, tap, verifyPeer: vp };
}

/** Loopback handshake that must FAIL on the client with `code` (+ message when given). */
async function failPair({ identity, clientOptions, deps, verifyPeer, server = {} }, code, msgMatch) {
  const { a, b } = duplexPair();
  const tap = tapTransport(a);
  const srv = startServer(b, identity, server);
  const err = await rejectsWithCode(
    () => handshakeTls13({
      transport: tap.transport, hostname: HOST,
      verifyPeer: verifyPeer ?? acceptStub(identity), options: clientOptions, deps,
    }),
    code, msgMatch,
  );
  return { err, srv, tap };
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

/**
 * One application round trip. Writes and reads are overlapped on purpose: payloads larger than
 * one record hit stream backpressure, and awaiting a multi-record write before the peer reads
 * would deadlock — which is also how real code must use the duplex.
 */
async function exchange(tls, srv, clientPayload, serverPayload) {
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

/** Does a supported_groups extension_data (u16 list length, then u16 group ids) name `group`? */
function hasGroup(extData, group) {
  for (let o = 2; o + 1 < extData.byteLength; o += 2) {
    if (((extData[o] << 8) | extData[o + 1]) === group) return true;
  }
  return false;
}

// ------------------------------------------------------------------ the factory itself

test('the test CA mints parseable certificates whose SPKI is the signing key', () => {
  // If this fails, every handshake test below is built on sand — check it directly rather
  // than let a malformed fixture masquerade as a client bug.
  for (const kind of ['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'rsa-pss', 'ed25519']) {
    const id = testIdentity(kind);
    const parsed = new X509Certificate(id.certDer);
    eq(new Uint8Array(parsed.publicKey.export({ type: 'spki', format: 'der' })), id.spkiDer,
      `${kind}: certificate SPKI is the key that signs CertificateVerify`);
    assert.match(parsed.subject, /CN=server\.test/);
  }
});

// ------------------------------------------------------------------ positive handshakes

test('TLS_AES_128_GCM_SHA256: full handshake, data both ways, and the wire shape', async () => {
  const identity = testIdentity('rsa-pss');
  const intermediate = testIdentity('ed25519'); // stands in for a chain's second element
  const { tls, srv, state, tap, verifyPeer } = await connectPair({
    identity,
    server: { alpn: 'http/1.1', extraChain: [intermediate.certDer] },
  });

  assert.equal(tls.info.version, TLS13);
  assert.equal(tls.info.cipherSuite, AES128);
  assert.equal(tls.info.group, GROUP.x25519);
  assert.equal(tls.info.alpnProtocol, 'http/1.1');
  assert.equal(tls.info.certificateRequested, false);
  assert.equal(tls.info.hostname, HOST);
  assert.equal(tls.peer.stub, true, 'verifyPeer resolution surfaces as tls.peer');

  // Trust plumbing: exactly one validation, with the hostname and the chain in wire order.
  assert.equal(verifyPeer.calls.length, 1);
  assert.equal(verifyPeer.calls[0].hostname, HOST);
  assert.deepEqual(
    verifyPeer.calls[0].chain.map(toHex),
    [identity.certDer, intermediate.certDer].map(toHex),
  );

  // What the server actually received in the ClientHello.
  const ch = state.clientHellos[0];
  assert.equal(ch.serverName, HOST, 'SNI names the target host');
  assert.deepEqual(ch.versions, [TLS13], 'this driver offers TLS 1.3 only');
  assert.deepEqual(ch.keyShares.map((k) => k.group), [GROUP.x25519]);
  assert.equal(state.finishedVerified, true, 'the server checked our Finished, not just read it');

  // Wire shape: plaintext ClientHello, compatibility CCS, then ONE encrypted record (the
  // Finished). Keys going on a message early or late would change this sequence.
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 20, 23]);

  await exchange(tls, srv, utf8('GET / HTTP/1.1\r\nHost: server.test\r\n\r\n'), pattern(300));
});

test('TLS_AES_256_GCM_SHA384 drives the SHA-384 transcript end to end', async () => {
  // A hardcoded SHA-256 anywhere in the schedule or transcript survives every AES-128 test
  // and dies here, on both Finished checks. The server also sends its compatibility CCS to
  // prove the client ignores it mid-handshake.
  const { tls, srv, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    server: { cipher: AES256, compatCcs: true },
  });
  assert.equal(tls.info.cipherSuite, AES256);
  assert.equal(state.finishedVerified, true);
  await exchange(tls, srv, pattern(2000), pattern(1000).reverse());
});

test('TLS_CHACHA20_POLY1305_SHA256: full handshake through the injected AEAD, curl-ordered offer', async () => {
  // Injecting a ChaCha20 implementation puts 0x1303 in the offer at curl's captured position —
  // second, right after AES-256-GCM — and lets the record layer actually protect the session with
  // it. The server needs the same implementation to protect its own flight. A round trip of real
  // application bytes proves seal/open are threaded through every createAead (initial keys here;
  // KeyUpdate rotation is covered in record.test.js).
  const chacha20 = nodeChacha20();
  const { tls, srv, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    deps: { aead: { chacha20 } },
    server: { cipher: 0x1303, aeadImpls: { chacha20 } },
  });
  assert.equal(tls.info.cipherSuite, 0x1303, 'ChaCha20-Poly1305 was negotiated');
  assert.equal(state.finishedVerified, true, 'the server decrypted and verified our Finished');
  // The offer is curl's TLS 1.3 order with ChaCha20 second: AES-256-GCM, ChaCha20, AES-128-GCM.
  assert.deepEqual(state.clientHellos[0].cipherSuites, [0x1302, 0x1303, 0x1301]);

  await exchange(tls, srv, utf8('POST /v1 HTTP/1.1\r\n\r\n{"x":1}'), pattern(800));
});

test('TLS_CHACHA20_POLY1305_SHA256 is NOT offered when no implementation is injected', async () => {
  // Without deps.aead.chacha20 the default offer is unchanged — AES-128, AES-256 — and 0x1303
  // appears nowhere. An AEAD suite offered but not performable is a dead connection if selected.
  const { state } = await connectPair({ identity: testIdentity('rsa-pss') });
  assert.ok(!state.clientHellos[0].cipherSuites.includes(0x1303), 'no ChaCha20 in the offer');
  assert.deepEqual(state.clientHellos[0].cipherSuites, [0x1301, 0x1302],
    'the classical default order is untouched');
});

test('an explicit cipher list cannot smuggle ChaCha20 without an implementation', async () => {
  // profiles.chrome sets tls.ciphers with 0x1303 in it; a caller could too. Capability gating
  // overrides the list — 0x1303 is filtered from the actual offer unless an implementation is
  // injected — so the suite is impossible to advertise dishonestly by hand-writing the list.
  const { state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    clientOptions: { ciphers: [0x1302, 0x1303, 0x1301] },
  });
  assert.ok(!state.clientHellos[0].cipherSuites.includes(0x1303));
  assert.deepEqual(state.clientHellos[0].cipherSuites, [0x1302, 0x1301]);
});

test('an explicit groups list cannot smuggle X25519MLKEM768 without an implementation', async () => {
  const { state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    clientOptions: { groups: [0x11ec, GROUP.x25519], offerGroups: [0x11ec, GROUP.x25519] },
  });
  assert.ok(!state.clientHellos[0].keyShares.some((k) => k.group === 0x11ec),
    'no hybrid key_share when the offerGroups list names it but no ML-KEM is injected');
  assert.ok(!hasGroup(state.clientHellos[0].extensions.get(EXTENSION.supported_groups), 0x11ec),
    'hybrid stripped from an explicit supported_groups too');
});

test('X25519MLKEM768: the injected hybrid group is offered, negotiated, and carries data', async () => {
  // A ClientHello offering the hybrid needs an ML-KEM implementation injected as deps.kem; the
  // server needs the same primitive to encapsulate. finishedVerified is the load-bearing assertion:
  // the server checked our Finished under a key it derived by combining the two secrets on ITS OWN
  // (hand-written, client-code-independent) side. If our concatenation order for the shares or the
  // secret disagreed with the server's, the secrets would differ and this would be false — which is
  // exactly how a hybrid mistake surfaces (never as an exception).
  const kem = fakeMlKem768();
  const { tls, srv, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    deps: { kem: { x25519mlkem768: kem } },
    server: { group: GROUP.x25519mlkem768, hybridKem: kem },
  });
  assert.equal(tls.info.version, TLS13);
  assert.equal(tls.info.group, GROUP.x25519mlkem768, 'the hybrid group was negotiated');
  assert.equal(state.finishedVerified, true, 'server verified our Finished over its own transcript');

  // With ML-KEM injected the default offer matches curl: a 1216-byte hybrid key_share (ek 1184 +
  // X25519 32) AND a plain x25519 share alongside it.
  const ch = state.clientHellos[0];
  const hybrid = ch.keyShares.find((k) => k.group === GROUP.x25519mlkem768);
  assert.ok(hybrid, 'a X25519MLKEM768 key_share was offered');
  assert.equal(hybrid.keyExchange.byteLength, 1216, 'client hybrid share is 1184 + 32');
  assert.ok(ch.keyShares.some((k) => k.group === GROUP.x25519), 'x25519 share offered alongside');
  assert.deepEqual(ch.keyShares.map((k) => k.group), [GROUP.x25519mlkem768, GROUP.x25519],
    'hybrid first, then x25519 — the order curl sends');

  await exchange(tls, srv, utf8('hello over a post-quantum session'), pattern(500));
});

test('X25519MLKEM768 is NOT offered when no ML-KEM implementation is injected', async () => {
  // The same client without deps.kem must fall back to the classical default: no hybrid group in
  // supported_groups, no hybrid key_share. An offer we cannot perform is a dead connection if a
  // server takes it, so it must be impossible to make without the capability.
  const { state } = await connectPair({ identity: testIdentity('rsa-pss') });
  const ch = state.clientHellos[0];
  assert.ok(!ch.keyShares.some((k) => k.group === GROUP.x25519mlkem768),
    'no hybrid key_share without an ML-KEM implementation');
  assert.ok(!ch.extensions.get(EXTENSION.supported_groups)
    || !hasGroup(ch.extensions.get(EXTENSION.supported_groups), GROUP.x25519mlkem768),
    'no hybrid group in supported_groups without an ML-KEM implementation');
});

test('every offered group completes and carries data: x25519, P-256, P-384, P-521', async () => {
  for (const [name, group] of [
    ['x25519', GROUP.x25519],
    ['secp256r1', GROUP.secp256r1],
    ['secp384r1', GROUP.secp384r1],
    ['secp521r1', GROUP.secp521r1],
  ]) {
    const { tls, srv, state } = await connectPair({
      identity: testIdentity('rsa-pss'),
      clientOptions: { offerGroups: [group] },
    });
    assert.equal(tls.info.group, group, name);
    assert.equal(state.finishedVerified, true, name);
    // A data round trip per group: Finished proves the handshake secrets, this proves the
    // application secrets derived from the same shared secret.
    await exchange(tls, srv, utf8(`ping over ${name}`), utf8(`pong over ${name}`));
  }
});

test('an Ed25519 certificate authenticates the handshake', async () => {
  const { tls, srv } = await connectPair({ identity: testIdentity('ed25519') });
  assert.equal(tls.info.cipherSuite, AES128);
  await exchange(tls, srv, utf8('ed25519 ping'), utf8('ed25519 pong'));
});

test('an RSA-PSS (rsa_pss_rsae_sha256) certificate authenticates the handshake', async () => {
  const { tls, srv, state } = await connectPair({ identity: testIdentity('rsa-pss') });
  assert.equal(state.negotiated.cipher, AES128);
  await exchange(tls, srv, utf8('pss ping'), utf8('pss pong'));
});

test('ECDSA certificates: the RFC 8446 DER-encoded CertificateVerify is accepted for ' +
     'P-256, P-384 and P-521', async () => {
  // RFC 8446 s4.4.3 (via RFC 8422 s5.10): ECDSA handshake signatures travel as a DER-encoded
  // ECDSA-Sig-Value, while WebCrypto's ECDSA verify consumes IEEE P1363 (fixed-width r||s) —
  // so verifyHandshakeSignature must convert. The test server deliberately signs DER, like
  // every real server; a version of this test signing raw P1363 would only prove the client
  // can talk to itself. This caught exactly that during development: verifyHandshakeSignature
  // originally passed the wire bytes straight to crypto.subtle.verify and rejected every
  // conforming ECDSA server. P-521 doubles as the long-form-DER-length case (~139-byte
  // signatures) and has a curve order length (66) that matches no hash size.
  for (const kind of ['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521']) {
    const { tls, srv } = await connectPair({ identity: testIdentity(kind) });
    assert.equal(tls.info.cipherSuite, AES128, kind);
    await exchange(tls, srv, utf8(`${kind} ping`), utf8(`${kind} pong`));
  }
});

test('ALPN: the server\'s selection surfaces; omission yields null, not a failure', async () => {
  {
    const { tls } = await connectPair({
      identity: testIdentity('rsa-pss'), server: { alpn: 'http/1.1' },
    });
    assert.equal(tls.info.alpnProtocol, 'http/1.1');
  }
  {
    const { tls, srv } = await connectPair({ identity: testIdentity('rsa-pss'), server: {} });
    assert.equal(tls.info.alpnProtocol, null, 'no ALPN extension means the server declined');
    await exchange(tls, srv, utf8('no alpn'), utf8('still works'));
  }
});

// ------------------------------------------------------------------ HelloRetryRequest

test('HelloRetryRequest: retry to secp256r1 reuses random and session id, and the ' +
     'transcript substitution matches an independent RFC 8446 s4.4.1 computation', async () => {
  const { tls, srv, state, tap } = await connectPair({
    identity: testIdentity('rsa-pss'),
    server: { hrr: { group: GROUP.secp256r1 } },
  });
  assert.equal(tls.info.group, GROUP.secp256r1);
  assert.equal(state.finishedVerified, true);

  const [ch1, ch2] = state.clientHellos;
  assert.equal(state.clientHellos.length, 2);
  // RFC 8446 s4.1.2: ClientHello2 changes the key share but reuses random and session id.
  eq(ch2.random, ch1.random, 'ClientHello2 reuses the random');
  eq(ch2.sessionId, ch1.sessionId, 'ClientHello2 reuses the legacy session id');
  assert.deepEqual(ch1.keyShares.map((k) => k.group), [GROUP.x25519]);
  assert.deepEqual(ch2.keyShares.map((k) => k.group), [GROUP.secp256r1]);
  assert.equal(ch2.keyShares[0].keyExchange.byteLength, 65, 'uncompressed P-256 point');

  // The Finished exchanges already prove client and server agree on the substituted
  // transcript; this proves they agree with the RFC, computed here from its text without the
  // Transcript class, so a substitution bug shared by both sides cannot vouch for itself.
  const ch1Digest = new Uint8Array(await crypto.subtle.digest('SHA-256', ch1.raw));
  const synthetic = concat([Uint8Array.of(254, 0, 0, 32), ch1Digest]); // message_hash header
  const expected = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', concat([synthetic, state.hrrRaw, ch2.raw]),
  ));
  eq(state.transcriptHashAfterCh2, expected, 'transcript after CH2 matches the RFC formula');

  // Both hellos travel in plaintext; the client's single CCS comes before its Finished.
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 22, 20, 23]);

  await exchange(tls, srv, utf8('post-HRR ping'), utf8('post-HRR pong'));
});

test('HelloRetryRequest with a cookie: the cookie is echoed verbatim', async () => {
  const cookie = pattern(64).map((b) => b ^ 0x5a);
  const { tls, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    server: { hrr: { group: GROUP.secp256r1, cookie } },
  });
  assert.equal(tls.info.group, GROUP.secp256r1);
  assert.ok(state.clientHellos[1].cookie, 'ClientHello2 carries the cookie extension');
  // Compared at extension_data level: same inner length prefix, same bytes, nothing re-encoded.
  eq(state.clientHellos[1].cookie, state.hrrCookieSent, 'cookie extension_data echoed verbatim');
  assert.equal(state.clientHellos[0].cookie, null, 'ClientHello1 had no cookie to send');
});

// ------------------------------------------------------------------ record-layer alignment

test('one handshake message spanning three records reassembles', async () => {
  // The flight is sliced so the Certificate message starts in record 1 (right behind a
  // complete EncryptedExtensions — a message boundary mid-record) and finishes in record 3.
  const { tls, srv, tap, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    server: {
      fragmentFlight: (msgs) => {
        const all = concat(msgs);
        const eeLen = msgs[0].byteLength;
        assert.ok(msgs[1].byteLength > 60, 'Certificate is big enough to span the cuts');
        return [
          all.subarray(0, eeLen + 2),
          all.subarray(eeLen + 2, eeLen + 50),
          all.subarray(eeLen + 50),
        ];
      },
    },
  });
  const heads = recordHeads(tap.receivedBytes);
  assert.deepEqual(heads.map((h) => h.type), [22, 23, 23, 23], 'ServerHello + 3 flight records');
  assert.equal(heads[1].len, state.flightLengths[0] + 2 + 17, 'record 1 = EE + 2 cert bytes');
  assert.equal(heads[2].len, 48 + 17, 'record 2 = 48 more Certificate bytes');
  await exchange(tls, srv, utf8('fragmented ping'), utf8('fragmented pong'));
});

test('three handshake messages packed into one record reassemble', async () => {
  const { tls, srv, tap, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    server: { fragmentFlight: (msgs) => [concat(msgs.slice(0, 3)), msgs[3]] },
  });
  const heads = recordHeads(tap.receivedBytes);
  assert.deepEqual(heads.map((h) => h.type), [22, 23, 23]);
  const [eeLen, certLen, cvLen, finLen] = state.flightLengths;
  // inner content-type byte + 16-byte GCM tag on top of the packed plaintext
  assert.equal(heads[1].len, eeLen + certLen + cvLen + 17,
    'EE+Certificate+CertificateVerify share one record');
  assert.equal(heads[2].len, finLen + 17);
  await exchange(tls, srv, utf8('packed ping'), utf8('packed pong'));
});

test('application data larger than one record round-trips both ways', async () => {
  const { tls, srv, tap } = await connectPair({ identity: testIdentity('rsa-pss') });
  const preHandshakeRecords = recordHeads(tap.sentBytes).length;
  const big = pattern(50000); // 4 records at the 2^14 fragmentation boundary
  await exchange(tls, srv, big, Uint8Array.from(big).reverse());
  const appRecords = recordHeads(tap.sentBytes).slice(preHandshakeRecords);
  assert.equal(appRecords.length, 4, '50000 bytes fragment into exactly four records');
  assert.ok(appRecords.every((h) => h.type === 23 && h.len <= 16384 + 256));
});

// ------------------------------------------------------------------ determinism and replay

test('injected randomness and key pairs make the whole handshake byte-for-byte ' +
     'reproducible', async () => {
  // Every random input is pinned: client random/session id via deps.randomBytes, both key
  // pairs pre-generated and reused, the server random fixed, and an Ed25519 certificate
  // because Ed25519 signing is deterministic (ECDSA and RSA-PSS both mix in fresh randomness,
  // which is why THEY get the replay test below instead).
  const identity = testIdentity('ed25519');
  const clientPair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const serverPair = await generateKeyShare(GROUP.x25519, {});
  const serverRandom = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i & 15));

  const run = async () => {
    const { tls, tap } = await connectPair({
      identity,
      deps: { randomBytes: seededBytes(0x5eed), generateKeyPair: async () => clientPair },
      server: { serverRandom, serverKeyPair: serverPair, alpn: 'http/1.1' },
    });
    assert.equal(tls.info.alpnProtocol, 'http/1.1');
    return { client: toHex(tap.sentBytes), server: toHex(tap.receivedBytes) };
  };

  const one = await run();
  const two = await run();
  assert.equal(two.client, one.client, 'client wire image is identical across runs');
  assert.equal(two.server, one.server, 'server wire image is identical across runs');
});

test('a recorded server flight replays: the client is a pure function of its deps and ' +
     'the peer\'s bytes', async () => {
  // This is the property that makes captured handshakes usable as offline fixtures. RSA-PSS
  // signatures are salted, so two LIVE runs differ — replaying the recorded server bytes is
  // exactly what removes that noise, and is the point of the test.
  const identity = testIdentity('rsa-pss');
  const clientPair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const depsFor = () => ({ randomBytes: seededBytes(0xf1), generateKeyPair: async () => clientPair });

  const live = await connectPair({ identity, deps: depsFor(), server: { alpn: 'http/1.1' } });
  const serverBytes = live.tap.receivedBytes;
  const clientBytes = live.tap.sentBytes;

  const out = recordingWritable();
  const tls = await handshakeTls13({
    transport: { readable: readableFrom([serverBytes]), writable: out.stream },
    hostname: HOST,
    verifyPeer: acceptStub(identity),
    deps: depsFor(),
  });
  assert.deepEqual(tls.info, live.tls.info, 'replay negotiates identically');
  eq(out.bytes, clientBytes, 'replayed client output is byte-for-byte the recorded output');
});

// ------------------------------------------------------------------ shutdown

test('close(): close_notify reads as a clean end on both sides, never an error', async () => {
  const { tls, srv } = await connectPair({ identity: testIdentity('rsa-pss') });
  await exchange(tls, srv, utf8('last words'), utf8('goodbye')); // close after real traffic
  // Overlapped on purpose: over duplexPair a write only completes once the peer reads it, so
  // the close_notify send and the peer's read of it must be in flight together — the same
  // discipline real code needs against a peer whose receive window may be full.
  const clientClosing = tls.close();
  assert.equal(await srv.record.readAppData(), null,
    'the server sees clean EOF — a bare transport close would have thrown TLS_TRUNCATED');
  await clientClosing;
  const serverClosing = srv.record.close();
  const reader = tls.readable.getReader();
  const { done, value } = await reader.read();
  assert.equal(done, true, 'the client readable ends cleanly after the answering close_notify');
  assert.equal(value, undefined);
  await serverClosing;
});

// ------------------------------------------------------------------ trust failures

test('a rejected certificate chain aborts with the verifier\'s own error, before any ' +
     'encrypted byte leaves the client', async () => {
  const identity = testIdentity('rsa-pss');
  const boom = new CertificateError(codes.CERT_UNTRUSTED_ROOT, 'the trust layer says no');
  const { a, b } = duplexPair();
  const tap = tapTransport(a);
  // The server pushes 0.5-RTT application data right behind its Finished: if any path handed
  // the application a duplex before verification, these bytes are what it would read.
  const srv = startServer(b, identity, { earlyAppData: utf8('half-RTT bytes that must never surface') });

  let err;
  try {
    await handshakeTls13({
      transport: tap.transport, hostname: HOST, verifyPeer: async () => { throw boom; },
    });
    assert.fail('handshake must reject when verifyPeer throws');
  } catch (e) {
    err = e;
  }
  assert.equal(err, boom, 'the verifier error propagates unwrapped, code and all');
  assert.equal(err.code, codes.CERT_UNTRUSTED_ROOT);

  // The strongest claim available, read off the wire: everything TLS 1.3 encrypts travels in
  // outer application_data (23) records, and the client sent NONE — so no Finished, no
  // application data, and nothing derived from the handshake keys ever left this process. The
  // rejected promise means no duplex exists to read the server's 0.5-RTT bait from either.
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 21],
    'ClientHello, then one plaintext fatal alert: nothing else escaped');
  assert.equal(srv.state.finishedVerified, false, 'the server never saw a client Finished');
});

test('a verifier that resolves without an SPKI is a configuration error, not a skipped ' +
     'check', async () => {
  const { tap } = await failPair(
    { identity: testIdentity('rsa-pss'), verifyPeer: async () => ({}) },
    codes.CONFIG_INVALID, /spki\.spkiDer/,
  );
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 21],
    'still nothing encrypted left the client');
});

test('CertificateVerify signed over the wrong transcript is rejected', async () => {
  const identity = testIdentity('rsa-pss');
  const vp = acceptStub(identity);
  const { tap } = await failPair(
    { identity, verifyPeer: vp, server: { cvTranscript: 'throughEncryptedExtensions' } },
    codes.TLS_HANDSHAKE, /does not verify/,
  );
  // Trust ran first (the chain was fine); the SIGNATURE over the wrong hash is what failed —
  // and the failure still predates any encrypted client byte.
  assert.equal(vp.calls.length, 1, 'chain validation happened before the signature check');
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 21]);
});

test('CertificateVerify signed by a key other than the certificate\'s is rejected', async () => {
  const identity = testIdentity('rsa-pss');
  const impostor = makeIdentity('rsa-pss'); // fresh key pair, same algorithm and scheme
  await failPair(
    { identity, server: { signWith: impostor.sign } },
    codes.TLS_HANDSHAKE, /does not verify/,
  );
});

test('a tampered ECDSA CertificateVerify (well-formed DER, wrong value) is rejected', async () => {
  // Flipping the low byte of s keeps the ECDSA-Sig-Value perfectly well-formed, so this cannot
  // be waved off by the DER parser — it must reach the actual signature verification and fail
  // there. Guards against a DER-to-P1363 conversion that "repairs" its input into validity.
  const identity = testIdentity('ecdsa-p256');
  await failPair(
    {
      identity,
      server: {
        signWith: (content) => {
          const sig = identity.sign(content);
          sig[sig.length - 1] ^= 0x01;
          return sig;
        },
      },
    },
    codes.TLS_HANDSHAKE, /does not verify/,
  );
});

test('a server Finished with wrong verify_data is rejected', async () => {
  const { tap } = await failPair(
    { identity: testIdentity('rsa-pss'), server: { corruptFinished: true } },
    codes.TLS_HANDSHAKE, /verify_data does not match/,
  );
  assert.deepEqual(recordHeads(tap.sentBytes).map((h) => h.type), [22, 21],
    'no client Finished went out against a server that failed its own');
});

// ------------------------------------------------------------------ negotiation failures

test('a ServerHello echoing a different legacy_session_id is rejected', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { sessionIdEcho: pattern(32).reverse() } },
    codes.TLS_HANDSHAKE, /did not echo legacy_session_id/,
  );
});

test('a ServerHello selecting a cipher suite we never offered is rejected', async () => {
  // 0x1303 (ChaCha20) is real TLS 1.3 but deliberately not offered by this package.
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { wireCipher: 0x1303 } },
    codes.TLS_CIPHER_UNSUPPORTED, /0x1303/,
  );
});

test('a ServerHello key_share for a group we sent no share for is rejected', async () => {
  // secp256r1 IS in our supported_groups — the correct server move was HelloRetryRequest.
  // Accepting it would mean doing ECDH with a share we never generated.
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { shareGroup: GROUP.secp256r1 } },
    codes.TLS_HANDSHAKE, /no share was offered/,
  );
});

test('a TLS 1.2 ServerHello (no supported_versions, legacy 0x0303) is rejected by the ' +
     '1.3-only driver', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { omitSupportedVersions: true } },
    codes.TLS_VERSION_UNSUPPORTED, /not offered/,
  );
});

test('the downgrade sentinel: unreachable end to end in the 1.3-only driver, and fatal at ' +
     'the negotiateVersion level', async () => {
  // End to end first: plant the RFC 8446 s4.1.3 sentinel in a 1.2-negotiating ServerHello.
  // handshakeTls13 offers ONLY 1.3, so any ServerHello landing on 1.2 is rejected as
  // "version not offered" BEFORE negotiateVersion's sentinel comparison — the sentinel check
  // exists for a client that offers {1.3, 1.2} and lands on 1.2, a combination this driver
  // cannot produce. So the sentinel path is exercised directly at the unit it lives in.
  const sentinelRandom = pattern(32);
  sentinelRandom.set(DOWNGRADE_SENTINEL_12, 24);
  const { err } = await failPair(
    {
      identity: testIdentity('rsa-pss'),
      server: { omitSupportedVersions: true, serverRandom: sentinelRandom },
    },
    codes.TLS_VERSION_UNSUPPORTED, /not offered/,
  );
  assert.ok(!/sentinel/.test(err.message),
    'the not-offered guard fires first; the sentinel branch is unreachable from handshakeTls13');

  // The sentinel check itself, with the offer list that CAN reach it.
  const sh = { legacyVersion: TLS12, random: sentinelRandom, extensions: new Map() };
  const unit = await rejectsWithCode(
    async () => negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }),
    codes.TLS_VERSION_UNSUPPORTED, /downgrade sentinel/,
  );
  assert.equal(unit.detail.sentinel, true);
});

test('EncryptedExtensions containing an extension we never offered is rejected', async () => {
  await failPair(
    {
      identity: testIdentity('rsa-pss'),
      server: { eeExtra: [rawExtension(EXTENSION.early_data, new Uint8Array(0))] },
    },
    codes.TLS_EXTENSION_UNSUPPORTED, /0x002a/,
  );
});

test('ALPN selecting a protocol we did not offer is rejected', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { alpn: 'h2' } },
    codes.TLS_ALPN, /"h2"/,
  );
});

// ------------------------------------------------------------------ flight-order and stream failures

test('Certificate arriving before EncryptedExtensions is rejected, naming both types', async () => {
  const { err } = await failPair(
    { identity: testIdentity('rsa-pss'), server: { flightOrder: 'certificateFirst' } },
    codes.TLS_HANDSHAKE, /certificate/,
  );
  assert.match(err.message, /EncryptedExtensions/, 'the error names what was expected too');
});

test('a fatal alert mid-handshake surfaces as TLS_ALERT with the alert NAME', async () => {
  const { err } = await failPair(
    { identity: testIdentity('rsa-pss'), server: { alertAfter: 'encryptedExtensions', alertDesc: 40 } },
    codes.TLS_ALERT, /handshake_failure/,
  );
  assert.equal(err.detail.name, 'handshake_failure');
  assert.equal(err.detail.description, 40);
});

test('the server closing the transport mid-flight is a truncation, never a clean end', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { closeAfter: 'encryptedExtensions' } },
    codes.TLS_TRUNCATED, /without close_notify/,
  );
});

test('an empty certificate_list is rejected as an incomplete chain', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { emptyCertificateList: true } },
    codes.CERT_CHAIN_INCOMPLETE, /empty certificate_list/,
  );
});

// ------------------------------------------------------------------ HelloRetryRequest failures

test('a second HelloRetryRequest is rejected', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { hrr: { group: GROUP.secp256r1, second: true } } },
    codes.TLS_HANDSHAKE, /second HelloRetryRequest/,
  );
});

test('a HelloRetryRequest demanding a group we already sent a share for is a loop', async () => {
  await failPair(
    { identity: testIdentity('rsa-pss'), server: { hrr: { group: GROUP.x25519 } } },
    codes.TLS_HANDSHAKE, /looping/,
  );
});

test('a ServerHello changing cipher suite after the HelloRetryRequest is rejected', async () => {
  await failPair(
    {
      identity: testIdentity('rsa-pss'),
      server: { hrr: { group: GROUP.secp256r1, cipherAfter: AES256 } },
    },
    codes.TLS_CIPHER_UNSUPPORTED, /after HelloRetryRequest selected/,
  );
});

// ------------------------------------------------------------------ version pinning

test('handshakeTls13 pins the offer to [TLS 1.3] even when options.versions asks for more', async () => {
  // Every guarantee in this file rests on the hello offering exactly one version; an offer
  // widened through an options passthrough would silently change which downgrade guards apply.
  const { tls, state } = await connectPair({
    identity: testIdentity('rsa-pss'),
    clientOptions: { versions: [TLS13, TLS12] },
  });
  assert.equal(tls.info.version, TLS13);
  assert.deepEqual(state.clientHellos[0].versions, [TLS13],
    'the single-version entry point cannot be widened through options');
});

test('connectTls with versions [TLS13] is byte-for-byte this driver', async () => {
  // The strongest form of "an explicit [TLS13] still behaves exactly as handshakeTls13": with
  // every random input pinned (ed25519 signing is deterministic; both key pairs and both
  // randoms injected), the two entries must emit the identical wire image.
  const identity = testIdentity('ed25519');
  const clientPair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const serverPair = await generateKeyShare(GROUP.x25519, {});
  const serverRandom = Uint8Array.from({ length: 32 }, (_, i) => 0xb0 + (i & 15));
  const run = async (handshake) => {
    const { a, b } = duplexPair();
    const tap = tapTransport(a);
    const srv = startServer(b, identity, {
      serverRandom, serverKeyPair: serverPair, alpn: 'http/1.1',
    });
    const tls = await handshake({
      transport: tap.transport, hostname: HOST, verifyPeer: acceptStub(identity),
      deps: { randomBytes: seededBytes(0xd1ff), generateKeyPair: async () => clientPair },
    });
    await srv.done;
    return { info: tls.info, bytes: toHex(tap.sentBytes) };
  };
  const viaDriver = await run(handshakeTls13);
  const viaConnect = await run((args) => connectTls({ ...args, options: { versions: [TLS13] } }));
  assert.deepEqual(viaConnect.info, viaDriver.info, 'identical negotiation outcome');
  assert.equal(viaConnect.bytes, viaDriver.bytes,
    'requesting [TLS13] explicitly produces the identical wire image');
});

// ------------------------------------------------------------------ configuration

test('handshakeTls13 without verifyPeer refuses to start: there is no unverified mode', async () => {
  const { a } = duplexPair();
  await rejectsWithCode(
    () => handshakeTls13({ transport: a, hostname: HOST }),
    codes.CONFIG_INVALID, /verifyPeer/,
  );
});
