// OCSP stapling at the TLS layer: the status_request offer, the two per-version delivery paths
// (RFC 8446 s4.4.2.1 CertificateEntry extension; RFC 6066 s8 CertificateStatus message), and
// the driver rules around them. The staple's MEANING is the trust layer's problem
// (test/trust/ocsp.test.js); this file proves the bytes arrive intact, at the right moment, and
// that every misplacement or malformation ends the handshake.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sign as nodeSign } from 'node:crypto';

import { handshakeTls13 } from '../../src/tls/handshake.js';
import { handshakeTls12 } from '../../src/tls/handshake12.js';
import {
  buildClientHello, generateKeyShare, parseCertificateStatus,
} from '../../src/tls/handshake-messages.js';
import { EXTENSION, GROUP, SIG_SCHEME, TLS12 } from '../../src/tls/constants.js';
import { Builder } from '../../src/tls/wire.js';
import { codes } from '../../src/errors.js';
import { verifyChain } from '../../src/trust/index.js';
import { toHex, utf8 } from '../../src/util/bytes.js';
import { collect, duplexPair, rejectsWithCode } from '../_harness.js';
import { rawExtension, stapleEntryExtension, startServer } from './_server.js';
import { startServer12 } from './_server12.js';
import { testIdentity } from './_testca.js';
import { caFixture, makeCert, makeOcspResponse } from '../trust/_certs.js';

const HOST = 'server.test';
const NOW = Date.now();
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

/** A plausible staple body; drivers must carry it opaquely, so content is irrelevant here. */
const fakeStaple = Uint8Array.from({ length: 96 }, (_, i) => (i * 7 + 3) & 0xff);

/** verifyPeer stub that records the details argument each driver passes. */
function capturingStub(identity) {
  const calls = [];
  const verifyPeer = async (chain, hostname, details) => {
    calls.push({ hostname, ocspResponse: details?.ocspResponse ?? null });
    return { spki: { spkiDer: identity.spkiDer } };
  };
  return { verifyPeer, calls };
}

// ================================================================ the offer

test('every ClientHello offers status_request, whatever the version set', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  const both = buildClientHello({ hostname: HOST, keyShares: [share] });
  assert.ok(both.offeredExtensions.has(EXTENSION.status_request));
  // The 1.2-only hello too: RFC 6066 stapling predates 1.3 and the offer costs 9 bytes.
  const only12 = buildClientHello({ hostname: HOST, keyShares: [], versions: [TLS12] });
  assert.ok(only12.offeredExtensions.has(EXTENSION.status_request));
});

// ================================================================ the shared CertificateStatus shape

test('parseCertificateStatus returns the DER exactly and refuses everything else', () => {
  const body = new Builder().u8(1).vector(3, fakeStaple).build();
  assert.equal(toHex(parseCertificateStatus(body, 'CertificateStatus')), toHex(fakeStaple));

  const wrongType = new Builder().u8(2).vector(3, fakeStaple).build();
  assert.throws(() => parseCertificateStatus(wrongType, 'CertificateStatus'), (e) => {
    assert.equal(e.code, codes.TLS_HANDSHAKE);
    assert.match(e.message, /status_type 2/);
    return true;
  });

  const empty = new Builder().u8(1).vector(3, new Uint8Array(0)).build();
  assert.throws(() => parseCertificateStatus(empty, 'CertificateStatus'),
    (e) => e.code === codes.TLS_HANDSHAKE);

  const trailing = new Builder().u8(1).vector(3, fakeStaple).u8(0).build();
  assert.throws(() => parseCertificateStatus(trailing, 'CertificateStatus'),
    (e) => e.code === codes.TLS_HANDSHAKE);
});

// ================================================================ TLS 1.3 delivery

// Nobody here closes the 1.3 session: the scripted server stops reading once its drive is done,
// so close() would sit out its close_notify deadline — the same reason handshake.test.js's
// connectPair leaves sessions open. Shutdown behaviour has its own suite.
async function run13({ server = {}, verifyPeer, identity = testIdentity('ecdsa-p256') }) {
  const { a, b } = duplexPair();
  const srv = startServer(b, identity, server);
  const tls = await handshakeTls13({ transport: a, hostname: HOST, verifyPeer });
  const state = await srv.done;
  return { tls, state };
}

async function fail13({ server = {}, verifyPeer, identity = testIdentity('ecdsa-p256') }, code, msgMatch) {
  const { a, b } = duplexPair();
  startServer(b, identity, server);
  return rejectsWithCode(
    () => handshakeTls13({ transport: a, hostname: HOST, verifyPeer }), code, msgMatch);
}

test('a leaf-entry staple reaches verifyPeer alongside the chain (TLS 1.3)', async () => {
  const identity = testIdentity('ecdsa-p256');
  const { verifyPeer, calls } = capturingStub(identity);
  const { state } = await run13({ server: { staple: fakeStaple }, verifyPeer });
  assert.equal(state.finishedVerified, true);
  assert.equal(calls.length, 1);
  assert.equal(toHex(calls[0].ocspResponse), toHex(fakeStaple));
});

test('no staple means ocspResponse null, not undefined and not absent (TLS 1.3)', async () => {
  const identity = testIdentity('ecdsa-p256');
  const { verifyPeer, calls } = capturingStub(identity);
  await run13({ verifyPeer });
  assert.equal(calls[0].ocspResponse, null);
});

test('a staple on an intermediate entry is not the leaf\'s staple (TLS 1.3)', async () => {
  // Legal per RFC 8446 (multi-stapling), but this package consumes only the leaf's; the entry
  // must still parse and the handshake must still complete.
  const identity = testIdentity('ecdsa-p256');
  const { verifyPeer, calls } = capturingStub(identity);
  const { state } = await run13({
    server: { extraChain: [identity.certDer], entryExtensions: { 1: stapleEntryExtension(fakeStaple) } },
    verifyPeer,
  });
  assert.equal(state.finishedVerified, true);
  assert.equal(calls[0].ocspResponse, null);
});

test('an unoffered extension in a CertificateEntry is fatal (TLS 1.3)', async () => {
  const identity = testIdentity('ecdsa-p256');
  await fail13({
    server: { entryExtensions: { 0: rawExtension(0xfafa, new Uint8Array(2)) } },
    verifyPeer: capturingStub(identity).verifyPeer,
  }, codes.TLS_EXTENSION_UNSUPPORTED, /CertificateEntry 0/);
});

test('an offered extension that does not belong in Certificate is fatal (TLS 1.3)', async () => {
  // ALPN was offered in the hello, so the unoffered check cannot catch it — the message-placement
  // rule of RFC 8446 s4.2 must.
  const identity = testIdentity('ecdsa-p256');
  await fail13({
    server: { entryExtensions: { 0: rawExtension(EXTENSION.alpn, new Uint8Array(0)) } },
    verifyPeer: capturingStub(identity).verifyPeer,
  }, codes.TLS_HANDSHAKE, /does not belong in a Certificate message/);
});

test('a malformed entry staple is fatal, not skipped (TLS 1.3)', async () => {
  const identity = testIdentity('ecdsa-p256');
  await fail13({
    server: { entryExtensions: {
      0: rawExtension(EXTENSION.status_request, new Builder().u8(2).vector(3, fakeStaple).build()),
    } },
    verifyPeer: capturingStub(identity).verifyPeer,
  }, codes.TLS_HANDSHAKE, /status_type 2/);
});

test('status_request answered in EncryptedExtensions is fatal (TLS 1.3)', async () => {
  const identity = testIdentity('ecdsa-p256');
  await fail13({
    server: { eeExtra: [rawExtension(EXTENSION.status_request, new Uint8Array(0))] },
    verifyPeer: capturingStub(identity).verifyPeer,
  }, codes.TLS_HANDSHAKE, /EncryptedExtensions/);
});

// ================================================================ TLS 1.2 delivery

function rig12(serverOpts = {}, verifyPeer) {
  const { a, b } = duplexPair();
  const server = startServer12(b, serverOpts);
  return {
    server,
    handshake: () => handshakeTls12({ transport: a, hostname: HOST, verifyPeer }),
  };
}

test('a CertificateStatus staple reaches verifyPeer, and the transcript survives it (TLS 1.2)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } });
  const { verifyPeer, calls } = capturingStub(identity);
  const r = rig12({ identity, staple: fakeStaple }, verifyPeer);
  const tls = await r.handshake();
  // Push a byte each way so the server-side Finished/transcript verdict is fully settled: the
  // scripted server folded CertificateStatus into ITS transcript, so both Finished checks prove
  // the client did too.
  const echoed = collect(tls.readable);
  const w = tls.writable.getWriter();
  await w.write(utf8('ping'));
  await w.close();
  await echoed;
  const summary = await r.server.done;
  assert.equal(summary.error, null, `server saw: ${JSON.stringify(summary.error)}`);
  assert.equal(summary.clientFinishedVerified, true);
  assert.equal(toHex(calls[0].ocspResponse), toHex(fakeStaple));
});

test('an echo without a CertificateStatus message is legal and yields null (TLS 1.2)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } });
  const { verifyPeer, calls } = capturingStub(identity);
  const r = rig12({ identity, echoStatusRequest: true }, verifyPeer);
  const tls = await r.handshake();
  assert.equal(calls[0].ocspResponse, null);
  await tls.close();
});

test('a CertificateStatus nobody announced is fatal (TLS 1.2)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } });
  const { verifyPeer } = capturingStub(identity);
  const r = rig12({ identity, stapleWithoutEcho: fakeStaple }, verifyPeer);
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /without echoing status_request/);
});

test('a non-empty status_request echo is fatal (TLS 1.2)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } });
  const { verifyPeer } = capturingStub(identity);
  const r = rig12({ identity, staple: fakeStaple, statusEchoBody: Uint8Array.of(1) }, verifyPeer);
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /must have empty extension_data/);
});

test('a CertificateStatus with a status_type other than ocsp is fatal (TLS 1.2)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } });
  const { verifyPeer } = capturingStub(identity);
  const r = rig12({ identity, staple: fakeStaple, stapleStatusType: 2 }, verifyPeer);
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /status_type 2/);
});

// ================================================================ full stack: driver + trust

const fxTls = caFixture();
const leafIdentity13 = {
  certDer: fxTls.leaf.der,
  spkiDer: fxTls.leaf.spkiDer,
  scheme: SIG_SCHEME.ecdsa_secp256r1_sha256,
  sign: (content) =>
    new Uint8Array(nodeSign('sha256', content, { key: fxTls.leaf.privateKey, dsaEncoding: 'der' })),
};
const realVerify = (anchors) => (chain, hostname, details) =>
  verifyChain({
    chain, hostname, trust: { mode: 'anchors', anchors }, now: NOW,
    ocspResponse: details?.ocspResponse ?? null,
  });

test('a stapled revoked verdict aborts the handshake before the client Finished (TLS 1.3)', async () => {
  const revoked = makeOcspResponse({
    issuer: fxTls.intermediate, subject: fxTls.leaf, status: 'revoked',
    revocationTime: NOW - DAY, reason: 1, thisUpdate: NOW - HOUR, nextUpdate: NOW + DAY,
  }).der;
  const { a, b } = duplexPair();
  const srv = startServer(b, leafIdentity13, {
    staple: revoked, extraChain: [fxTls.intermediate.der],
  });
  const err = await rejectsWithCode(
    () => handshakeTls13({
      transport: a, hostname: HOST, verifyPeer: realVerify([fxTls.root.der]),
    }),
    codes.OCSP_REVOKED, /keyCompromise/);
  assert.match(err.message, /serial 0x/);
  assert.equal(srv.state.finishedVerified, false,
    'the client must never have sent its Finished for a revoked peer');
});

test('a good staple rides the same rails to a completed handshake (TLS 1.3)', async () => {
  const good = makeOcspResponse({
    issuer: fxTls.intermediate, subject: fxTls.leaf,
    thisUpdate: NOW - HOUR, nextUpdate: NOW + 7 * DAY,
  }).der;
  const { a, b } = duplexPair();
  const srv = startServer(b, leafIdentity13, {
    staple: good, extraChain: [fxTls.intermediate.der],
  });
  const tls = await handshakeTls13({
    transport: a, hostname: HOST, verifyPeer: realVerify([fxTls.root.der]),
  });
  const state = await srv.done;
  assert.equal(state.finishedVerified, true);
  assert.equal(tls.peer.subject.text, 'CN=server.test, O=tunnelfetch');
});

test('a stapled revoked verdict aborts the handshake (TLS 1.2, leaf under the anchor itself)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } }); // self-signed = its own issuer
  const revoked = makeOcspResponse({
    issuer: identity, subject: identity, status: 'revoked',
    revocationTime: NOW - DAY, reason: 4, thisUpdate: NOW - HOUR, nextUpdate: NOW + DAY,
  }).der;
  const r = rig12({ identity, staple: revoked }, realVerify([identity.der]));
  const err = await rejectsWithCode(() => r.handshake(), codes.OCSP_REVOKED, /superseded/);
  assert.match(err.message, /serial 0x/);
});

test('a good staple completes the handshake (TLS 1.2, anchor-issuer branch)', async () => {
  const identity = makeCert({ subject: { CN: HOST, O: 't' } });
  const good = makeOcspResponse({
    issuer: identity, subject: identity, thisUpdate: NOW - HOUR, nextUpdate: NOW + DAY,
  }).der;
  const r = rig12({ identity, staple: good }, realVerify([identity.der]));
  const tls = await r.handshake();
  assert.equal(tls.peer.subject.text, `CN=${HOST}, O=t`);
  await tls.close();
});
