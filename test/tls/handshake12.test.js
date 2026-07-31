// TLS 1.2 handshake driver against an independent RFC 5246 server (_server12.js, node:crypto).
//
// The positive tests prove interop — same PRF, same key_block, same AEAD framing, same DER
// signature format — against an implementation that shares no code with src/tls. The negative
// tests each make the server wrong in exactly one way and pin the specific error code the
// driver must produce, because a client that fails open (or fails with the wrong story) against
// a hostile peer is the actual threat model of this package.

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';

import { handshakeTls12, ecdsaDerToRaw } from '../../src/tls/handshake12.js';
import { connectTls } from '../../src/tls/connect.js';
import { parseServerHello, verifyHandshakeSignature } from '../../src/tls/handshake-messages.js';
import {
  CIPHER,
  GROUP,
  HELLO_RETRY_REQUEST_RANDOM,
  SIG_SCHEME,
  SUPPORTED_GROUPS,
  SUPPORTED_SIG_SCHEMES,
  TLS12,
  TLS12_CIPHERS,
  TLS13,
} from '../../src/tls/constants.js';
import { Builder } from '../../src/tls/wire.js';
import { CertificateError, codes } from '../../src/errors.js';
import { concat, toHex, utf8 } from '../../src/util/bytes.js';
import { collect, duplexPair, rejectsWithCode } from '../_harness.js';
import { makeEcdhe, serverIdentity, startServer12 } from './_server12.js';
import { makeKeys } from '../trust/_certs.js';

const HOST = 'server.test';
const pattern = (n) => Uint8Array.from({ length: n }, (_, i) => i & 0xff);
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);

/** The trust stub: hands back the minted identity's SPKI, exactly as the real layer would. */
const trust = (identity) => async () => ({ spki: { spkiDer: identity.spkiDer } });

/** One server + one client transport, wired through duplexPair. */
function rig(serverOpts = {}) {
  const { a, b } = duplexPair();
  const identity = serverOpts.identity ?? serverIdentity('ec-p256');
  const server = startServer12(b, serverOpts);
  return {
    identity,
    server,
    handshake: (clientOptions = {}, verifyPeer) =>
      handshakeTls12({
        transport: a,
        hostname: HOST,
        verifyPeer: verifyPeer ?? trust(identity),
        options: clientOptions,
      }),
  };
}

/** Full happy path: handshake, one payload each way through the echo, clean close. */
async function roundTrip(serverOpts = {}, clientOptions = {}, payload = utf8('ping over TLS 1.2')) {
  const r = rig(serverOpts);
  const tls = await r.handshake(clientOptions);
  const echoedP = collect(tls.readable);
  const w = tls.writable.getWriter();
  await w.write(payload);
  await w.close();
  const echoed = await echoedP;
  const summary = await r.server.done;
  return { tls, echoed, summary };
}

function assertClean(summary) {
  assert.equal(summary.error, null, `server saw: ${JSON.stringify(summary.error)}`);
  assert.equal(summary.clientFinishedVerified, true, 'server verified the client Finished');
  assert.equal(summary.sawCloseNotify, true, 'shutdown ended with close_notify');
}

// ================================================================ positive paths

test('full handshake, echo and clean close for every negotiable suite', async (t) => {
  const matrix = [
    {
      name: 'ECDHE_ECDSA_AES128_GCM_SHA256, P-256 cert, x25519',
      cipher: CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      keyType: 'ec-p256',
      sigScheme: SIG_SCHEME.ecdsa_secp256r1_sha256,
      group: GROUP.x25519,
    },
    {
      name: 'ECDHE_RSA_AES128_GCM_SHA256, RSA cert (PSS), secp256r1',
      cipher: CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      keyType: 'rsa',
      sigScheme: SIG_SCHEME.rsa_pss_rsae_sha256,
      group: GROUP.secp256r1,
    },
    {
      name: 'ECDHE_ECDSA_AES256_GCM_SHA384, P-384 cert, secp384r1',
      cipher: CIPHER.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
      keyType: 'ec-p384',
      sigScheme: SIG_SCHEME.ecdsa_secp384r1_sha384,
      group: GROUP.secp384r1,
    },
    {
      name: 'ECDHE_RSA_AES256_GCM_SHA384, RSA cert (PKCS#1), secp521r1',
      cipher: CIPHER.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      keyType: 'rsa',
      sigScheme: SIG_SCHEME.rsa_pkcs1_sha384,
      group: GROUP.secp521r1,
    },
  ];
  for (const m of matrix) {
    await t.test(m.name, async () => {
      const payload = utf8(`payload for ${m.name}`);
      const { tls, echoed, summary } = await roundTrip(
        { identity: serverIdentity(m.keyType), cipher: m.cipher, sigScheme: m.sigScheme, group: m.group },
        {},
        payload,
      );
      eq(echoed, payload, 'echo made the round trip');
      eq(summary.appDataReceived, payload, 'server decrypted what we sent');
      assert.equal(tls.info.version, TLS12);
      assert.equal(tls.info.cipherSuite, m.cipher);
      assert.equal(tls.info.group, m.group);
      assert.equal(tls.info.extendedMasterSecret, true);
      assert.equal(tls.info.alpnProtocol, null);
      assert.equal(tls.info.certificateRequested, false);
      assert.equal(tls.info.hostname, HOST);
      assertClean(summary);
    });
  }
});

test('P-521 ECDSA ServerKeyExchange (long-form DER signature) verifies end to end', async () => {
  // _certs.js has no P-521 keyType, so hand serverIdentity an explicit pair. A P-521 signature
  // is ~138 DER bytes, which forces the 0x81 long-form length the converter must handle.
  const keys = generateKeyPairSync('ec', { namedCurve: 'secp521r1' });
  const identity = serverIdentity('ec-p256', keys);
  const { echoed, summary } = await roundTrip({
    identity,
    cipher: CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    sigScheme: SIG_SCHEME.ecdsa_secp521r1_sha512,
    group: GROUP.secp521r1,
  });
  eq(echoed, utf8('ping over TLS 1.2'));
  assertClean(summary);
});

const ed25519Available = await (async () => {
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    return true;
  } catch {
    return false;
  }
})();

test('Ed25519-signed ServerKeyExchange under an ECDSA suite (RFC 8422 s5.10)',
  { skip: !ed25519Available && 'WebCrypto Ed25519 unavailable' }, async () => {
    const { summary, tls } = await roundTrip({
      identity: serverIdentity('ed25519'),
      cipher: CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
      sigScheme: SIG_SCHEME.ed25519,
      group: GROUP.secp256r1,
    });
    assert.equal(tls.info.cipherSuite, CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    assertClean(summary);
  });

test('the ClientHello is strictly TLS 1.2: no 1.3 extensions, and the 1.2 armour is on', async () => {
  const { summary } = await roundTrip({ alpn: 'http/1.1' });
  const ch = summary.clientHello;
  assert.equal(ch.legacyVersion, 0x0303);
  assert.equal(ch.hasSupportedVersions, false, 'supported_versions would make this a 1.3 hello');
  assert.equal(ch.hasKeyShare, false, 'key_share is 1.3-only');
  assert.equal(ch.hasPskModes, false, 'psk_key_exchange_modes is 1.3-only');
  assert.equal(ch.hasEms, true, 'extended_master_secret must be offered');
  assert.equal(ch.hasRenegotiationInfo, true, 'renegotiation_info must be offered');
  assert.equal(ch.hasEcPointFormats, true);
  assert.deepEqual(ch.ciphers, TLS12_CIPHERS, 'exactly the 1.2 AEAD suites, in order');
  assert.deepEqual(ch.compressions, [0], 'null compression only (CRIME)');
  assert.equal(ch.sni, HOST);
  assert.deepEqual(ch.alpn, ['http/1.1']);
  assert.equal(ch.sessionId.byteLength, 32, 'throwaway session id for middlebox camouflage');
  assert.deepEqual(ch.groups, SUPPORTED_GROUPS);
  assert.deepEqual(ch.sigSchemes, SUPPORTED_SIG_SCHEMES);
});

test('verifyPeer receives the presented chain and the hostname', async () => {
  const r = rig({});
  let seen = null;
  const tls = await r.handshake({}, async (chain, hostname) => {
    seen = { chain, hostname };
    return { spki: { spkiDer: r.identity.spkiDer } };
  });
  assert.ok(seen, 'verifyPeer ran');
  assert.equal(seen.hostname, HOST);
  assert.equal(seen.chain.length, 1);
  eq(seen.chain[0], r.identity.der, 'the exact DER the server presented');
  await tls.close();
  await r.server.done;
});

test('ALPN comes back in the ServerHello: selected when offered, null when declined', async () => {
  const yes = await roundTrip({ alpn: 'http/1.1' });
  assert.equal(yes.tls.info.alpnProtocol, 'http/1.1');
  assertClean(yes.summary);
  const no = await roundTrip({ alpn: null });
  assert.equal(no.tls.info.alpnProtocol, null);
  assertClean(no.summary);
});

test('a server declining extended master secret is accepted, and the fact is visible', async () => {
  // renegotiationInfo:false too: a legacy server sending neither extension must still work.
  const { tls, echoed, summary } = await roundTrip({ ems: false, renegotiationInfo: false });
  assert.equal(tls.info.extendedMasterSecret, false, 'the downgrade must not be hidden');
  eq(echoed, utf8('ping over TLS 1.2'));
  assertClean(summary);
});

test('CertificateRequest is answered with an empty Certificate before ClientKeyExchange', async () => {
  const { tls, summary } = await roundTrip({ requestCertificate: true });
  assert.equal(tls.info.certificateRequested, true);
  assert.deepEqual(summary.clientMessageTypes, [1, 11, 16, 20], 'Certificate, then CKE, then Finished');
  assert.equal(summary.clientCertificateListLength, 0, 'empty certificate_list (RFC 5246 s7.4.6)');
  assertClean(summary);
});

test('the whole server flight packed into one record parses identically', async () => {
  const { echoed, summary } = await roundTrip({ packing: 'single' });
  eq(echoed, utf8('ping over TLS 1.2'));
  assertClean(summary);
});

test('the server flight split into 5-byte records (messages span records) parses identically', async () => {
  const { echoed, summary } = await roundTrip({ packing: 'split', splitSize: 5 });
  eq(echoed, utf8('ping over TLS 1.2'));
  assertClean(summary);
});

test('application data larger than one record fragments and reassembles both ways', async () => {
  const payload = pattern(50000); // 4 records client-side, echoed per record by the server
  const { echoed, summary } = await roundTrip({}, {}, payload);
  eq(echoed, payload);
  eq(summary.appDataReceived, payload);
  assertClean(summary);
});

test('a server explicit nonce that is not the sequence number still decrypts', async () => {
  // RFC 5288 only requires the explicit nonce to be unique; the replay protection lives in the
  // AAD sequence number. A client that wrongly used the wire nonce as the AAD counter would
  // fail here and only here.
  const { echoed, summary } = await roundTrip({
    explicitNonceXor: Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x01),
  });
  eq(echoed, utf8('ping over TLS 1.2'));
  assertClean(summary);
});

test('injected deps make the client wire image byte-for-byte reproducible', async () => {
  const fixedPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
  );
  const fixedEcdhe = makeEcdhe(GROUP.secp256r1);
  const identity = serverIdentity('rsa');
  const run = async () => {
    const { a, b } = duplexPair();
    const sent = [];
    const tap = new TransformStream({
      transform(chunk, ctrl) {
        sent.push(chunk.slice());
        ctrl.enqueue(chunk);
      },
    });
    // The pipe may end by tap close (client done) or by server-side cancel — a benign race, so
    // the rejection is absorbed at creation. The capture happens in the tap, before the pipe.
    const pipe = tap.readable.pipeTo(a.writable).catch(() => {});
    const server = startServer12(b, {
      identity,
      cipher: CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      sigScheme: SIG_SCHEME.rsa_pkcs1_sha256, // deterministic, unlike PSS and ECDSA
      group: GROUP.secp256r1,
      ecdhe: fixedEcdhe,
      serverRandom: new Uint8Array(32).fill(0x5c),
      sessionId: new Uint8Array(32).fill(0x3d),
      alpn: 'http/1.1',
    });
    let s = 1;
    const deps = {
      randomBytes: (n) => Uint8Array.from({ length: n }, () => (s = (s * 33 + 7) & 0xff)),
      generateKeyPair: async () => fixedPair,
    };
    const tls = await handshakeTls12({
      transport: { readable: a.readable, writable: tap.writable },
      hostname: HOST,
      verifyPeer: trust(identity),
      deps,
    });
    const echoedP = collect(tls.readable);
    const w = tls.writable.getWriter();
    await w.write(utf8('deterministic'));
    await w.close();
    await echoedP;
    const summary = await server.done;
    assertClean(summary);
    await pipe;
    return toHex(concat(sent));
  };
  const one = await run();
  const two = await run();
  assert.ok(one.length > 400, 'the capture actually contains the handshake');
  assert.equal(one, two, 'every byte the client emits, handshake and data, is reproducible');
});

// ================================================================ version pinning

test('handshakeTls12 pins the offer to [TLS 1.2] even when options.versions asks for more', async () => {
  // The armour asserted by "the ClientHello is strictly TLS 1.2" above must not be removable
  // through an options passthrough: a hello that grew supported_versions and key_share would
  // change which downgrade guards apply without any caller choosing that.
  const { tls, summary } = await roundTrip({}, { versions: [TLS13, TLS12] });
  assert.equal(tls.info.version, TLS12);
  assert.equal(summary.clientHello.hasSupportedVersions, false,
    'the single-version entry point cannot be widened through options');
  assert.equal(summary.clientHello.hasKeyShare, false);
  assertClean(summary);
});

test('connectTls with versions [TLS12] is byte-for-byte this driver', async () => {
  // The strongest form of "an explicit [TLS12] still behaves exactly as handshakeTls12": with
  // every random input pinned (PKCS#1 signing is deterministic; ECDHE pairs and randoms
  // injected on both sides), the two entries must emit the identical wire image.
  const fixedPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
  );
  const fixedEcdhe = makeEcdhe(GROUP.secp256r1);
  const identity = serverIdentity('rsa');
  const run = async (handshake) => {
    const { a, b } = duplexPair();
    const sent = [];
    const tap = new TransformStream({
      transform(chunk, ctrl) {
        sent.push(chunk.slice());
        ctrl.enqueue(chunk);
      },
    });
    const pipe = tap.readable.pipeTo(a.writable).catch(() => {});
    const server = startServer12(b, {
      identity,
      cipher: CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      sigScheme: SIG_SCHEME.rsa_pkcs1_sha256,
      group: GROUP.secp256r1,
      ecdhe: fixedEcdhe,
      serverRandom: new Uint8Array(32).fill(0x21),
      sessionId: new Uint8Array(32).fill(0x42),
    });
    let s = 9;
    const deps = {
      randomBytes: (n) => Uint8Array.from({ length: n }, () => (s = (s * 33 + 7) & 0xff)),
      generateKeyPair: async () => fixedPair,
    };
    const tls = await handshake({
      transport: { readable: a.readable, writable: tap.writable },
      hostname: HOST,
      verifyPeer: trust(identity),
      deps,
    });
    const echoedP = collect(tls.readable);
    const w = tls.writable.getWriter();
    await w.write(utf8('one hello either way'));
    await w.close();
    await echoedP;
    const summary = await server.done;
    assertClean(summary);
    await pipe;
    return toHex(concat(sent));
  };
  const viaDriver = await run(handshakeTls12);
  const viaConnect = await run((args) => connectTls({ ...args, options: { versions: [TLS12] } }));
  assert.equal(viaConnect, viaDriver,
    'requesting [TLS12] explicitly produces the identical wire image');
});

// ================================================================ the DER signature bridge

test('ecdsaDerToRaw: fixed vectors, sign-byte stripping, and a WebCrypto round trip', async () => {
  // Minimal hand-built Ecdsa-Sig-Value: r=1, s=2.
  const tiny = Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02);
  const raw = ecdsaDerToRaw(tiny, 32);
  assert.equal(raw.byteLength, 64);
  assert.equal(raw[31], 1);
  assert.equal(raw[63], 2);
  assert.ok(raw.subarray(0, 31).every((b) => b === 0));

  // r needing a DER sign byte (0x00 0x80): the pad must be stripped, not counted.
  const signByte = Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01);
  const raw2 = ecdsaDerToRaw(signByte, 32);
  assert.equal(raw2[31], 0x80);

  // Real signatures from node (DER) must verify under WebCrypto (P1363) after conversion.
  for (const [curve, webCurve, hash, orderLen] of [
    ['prime256v1', 'P-256', 'SHA-256', 32],
    ['secp521r1', 'P-521', 'SHA-512', 66], // long-form SEQUENCE length
  ]) {
    const kp = generateKeyPairSync('ec', { namedCurve: curve });
    const content = utf8(`content signed on ${curve}`);
    const der = new Uint8Array(nodeSign(hash.toLowerCase().replace('-', ''), Buffer.from(content), kp.privateKey));
    const spki = new Uint8Array(kp.publicKey.export({ type: 'spki', format: 'der' }));
    const key = await crypto.subtle.importKey(
      'spki', spki, { name: 'ECDSA', namedCurve: webCurve }, false, ['verify'],
    );
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash }, key, ecdsaDerToRaw(der, orderLen), content,
    );
    assert.equal(ok, true, `${curve} DER signature verifies after conversion`);
  }
});

test('ecdsaDerToRaw fails closed on every malformed shape', async () => {
  const cases = [
    ['not a SEQUENCE', Uint8Array.of(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)],
    ['length disagrees', Uint8Array.of(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)],
    ['trailing bytes', Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00)],
    ['non-minimal INTEGER', Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02)],
    ['negative INTEGER', Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x02)],
    ['empty INTEGER', Uint8Array.of(0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x02)],
    ['not an INTEGER', Uint8Array.of(0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x02)],
    ['truncated', Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01)],
    ['non-minimal long form', Uint8Array.of(0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02)],
    ['oversize r', concat([
      Uint8Array.of(0x30, 0x26, 0x02, 0x21, 0x01), new Uint8Array(32), Uint8Array.of(0x02, 0x01, 0x02),
    ])],
    ['empty input', new Uint8Array(0)],
  ];
  for (const [name, der] of cases) {
    let err;
    try {
      ecdsaDerToRaw(der, 32);
    } catch (e) {
      err = e;
    }
    assert.ok(err, `${name}: expected a throw`);
    assert.equal(err.code, codes.TLS_HANDSHAKE, `${name}: ${err.message}`);
    assert.match(err.message, /malformed DER/, name);
  }
});

// ================================================================ trust comes first

test('verifyPeer rejection aborts before any key material or data leaves the client', async () => {
  const r = rig({});
  await rejectsWithCode(
    () => r.handshake({}, async () => {
      throw new CertificateError(codes.CERT_UNTRUSTED_ROOT, 'no path to a trusted root (stub)');
    }),
    codes.CERT_UNTRUSTED_ROOT,
  );
  const summary = await r.server.done;
  // No duplex was ever returned, so no application data could become readable; the server's
  // view proves the stronger fact that nothing after ClientHello was ever sent — no
  // ClientKeyExchange, no Finished, and certainly no data.
  assert.deepEqual(summary.clientMessageTypes, [1], 'the server saw only the ClientHello');
  assert.equal(summary.clientFinishedVerified, false);
  assert.equal(summary.appDataReceived.byteLength, 0);
  // The abort path still told the peer why we hung up: fatal internal_error (80), best effort.
  assert.match(summary.error.message, /fatal alert 80/);
});

test('a missing verifyPeer, or one resolving without an SPKI, is refused', async () => {
  await rejectsWithCode(
    () => handshakeTls12({ transport: duplexPair().a, hostname: HOST }),
    codes.CONFIG_INVALID, /verifyPeer/,
  );
  const r = rig({});
  await rejectsWithCode(() => r.handshake({}, async () => ({})), codes.CONFIG_INVALID, /spkiDer/);
  await r.server.done;
});

// ================================================================ ServerKeyExchange attacks

test('a tampered ServerKeyExchange signature is refused (RSA and ECDSA forms)', async () => {
  {
    const r = rig({ identity: serverIdentity('rsa'), tamperSignature: true });
    await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /does not verify/);
    await r.server.done;
  }
  {
    // Flipping a bit in the s value keeps the DER valid, so this exercises the verify itself.
    const r = rig({ identity: serverIdentity('ec-p256'), tamperSignature: true });
    await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /does not verify/);
    await r.server.done;
  }
});

test('a ServerKeyExchange signed by a key other than the certificate is refused', async () => {
  // The MITM shape: present the real certificate, sign the ephemeral key with your own key.
  const r = rig({ identity: serverIdentity('rsa'), signWith: makeKeys('rsa').privateKey });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /does not verify/);
  await r.server.done;
});

test('a server omitting ServerKeyExchange is refused, naming the suite and the reason', async () => {
  const r = rig({ omitServerKeyExchange: true });
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE,
    /omitted ServerKeyExchange/);
  assert.match(err.message, /TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256/);
  assert.match(err.message, /forward secrecy/);
  assert.match(err.message, /static-RSA key transport is deliberately not implemented/);
  assert.equal(err.detail.cipherSuite, CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
  await r.server.done;
});

test('an explicit-curve ServerKeyExchange is refused', async () => {
  const r = rig({ explicitCurve: true });
  await rejectsWithCode(() => r.handshake(), codes.TLS_GROUP_UNSUPPORTED, /named_curve/);
  await r.server.done;
});

test('a ServerKeyExchange group outside our supported_groups offer is refused', async () => {
  const r = rig({ group: GROUP.x25519 });
  await rejectsWithCode(
    () => r.handshake({ groups: [GROUP.secp256r1] }),
    codes.TLS_HANDSHAKE, /not offered in supported_groups/,
  );
  await r.server.done;
});

test('a signature scheme we never offered is refused before verification', async () => {
  const r = rig({ identity: serverIdentity('rsa'), sigScheme: 0x0809 }); // rsa_pss_pss_sha256
  await rejectsWithCode(() => r.handshake(), codes.TLS_SIGALG_UNSUPPORTED, /not offered/);
  await r.server.done;
});

test('a signature whose family contradicts the suite (ECDSA suite, RSA signature) is refused', async () => {
  // The SKX signature does not cover the ServerHello, so suite/signature agreement is a check
  // the client must make itself.
  const r = rig({
    identity: serverIdentity('rsa'),
    selectCipher: CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    sigScheme: SIG_SCHEME.rsa_pss_rsae_sha256,
  });
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /authenticates with ecdsa/);
  assert.match(err.message, /rsa_pss_rsae_sha256/);
  await r.server.done;
});

// ================================================================ negotiation attacks

test('a suite we never offered is refused', async () => {
  const r = rig({ selectCipher: 0x009d }); // TLS_RSA_WITH_AES_256_GCM_SHA384
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_CIPHER_UNSUPPORTED, /0x009d/);
  assert.match(err.message, /not offered/);
  await r.server.done;
});

test('a CBC suite is refused with the Lucky13 explanation', async () => {
  const r = rig({ selectCipher: 0xc027 }); // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_CIPHER_UNSUPPORTED, /0xc027/);
  assert.match(err.message, /CBC/);
  assert.match(err.message, /Lucky13/);
  await r.server.done;
});

test('a ServerHello claiming TLS 1.1 is refused', async () => {
  const r = rig({ claimVersion: 0x0302 });
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_VERSION_UNSUPPORTED, /TLS 1\.1/);
  assert.match(err.message, /not offered/);
  await r.server.done;
});

test('a TLS 1.2 ServerHello carrying the HelloRetryRequest random is refused', async () => {
  const r = rig({ serverRandom: HELLO_RETRY_REQUEST_RANDOM });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /HelloRetryRequest sentinel/);
  await r.server.done;
});

test('a server echoing our session id (abbreviated handshake) is refused', async () => {
  const r = rig({ sessionId: 'echo' });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /abbreviated/);
  await r.server.done;
});

test('a non-empty renegotiation_info is refused', async () => {
  const r = rig({ renegotiationInfoBody: Uint8Array.of(2, 0xaa, 0xbb) });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /renegotiation/);
  await r.server.done;
});

test('an extension we never offered coming back in ServerHello is refused', async () => {
  const r = rig({ includeUnofferedExtension: true }); // session_ticket
  await rejectsWithCode(() => r.handshake(), codes.TLS_EXTENSION_UNSUPPORTED, /0x0023/);
  await r.server.done;
});

test('extended_master_secret with a non-empty body is refused', async () => {
  const r = rig({ emsBody: Uint8Array.of(1) });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /extended_master_secret/);
  await r.server.done;
});

// ================================================================ flight-order attacks

test('HelloRequest mid-handshake is refused as renegotiation, not obeyed', async () => {
  const r = rig({ helloRequest: 'before-server-hello' });
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /renegotiation is refused/);
  assert.match(err.message, /CVE-2009-3555/);
  await r.server.done;
});

test('HelloRequest after the handshake is refused by the record layer', async () => {
  const r = rig({ helloRequest: 'after-handshake' });
  const tls = await r.handshake();
  await rejectsWithCode(() => collect(tls.readable), codes.TLS_HANDSHAKE,
    /post-handshake message type 0/);
  await r.server.done;
});

test('an out-of-order server flight is refused, naming got and expected', async () => {
  const r = rig({ outOfOrder: true }); // ServerKeyExchange before Certificate
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE,
    /where Certificate was expected/);
  assert.equal(err.detail.got, 12);
  await r.server.done;
});

test('a wrong server Finished is refused', async () => {
  const r = rig({ wrongFinished: true });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /verify_data does not match/);
  await r.server.done;
});

test('a Finished with no ChangeCipherSpec before it is refused', async () => {
  const r = rig({ skipCcs: true });
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE,
    /where its ChangeCipherSpec was expected/);
  assert.equal(err.detail.got, 20);
  await r.server.done;
});

test('a fatal alert mid-handshake surfaces by name', async () => {
  const r = rig({ fatalAlertAfterServerHello: 40 });
  const err = await rejectsWithCode(() => r.handshake(), codes.TLS_ALERT, /handshake_failure/);
  assert.equal(err.detail.description, 40);
  await r.server.done;
});

test('a transport closed mid-flight is a truncation error, never a clean end', async () => {
  const r = rig({ closeAfterServerHello: true });
  await rejectsWithCode(() => r.handshake(), codes.TLS_TRUNCATED);
  await r.server.done;
});

test('an empty certificate_list is a chain error', async () => {
  const r = rig({ emptyCertList: true });
  await rejectsWithCode(() => r.handshake(), codes.CERT_CHAIN_INCOMPLETE);
  await r.server.done;
});

test('a non-empty ServerHelloDone body is refused', async () => {
  const r = rig({ doneBody: Uint8Array.of(0) });
  await rejectsWithCode(() => r.handshake(), codes.TLS_HANDSHAKE, /ServerHelloDone/);
  await r.server.done;
});

// ================================================================ the server is honest too

test('the test server genuinely verifies the client Finished (tampered transcript is caught)', async () => {
  // Flip one byte of the client's session id in flight. Without extended master secret the two
  // sides still derive identical keys (the randoms are untouched), so the client's Finished
  // decrypts fine on the server — and then fails the verify_data comparison, which is the only
  // check that can catch it. A server that skipped real verification would sail through and
  // silently certify a broken client.
  const identity = serverIdentity('ec-p256');
  const { a, b } = duplexPair();
  let first = true;
  const tap = new TransformStream({
    transform(chunk, ctrl) {
      if (first) {
        first = false;
        const x = chunk.slice();
        x[50] ^= 0x01; // inside ClientHello.session_id (record 5 + header 4 + 2 + 32 + 1 = 44..75)
        ctrl.enqueue(x);
      } else {
        ctrl.enqueue(chunk);
      }
    },
  });
  const pipe = tap.readable.pipeTo(a.writable).catch(() => {});
  const server = startServer12(b, { identity, ems: false });
  await rejectsWithCode(
    () => handshakeTls12({
      transport: { readable: a.readable, writable: tap.writable },
      hostname: HOST,
      verifyPeer: trust(identity),
    }),
    codes.TLS_ALERT, /decrypt_error/,
  );
  const summary = await server.done;
  assert.equal(summary.clientFinishedVerified, false);
  assert.match(summary.error.message, /verify_data mismatch/);
  await pipe;
});

// ================================================================ regression guards
// Both of these were genuine bugs in src/ when this driver was written, found by building an
// independent server rather than by reading the code. They are fixed now; the assertions stay as
// permanent guards, because each would otherwise fail only against a real peer.

test('verifyHandshakeSignature accepts the DER ECDSA form real peers send', async () => {
    const kp = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const spki = new Uint8Array(kp.publicKey.export({ type: 'spki', format: 'der' }));
    const content = utf8('TLS 1.3, server CertificateVerify — stand-in content');
    const derSig = new Uint8Array(nodeSign('sha256', Buffer.from(content), kp.privateKey));
    assert.equal(
      await verifyHandshakeSignature({
        scheme: SIG_SCHEME.ecdsa_secp256r1_sha256, spki, signature: derSig, content,
      }),
      true,
      'a DER ECDSA signature from a real peer must verify',
    );
  });

test('parseServerHello accepts a legal extensionless TLS 1.2 ServerHello', () => {
    const body = new Builder()
      .u16(0x0303)
      .push(new Uint8Array(32).fill(9))
      .vector(1, new Uint8Array(0))
      .u16(CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
      .u8(0)
      .build(); // ends at compression_method: no extensions block at all
    const sh = parseServerHello(body);
    assert.equal(sh.cipherSuite, CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  });
