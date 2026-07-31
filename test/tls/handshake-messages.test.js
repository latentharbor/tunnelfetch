// Negotiation is where a TLS client is attacked, so every guard gets an adversarial test:
// a server that lies about the version, echoes the wrong session id, picks a suite we never
// offered, or plants the downgrade sentinel must be refused, not accommodated.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyShare,
  deriveSharedSecret,
  buildClientHello,
  parseServerHello,
  negotiateVersion,
  negotiateCipher,
  checkSessionIdEcho,
  selectServerKeyShare,
  parseHelloRetryRequest,
  parseCertificate13,
  parseCertificate12,
  parseCertificateVerify,
  certificateVerifyContent,
  verifyHandshakeSignature,
  parseServerKeyExchangeEcdhe,
  serverKeyExchangeContent,
  checkFinished,
  checkAlpn,
} from '../../src/tls/handshake-messages.js';
import {
  CIPHER,
  DOWNGRADE_SENTINEL_12,
  EXTENSION,
  GROUP,
  HANDSHAKE_TYPE,
  HELLO_RETRY_REQUEST_RANDOM,
  LEGACY_VERSION,
  SIG_SCHEME,
  TLS12,
  TLS13,
} from '../../src/tls/constants.js';
import { Builder, vector } from '../../src/tls/wire.js';
import { concat, fromHex, toHex, utf8 } from '../../src/util/bytes.js';
import {
  encodeAlpn,
  encodeExtensionBlock,
  encodeKeyShare,
  encodeKeyShareHrr,
  encodeSupportedVersions,
} from '../../src/tls/extensions.js';

const throwsCode = (fn, code) => {
  let err;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err, `expected a throw with code ${code}, nothing thrown`);
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err?.message}`);
  return err;
};
const rejectsCode = async (fn, code) => {
  let err;
  try {
    await fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err, `expected a rejection with code ${code}, nothing thrown`);
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err?.message}`);
  return err;
};

const SESSION_ID = new Uint8Array(32).fill(0x5a);

/** Assemble ServerHello bytes so the parser is tested against something we control exactly. */
function serverHelloBody({
  legacyVersion = LEGACY_VERSION,
  random = new Uint8Array(32).fill(0x11),
  sessionId = SESSION_ID,
  cipherSuite = CIPHER.TLS_AES_128_GCM_SHA256,
  compression = 0,
  extensions = [],
} = {}) {
  return new Builder()
    .u16(legacyVersion)
    .push(random)
    .vector(1, sessionId)
    .u16(cipherSuite)
    .u8(compression)
    .push(encodeExtensionBlock(extensions))
    .build();
}

// A ServerHello's supported_versions carries a bare uint16, not the client's length-prefixed
// list, so the client-side encoder cannot be reused here.
const serverSupportedVersions = (v) =>
  new Builder().u16(EXTENSION.supported_versions).vector(2, new Builder().u16(v).build()).build();

const tls13Extensions = (keyShareBytes) => [
  serverSupportedVersions(TLS13),
  keyShareBytes ?? encodeKeyShare([{ group: GROUP.x25519, keyExchange: new Uint8Array(32).fill(9) }]),
];

// The ServerHello key_share is a single entry, not a client-style list.
function serverKeyShareExt(group, key) {
  return new Builder().u16(EXTENSION.key_share).vector(2, new Builder().u16(group).vector(2, key).build()).build();
}

// ------------------------------------------------------------------ key shares

test('generateKeyShare produces the right public key length per group', async () => {
  for (const [group, len] of [
    [GROUP.x25519, 32],
    [GROUP.secp256r1, 65],
    [GROUP.secp384r1, 97],
    [GROUP.secp521r1, 133],
  ]) {
    const share = await generateKeyShare(group);
    assert.equal(share.group, group);
    assert.equal(share.keyExchange.byteLength, len);
  }
});

test('generateKeyShare refuses a group we do not implement', async () => {
  await rejectsCode(() => generateKeyShare(GROUP.x448), 'TLS_GROUP_UNSUPPORTED');
});

test('an injected key pair makes the share deterministic, so handshakes can be replayed', async () => {
  const fixed = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const a = await generateKeyShare(GROUP.x25519, { generateKeyPair: async () => fixed });
  const b = await generateKeyShare(GROUP.x25519, { generateKeyPair: async () => fixed });
  assert.equal(toHex(a.keyExchange), toHex(b.keyExchange));
});

test('deriveSharedSecret agrees between two peers', async () => {
  const client = await generateKeyShare(GROUP.x25519);
  const server = await generateKeyShare(GROUP.x25519);
  const s1 = await deriveSharedSecret(GROUP.x25519, client.privateKey, server.keyExchange);
  const s2 = await deriveSharedSecret(GROUP.x25519, server.privateKey, client.keyExchange);
  assert.equal(toHex(s1), toHex(s2));
  assert.equal(s1.byteLength, 32);
});

test('deriveSharedSecret agrees on every EC group too', async () => {
  for (const [group, len] of [
    [GROUP.secp256r1, 32],
    [GROUP.secp384r1, 48],
    [GROUP.secp521r1, 66],
  ]) {
    const client = await generateKeyShare(group);
    const server = await generateKeyShare(group);
    const s1 = await deriveSharedSecret(group, client.privateKey, server.keyExchange);
    const s2 = await deriveSharedSecret(group, server.privateKey, client.keyExchange);
    assert.equal(toHex(s1), toHex(s2));
    assert.equal(s1.byteLength, len);
  }
});

test('a peer key of the wrong length is rejected before it reaches WebCrypto', async () => {
  const client = await generateKeyShare(GROUP.x25519);
  const err = await rejectsCode(
    () => deriveSharedSecret(GROUP.x25519, client.privateKey, new Uint8Array(31)),
    'TLS_HANDSHAKE',
  );
  assert.match(err.message, /31 bytes, expected 32/);
});

test('a compressed EC point is refused rather than silently mishandled', async () => {
  const client = await generateKeyShare(GROUP.secp256r1);
  const compressed = new Uint8Array(65);
  compressed[0] = 0x02;
  await rejectsCode(
    () => deriveSharedSecret(GROUP.secp256r1, client.privateKey, compressed),
    'TLS_GROUP_UNSUPPORTED',
  );
});

test('an X25519 small-order key producing an all-zero secret is rejected', async () => {
  const client = await generateKeyShare(GROUP.x25519);
  // The all-zero public key is the canonical small-order point.
  const smallOrder = new Uint8Array(32);
  const err = await rejectsCode(
    () => deriveSharedSecret(GROUP.x25519, client.privateKey, smallOrder),
    'TLS_HANDSHAKE',
  );
  assert.match(err.message, /small-order|not a valid public key/);
});

// ------------------------------------------------------------------ ClientHello

test('ClientHello has the shape a middlebox expects', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  const hello = buildClientHello({ hostname: 'host.example', keyShares: [share] });
  const m = hello.message;
  assert.equal(m[0], HANDSHAKE_TYPE.client_hello);
  const len = (m[1] << 16) | (m[2] << 8) | m[3];
  assert.equal(len, m.byteLength - 4, 'declared length must match the body');
  // legacy_version is always 0x0303 on the wire, whatever we actually negotiate
  assert.equal(toHex(m.subarray(4, 6)), '0303');
  assert.equal(hello.clientRandom.byteLength, 32);
  assert.equal(hello.legacySessionId.byteLength, 32, 'a non-empty session id keeps middleboxes calm');
});

test('ClientHello is byte-for-byte reproducible when randomness is injected', async () => {
  const fixed = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const share = await generateKeyShare(GROUP.x25519, { generateKeyPair: async () => fixed });
  const opts = {
    hostname: 'host.example',
    keyShares: [share],
    random: new Uint8Array(32).fill(1),
    legacySessionId: new Uint8Array(32).fill(2),
  };
  assert.equal(toHex(buildClientHello(opts).message), toHex(buildClientHello(opts).message));
});

test('ClientHello omits SNI for an IP literal but still offers everything else', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  const hello = buildClientHello({ hostname: '192.0.2.10', keyShares: [share] });
  assert.equal(hello.offeredExtensions.has(EXTENSION.server_name), false);
  assert.equal(hello.offeredExtensions.has(EXTENSION.key_share), true);
  assert.equal(hello.offeredExtensions.has(EXTENSION.supported_versions), true);
});

test('a TLS 1.2 only ClientHello drops the 1.3 extensions and offers 1.2 suites', async () => {
  const hello = buildClientHello({ hostname: 'h.example', keyShares: [], versions: [TLS12] });
  assert.equal(hello.offeredExtensions.has(EXTENSION.key_share), false);
  assert.equal(hello.offeredExtensions.has(EXTENSION.supported_versions), false);
  assert.equal(hello.offeredExtensions.has(EXTENSION.extended_master_secret), true);
  assert.ok(hello.offeredCiphers.includes(CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
  assert.ok(!hello.offeredCiphers.includes(CIPHER.TLS_AES_128_GCM_SHA256));
});

test('a ClientHello with a bad random length or no suites is refused', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  throwsCode(
    () => buildClientHello({ hostname: 'h.example', keyShares: [share], random: new Uint8Array(16) }),
    'CONFIG_INVALID',
  );
  throwsCode(
    () => buildClientHello({ hostname: 'h.example', keyShares: [share], ciphers: [] }),
    'CONFIG_INVALID',
  );
});

// ------------------------------------------------------------------ ServerHello parsing

test('parseServerHello reads every field and flags HelloRetryRequest', () => {
  const sh = parseServerHello(serverHelloBody({ extensions: tls13Extensions() }));
  assert.equal(sh.legacyVersion, LEGACY_VERSION);
  assert.equal(sh.cipherSuite, CIPHER.TLS_AES_128_GCM_SHA256);
  assert.equal(sh.isHelloRetryRequest, false);

  const hrr = parseServerHello(serverHelloBody({ random: HELLO_RETRY_REQUEST_RANDOM }));
  assert.equal(hrr.isHelloRetryRequest, true);
});

test('a non-zero compression method is refused (CRIME)', () => {
  const err = throwsCode(() => parseServerHello(serverHelloBody({ compression: 1 })), 'TLS_HANDSHAKE');
  assert.match(err.message, /compression/i);
});

test('trailing bytes after a ServerHello are refused', () => {
  const body = concat([serverHelloBody(), fromHex('ff')]);
  throwsCode(() => parseServerHello(body), 'TLS_HANDSHAKE');
});

// ------------------------------------------------------------------ version negotiation

test('supported_versions selects TLS 1.3', () => {
  const sh = parseServerHello(serverHelloBody({ extensions: tls13Extensions() }));
  assert.equal(negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }), TLS13);
});

test('no supported_versions falls back to legacy_version for TLS 1.2', () => {
  const sh = parseServerHello(serverHelloBody({ cipherSuite: CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 }));
  assert.equal(negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }), TLS12);
});

test('the RFC 8446 downgrade sentinel aborts the handshake', () => {
  const random = new Uint8Array(32).fill(0x11);
  random.set(DOWNGRADE_SENTINEL_12, 24);
  const sh = parseServerHello(serverHelloBody({ random }));
  const err = throwsCode(
    () => negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }),
    'TLS_VERSION_UNSUPPORTED',
  );
  assert.match(err.message, /downgrade sentinel/);
});

test('the sentinel is irrelevant when TLS 1.3 was never offered', () => {
  const random = new Uint8Array(32).fill(0x11);
  random.set(DOWNGRADE_SENTINEL_12, 24);
  const sh = parseServerHello(serverHelloBody({ random }));
  assert.equal(negotiateVersion(sh, { offeredVersions: [TLS12] }), TLS12);
});

test('TLS 1.0 and 1.1 are refused with an error that explains why', () => {
  for (const v of [0x0301, 0x0302]) {
    const sh = parseServerHello(serverHelloBody({ legacyVersion: v }));
    const err = throwsCode(
      () => negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }),
      'TLS_VERSION_UNSUPPORTED',
    );
    assert.match(err.message, /TLS 1\.0 and 1\.1 are not implemented/);
    assert.match(err.message, /constant-time/);
  }
});

test('supported_versions selecting anything but 1.3 is a protocol violation', () => {
  const sh = parseServerHello(serverHelloBody({ extensions: [serverSupportedVersions(TLS12)] }));
  throwsCode(() => negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }), 'TLS_VERSION_UNSUPPORTED');
});

test('TLS 1.3 with a wrong legacy_version is refused', () => {
  const sh = parseServerHello(serverHelloBody({ legacyVersion: 0x0304, extensions: tls13Extensions() }));
  throwsCode(() => negotiateVersion(sh, { offeredVersions: [TLS13, TLS12] }), 'TLS_HANDSHAKE');
});

// ------------------------------------------------------------------ cipher negotiation

test('a suite we never offered is refused with an actionable message', () => {
  const sh = parseServerHello(serverHelloBody({ cipherSuite: 0xc02f, extensions: tls13Extensions() }));
  const err = throwsCode(
    () => negotiateCipher(sh, { offeredCiphers: [CIPHER.TLS_AES_128_GCM_SHA256], version: TLS13 }),
    'TLS_CIPHER_UNSUPPORTED',
  );
  assert.match(err.message, /0xc02f/);
  assert.match(err.message, /TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256/);
  assert.match(err.message, /TLS 1\.3/);
  assert.match(err.message, /Lucky13/);
});

test('crossing a 1.2 suite with 1.3 (or the reverse) is refused', () => {
  const a = parseServerHello(serverHelloBody({ cipherSuite: 0xc02f, extensions: tls13Extensions() }));
  throwsCode(() => negotiateCipher(a, { offeredCiphers: [0xc02f], version: TLS13 }), 'TLS_CIPHER_UNSUPPORTED');
  const b = parseServerHello(serverHelloBody({ cipherSuite: CIPHER.TLS_AES_128_GCM_SHA256 }));
  throwsCode(
    () => negotiateCipher(b, { offeredCiphers: [CIPHER.TLS_AES_128_GCM_SHA256], version: TLS12 }),
    'TLS_CIPHER_UNSUPPORTED',
  );
});

test('ChaCha20 selection produces a named error rather than a silent failure', () => {
  const sh = parseServerHello(serverHelloBody({ cipherSuite: 0x1303, extensions: tls13Extensions() }));
  const err = throwsCode(
    () => negotiateCipher(sh, { offeredCiphers: [CIPHER.TLS_AES_128_GCM_SHA256], version: TLS13 }),
    'TLS_CIPHER_UNSUPPORTED',
  );
  assert.match(err.message, /0x1303/);
  assert.match(err.message, /TLS_CHACHA20_POLY1305_SHA256/);
});

// ------------------------------------------------------------------ session id and key share

test('a session id the server did not echo is refused', () => {
  const sh = parseServerHello(serverHelloBody({ sessionId: new Uint8Array(32).fill(0x99) }));
  throwsCode(() => checkSessionIdEcho(sh, SESSION_ID), 'TLS_HANDSHAKE');
  const good = parseServerHello(serverHelloBody({ sessionId: SESSION_ID }));
  assert.equal(checkSessionIdEcho(good, SESSION_ID), undefined);
});

test('selectServerKeyShare matches the server choice to one of ours', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  const sh = parseServerHello(
    serverHelloBody({
      extensions: [serverSupportedVersions(TLS13), serverKeyShareExt(GROUP.x25519, new Uint8Array(32).fill(3))],
    }),
  );
  const chosen = selectServerKeyShare(sh, [share]);
  assert.equal(chosen.group, GROUP.x25519);
  assert.equal(chosen.privateKey, share.privateKey);
});

test('a key share for a group we never offered is refused', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  const sh = parseServerHello(
    serverHelloBody({
      extensions: [serverSupportedVersions(TLS13), serverKeyShareExt(GROUP.secp384r1, new Uint8Array(97).fill(4))],
    }),
  );
  throwsCode(() => selectServerKeyShare(sh, [share]), 'TLS_HANDSHAKE');
});

test('a TLS 1.3 ServerHello with no key_share is refused', () => {
  const sh = parseServerHello(serverHelloBody({ extensions: [serverSupportedVersions(TLS13)] }));
  throwsCode(() => selectServerKeyShare(sh, []), 'TLS_HANDSHAKE');
});

test('HelloRetryRequest names a group we offered, or is refused', () => {
  const hrr = parseServerHello(
    serverHelloBody({ random: HELLO_RETRY_REQUEST_RANDOM, extensions: [encodeKeyShareHrr(GROUP.secp256r1)] }),
  );
  assert.equal(parseHelloRetryRequest(hrr, { offeredGroups: [GROUP.x25519, GROUP.secp256r1] }).group, GROUP.secp256r1);
  throwsCode(() => parseHelloRetryRequest(hrr, { offeredGroups: [GROUP.x25519] }), 'TLS_HANDSHAKE');
});

// ------------------------------------------------------------------ Certificate messages

test('parseCertificate13 reads the chain and tolerates empty per-entry extensions', () => {
  const entry = (der) => new Builder().vector(3, der).vector(2, new Uint8Array(0)).build();
  const body = new Builder()
    .vector(1, new Uint8Array(0))
    .vector(3, concat([entry(fromHex('3082aa')), entry(fromHex('3082bb'))]))
    .build();
  const { chain, ocspResponse } = parseCertificate13(body);
  assert.deepEqual(chain.map(toHex), ['3082aa', '3082bb']);
  assert.equal(ocspResponse, null);
});

test('a non-empty certificate_request_context in a server Certificate is refused', () => {
  const body = new Builder().vector(1, fromHex('aa')).vector(3, new Uint8Array(0)).build();
  throwsCode(() => parseCertificate13(body), 'TLS_HANDSHAKE');
});

test('an empty certificate_list is a chain error, not an empty success', () => {
  const body = new Builder().vector(1, new Uint8Array(0)).vector(3, new Uint8Array(0)).build();
  throwsCode(() => parseCertificate13(body), 'CERT_CHAIN_INCOMPLETE');
  throwsCode(() => parseCertificate12(new Builder().vector(3, new Uint8Array(0)).build()), 'CERT_CHAIN_INCOMPLETE');
});

test('parseCertificate12 reads a bare list with no extensions', () => {
  const body = new Builder()
    .vector(3, concat([vector(3, fromHex('3082aa')), vector(3, fromHex('3082bb'))]))
    .build();
  assert.deepEqual(parseCertificate12(body).map(toHex), ['3082aa', '3082bb']);
});

test('parseCertificateVerify splits algorithm from signature', () => {
  const body = new Builder().u16(SIG_SCHEME.rsa_pss_rsae_sha256).vector(2, fromHex('deadbeef')).build();
  const cv = parseCertificateVerify(body);
  assert.equal(cv.algorithm, SIG_SCHEME.rsa_pss_rsae_sha256);
  assert.equal(toHex(cv.signature), 'deadbeef');
});

test('the CertificateVerify content follows RFC 8446 exactly', () => {
  const hash = new Uint8Array(32).fill(0xab);
  const content = certificateVerifyContent(hash, true);
  assert.equal(content.byteLength, 64 + 33 + 1 + 32);
  assert.ok(content.subarray(0, 64).every((b) => b === 0x20));
  assert.equal(new TextDecoder().decode(content.subarray(64, 97)), 'TLS 1.3, server CertificateVerify');
  assert.equal(content[97], 0);
  assert.equal(toHex(content.subarray(98)), toHex(hash));
});

// ------------------------------------------------------------------ signature verification

/**
 * WebCrypto signs ECDSA in the raw P1363 form, but TLS puts a DER Ecdsa-Sig-Value on the wire.
 * Re-encoding here is what makes this an honest test: signing and verifying with WebCrypto at both
 * ends agrees with itself while failing against every real server, which is exactly how the
 * missing conversion hid until an independently written test server exposed it.
 */
function p1363ToDer(raw) {
  const half = raw.byteLength / 2;
  const int = (v) => {
    let i = 0;
    while (i < v.byteLength - 1 && v[i] === 0) i++;
    let b = v.subarray(i);
    if (b[0] & 0x80) b = concat([Uint8Array.from([0x00]), b]);
    return concat([Uint8Array.from([0x02, b.byteLength]), b]);
  };
  const body = concat([int(raw.subarray(0, half)), int(raw.subarray(half))]);
  const header =
    body.byteLength < 0x80
      ? Uint8Array.from([0x30, body.byteLength])
      : Uint8Array.from([0x30, 0x81, body.byteLength]);
  return concat([header, body]);
}

test('a real ECDSA handshake signature verifies, and a tampered one does not', async () => {
  for (const [curve, scheme, hash] of [
    ['P-256', SIG_SCHEME.ecdsa_secp256r1_sha256, 'SHA-256'],
    ['P-384', SIG_SCHEME.ecdsa_secp384r1_sha384, 'SHA-384'],
    ['P-521', SIG_SCHEME.ecdsa_secp521r1_sha512, 'SHA-512'],
  ]) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, [
      'sign',
      'verify',
    ]);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
    const content = certificateVerifyContent(new Uint8Array(32).fill(7));
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: 'ECDSA', hash }, kp.privateKey, content),
    );
    const signature = p1363ToDer(raw);
    assert.equal(
      await verifyHandshakeSignature({ scheme, spki, signature, content }),
      true,
      `${curve} DER signature must verify`,
    );

    // Tampering with the signature value must fail the verification, not the DER parse.
    const tampered = raw.slice();
    tampered[tampered.byteLength - 1] ^= 0xff;
    await rejectsCode(
      () => verifyHandshakeSignature({ scheme, spki, signature: p1363ToDer(tampered), content }),
      'TLS_HANDSHAKE',
    );
  }
});

test('a P1363 signature offered where DER is required is refused, not silently accepted', async () => {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const content = certificateVerifyContent(new Uint8Array(32).fill(7));
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, content),
  );
  const err = await rejectsCode(
    () =>
      verifyHandshakeSignature({
        scheme: SIG_SCHEME.ecdsa_secp256r1_sha256,
        spki,
        signature: raw,
        content,
      }),
    'TLS_HANDSHAKE',
  );
  assert.match(err.message, /ECDSA-Sig-Value|malformed DER/i);
});

test('an RSA-PSS handshake signature verifies with the scheme salt length', async () => {
  const kp = await crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const content = certificateVerifyContent(new Uint8Array(32).fill(3));
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, kp.privateKey, content),
  );
  assert.equal(
    await verifyHandshakeSignature({ scheme: SIG_SCHEME.rsa_pss_rsae_sha256, spki, signature, content }),
    true,
  );
});

test('an unimplemented signature scheme names itself and what we offered', async () => {
  const err = await rejectsCode(
    () =>
      verifyHandshakeSignature({
        scheme: SIG_SCHEME.ed448,
        spki: new Uint8Array(10),
        signature: new Uint8Array(10),
        content: new Uint8Array(10),
      }),
    'TLS_SIGALG_UNSUPPORTED',
  );
  assert.match(err.message, /0x0808/);
  assert.match(err.message, /ed448/);
  assert.match(err.message, /offered/);
});

test('SHA-1 handshake signatures are not accepted even if a server insists', async () => {
  await rejectsCode(
    () =>
      verifyHandshakeSignature({
        scheme: SIG_SCHEME.rsa_pkcs1_sha1,
        spki: new Uint8Array(10),
        signature: new Uint8Array(10),
        content: new Uint8Array(10),
      }),
    'TLS_SIGALG_UNSUPPORTED',
  );
});

// ------------------------------------------------------------------ TLS 1.2 ServerKeyExchange

test('ServerKeyExchange parses named-curve ECDHE and reconstructs the signed blob', () => {
  const pub = new Uint8Array(65).fill(4);
  pub[0] = 0x04;
  const body = new Builder()
    .u8(3)
    .u16(GROUP.secp256r1)
    .vector(1, pub)
    .u16(SIG_SCHEME.rsa_pss_rsae_sha256)
    .vector(2, fromHex('aabbcc'))
    .build();
  const ske = parseServerKeyExchangeEcdhe(body);
  assert.equal(ske.group, GROUP.secp256r1);
  assert.equal(ske.publicKey.byteLength, 65);
  assert.equal(toHex(ske.signature), 'aabbcc');
  // signed params are curve_type + named_curve + length byte + point
  assert.equal(ske.signedParams.byteLength, 1 + 2 + 1 + 65);
  assert.equal(ske.signedParams[0], 3);
});

test('explicit-curve ServerKeyExchange is refused', () => {
  const body = new Builder().u8(1).u16(0).vector(1, new Uint8Array(1)).u16(0).vector(2, new Uint8Array(1)).build();
  throwsCode(() => parseServerKeyExchangeEcdhe(body), 'TLS_GROUP_UNSUPPORTED');
});

test('the TLS 1.2 signed content is the two randoms then the params', () => {
  const cr = new Uint8Array(32).fill(1);
  const sr = new Uint8Array(32).fill(2);
  const params = fromHex('030017' + '41' + '04'.repeat(1));
  const content = serverKeyExchangeContent(cr, sr, params);
  assert.equal(content.byteLength, 64 + params.byteLength);
  assert.equal(toHex(content.subarray(0, 32)), toHex(cr));
  assert.equal(toHex(content.subarray(32, 64)), toHex(sr));
});

// ------------------------------------------------------------------ Finished and ALPN

test('checkFinished accepts a match and refuses a mismatch', () => {
  const a = new Uint8Array(32).fill(9);
  assert.equal(checkFinished(a, new Uint8Array(32).fill(9)), true);
  throwsCode(() => checkFinished(a, new Uint8Array(32).fill(8)), 'TLS_HANDSHAKE');
  throwsCode(() => checkFinished(a, new Uint8Array(31).fill(9)), 'TLS_HANDSHAKE');
});

test('ALPN: absent is fine, matching is returned, unoffered is refused', () => {
  const offered = ['http/1.1'];
  assert.equal(checkAlpn(new Map(), offered, 'EncryptedExtensions'), null);

  const ok = new Map([[EXTENSION.alpn, encodeAlpn(['http/1.1']).subarray(4)]]);
  assert.equal(checkAlpn(ok, offered, 'EncryptedExtensions'), 'http/1.1');

  const h2 = new Map([[EXTENSION.alpn, encodeAlpn(['h2']).subarray(4)]]);
  const err = throwsCode(() => checkAlpn(h2, offered, 'EncryptedExtensions'), 'TLS_ALPN');
  assert.match(err.message, /"h2"/);
  assert.match(err.message, /not offered/);
});
