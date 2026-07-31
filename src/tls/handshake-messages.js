// Handshake message encoding, decoding, and the negotiation decisions that follow from them.
//
// Deliberately free of any dependency on the record layer: these are byte-level functions over
// complete handshake message bodies, which makes the whole of negotiation — including every
// downgrade guard — testable from fixed vectors with no I/O.
//
// All randomness and key generation is injectable. That is not a testing nicety: without it a
// TLS handshake cannot be replayed, and a transport that cannot be replayed cannot be tested
// offline at all.

import { TlsError, TlsUnsupportedError, CertificateError, codes, hex16 } from '../errors.js';
import { concat, equal, timingSafeEqual, utf8 } from '../util/bytes.js';
import { Builder, Cursor, vector, handshakeMessage } from './wire.js';
// der.js is a strict ASN.1 reader with no trust policy in it; the signature-format conversion
// lives there so the certificate path builder and this file cannot drift apart.
import { ecdsaDerToRaw } from '../trust/der.js';
import {
  CIPHER_NAME,
  CIPHER_PARAMS,
  DOWNGRADE_SENTINEL_11,
  DOWNGRADE_SENTINEL_12,
  EXTENSION,
  GROUP_PARAMS,
  HANDSHAKE_TYPE,
  HELLO_RETRY_REQUEST_RANDOM,
  LEGACY_VERSION,
  SIG_SCHEME_PARAMS,
  TLS12,
  TLS12_CIPHERS,
  TLS13,
  TLS13_CIPHERS,
  SUPPORTED_GROUPS,
  SUPPORTED_SIG_SCHEMES,
  ALPN_HTTP11,
} from './constants.js';
import {
  decodeAlpn,
  decodeExtensionBlock,
  decodeKeyShareEntry,
  decodeKeyShareHrr,
  decodeSelectedVersion,
  describeSigScheme,
  describeVersion,
  encodeAlpn,
  encodeEcPointFormats,
  encodeExtendedMasterSecret,
  encodeExtensionBlock,
  encodeKeyShare,
  encodePskKeyExchangeModes,
  encodeRenegotiationInfo,
  encodeServerName,
  encodeSignatureAlgorithms,
  encodeSupportedGroups,
  encodeSupportedVersions,
  requireSupportedGroup,
} from './extensions.js';

const defaultRandom = (n) => crypto.getRandomValues(new Uint8Array(n));

// ------------------------------------------------------------------ key shares

/**
 * Generate an ephemeral key share for one group.
 * `generateKeyPair` is injectable so a recorded handshake can be replayed with the exact private
 * key that produced it.
 */
export async function generateKeyShare(group, { generateKeyPair } = {}) {
  const params = requireSupportedGroup(group, 'ClientHello');
  const gen =
    generateKeyPair ??
    ((algorithm) => crypto.subtle.generateKey(algorithm, false, ['deriveBits']));
  const pair = await gen(params.algorithm, group);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  if (raw.byteLength !== params.publicLen) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `generated a ${raw.byteLength}-byte public key for group ${hex16(group)}, expected ${params.publicLen}`,
    );
  }
  return { group, keyExchange: raw, privateKey: pair.privateKey };
}

/**
 * ECDH/X25519 shared secret. The peer's key is imported in raw form, which is where a malformed
 * point is caught: WebCrypto rejects a point that is not on the curve, so we do not have to
 * implement that check ourselves — but a wrong LENGTH would be accepted by some implementations,
 * so it is checked here first.
 */
export async function deriveSharedSecret(group, privateKey, peerKey) {
  const params = requireSupportedGroup(group, 'ServerHello');
  if (peerKey.byteLength !== params.publicLen) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server key_share for group ${hex16(group)} is ${peerKey.byteLength} bytes, expected ${params.publicLen}`,
      { group, got: peerKey.byteLength, expected: params.publicLen },
    );
  }
  if (params.kind === 'ec' && peerKey[0] !== 0x04) {
    throw new TlsUnsupportedError(
      codes.TLS_GROUP_UNSUPPORTED,
      `server sent a compressed or invalid EC point (first byte 0x${peerKey[0].toString(16)}) ` +
        `for group ${hex16(group)}; only uncompressed points are supported`,
      { group, firstByte: peerKey[0] },
    );
  }
  let peer;
  try {
    peer = await crypto.subtle.importKey('raw', peerKey, params.algorithm, false, []);
  } catch (cause) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server key_share for group ${hex16(group)} is not a valid public key: ${cause?.message}`,
      { group },
    );
  }
  const bits = params.kind === 'x25519' ? params.secretLen * 8 : params.secretBits;
  let shared;
  try {
    shared = new Uint8Array(
      await crypto.subtle.deriveBits({ ...params.algorithm, public: peer }, privateKey, bits),
    );
  } catch (cause) {
    // WebCrypto rejects small-order X25519 peers itself, with an OperationError carrying no
    // useful text. Letting that escape untyped would put a bare DOMException in front of a
    // caller who is catching our error taxonomy, so it is translated here.
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `key agreement failed for group ${hex16(group)}: ${cause?.message ?? cause}. ` +
        'This usually means the server sent a degenerate or small-order public key.',
      { group },
    );
  }
  // RFC 7748 s6.1: an all-zero X25519 output means a small-order peer key. Reject.
  if (params.kind === 'x25519' && shared.every((b) => b === 0)) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'X25519 shared secret is all zeroes, indicating a small-order server key_share',
    );
  }
  return shared;
}

// ------------------------------------------------------------------ ClientHello

/**
 * Build a ClientHello. Returns the framed handshake message plus the metadata the rest of the
 * handshake needs to police the server's answer.
 */
export function buildClientHello({
  hostname,
  keyShares,
  random,
  legacySessionId,
  ciphers,
  groups = SUPPORTED_GROUPS,
  sigSchemes = SUPPORTED_SIG_SCHEMES,
  alpn = [ALPN_HTTP11],
  versions = [TLS13, TLS12],
  extraExtensions = [],
  randomBytes = defaultRandom,
}) {
  const clientRandom = random ?? randomBytes(32);
  if (clientRandom.byteLength !== 32) {
    throw new TlsError(codes.CONFIG_INVALID, `ClientHello.random must be 32 bytes, got ${clientRandom.byteLength}`);
  }
  // RFC 8446 s4.1.2: a non-empty legacy_session_id makes middleboxes treat the flow as a
  // resumed TLS 1.2 session and leave it alone. 32 random bytes is what every browser sends.
  const sessionId = legacySessionId ?? randomBytes(32);

  const offersTls13 = versions.includes(TLS13);
  const offersTls12 = versions.includes(TLS12);
  const suites = ciphers ?? [
    ...(offersTls13 ? TLS13_CIPHERS : []),
    ...(offersTls12 ? TLS12_CIPHERS : []),
  ];
  if (suites.length === 0) {
    throw new TlsError(codes.CONFIG_INVALID, 'ClientHello would offer no cipher suites');
  }

  const suiteBytes = new Builder();
  for (const s of suites) suiteBytes.u16(s);

  const extensionParts = [
    encodeServerName(hostname),
    encodeSupportedGroups(groups),
    encodeSignatureAlgorithms(sigSchemes),
    alpn.length ? encodeAlpn(alpn) : null,
    offersTls13 ? encodeSupportedVersions(versions) : null,
    offersTls13 ? encodeKeyShare(keyShares.map(({ group, keyExchange }) => ({ group, keyExchange }))) : null,
    offersTls13 ? encodePskKeyExchangeModes() : null,
    offersTls12 ? encodeExtendedMasterSecret() : null,
    offersTls12 ? encodeEcPointFormats() : null,
    offersTls12 ? encodeRenegotiationInfo() : null,
    // A HelloRetryRequest cookie arrives here, already encoded, and must go out verbatim.
    ...extraExtensions,
  ];
  const offered = new Set();
  for (const part of extensionParts) {
    if (part) offered.add((part[0] << 8) | part[1]);
  }

  const body = new Builder()
    .u16(LEGACY_VERSION)
    .push(clientRandom)
    .vector(1, sessionId)
    .vector(2, suiteBytes.build())
    .vector(1, Uint8Array.from([0])) // legacy_compression_methods: null only
    .push(encodeExtensionBlock(extensionParts))
    .build();

  return {
    message: handshakeMessage(HANDSHAKE_TYPE.client_hello, body),
    clientRandom,
    legacySessionId: sessionId,
    offeredCiphers: suites,
    offeredGroups: groups,
    offeredSigSchemes: sigSchemes,
    offeredExtensions: offered,
    offeredAlpn: alpn,
  };
}

// ------------------------------------------------------------------ ServerHello

export function parseServerHello(body) {
  const c = new Cursor(body, 'ServerHello');
  const legacyVersion = c.u16('legacy_version');
  const random = c.take(32, 'random');
  const legacySessionIdEcho = c.vector(1, 'legacy_session_id_echo');
  const cipherSuite = c.u16('cipher_suite');
  const compressionMethod = c.u8('legacy_compression_method');
  // RFC 5246 s7.4.1.4 makes the extension block optional, and TLS 1.2 servers with nothing to say
  // do omit it entirely. (TLS 1.3 always has one, since supported_versions lives there — a 1.3
  // ServerHello without extensions cannot pass negotiateVersion anyway.)
  const extensions = c.done
    ? new Map()
    : decodeExtensionBlock(c.vector(2, 'extensions'), 'ServerHello');
  c.end('ServerHello');

  if (compressionMethod !== 0) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server selected compression method ${compressionMethod}; TLS compression is not implemented and is unsafe (CRIME)`,
      { compressionMethod },
    );
  }
  return {
    legacyVersion,
    random,
    legacySessionIdEcho,
    cipherSuite,
    extensions,
    isHelloRetryRequest: equal(random, HELLO_RETRY_REQUEST_RANDOM),
  };
}

/**
 * Decide the negotiated version, and refuse every shape of downgrade.
 *
 * The subtle one is the sentinel check (RFC 8446 s4.1.3): a server that supports TLS 1.3 but was
 * pushed down to 1.2 by an attacker stripping our supported_versions plants a known value in the
 * last 8 bytes of its random. A 1.3-capable client that ignores it is exactly the client the
 * attack targets.
 */
export function negotiateVersion(serverHello, { offeredVersions }) {
  const ext = serverHello.extensions.get(EXTENSION.supported_versions);
  let selected;
  if (ext) {
    selected = decodeSelectedVersion(ext);
    if (selected !== TLS13) {
      throw new TlsError(
        codes.TLS_VERSION_UNSUPPORTED,
        `server sent supported_versions selecting ${describeVersion(selected)}; ` +
          'that extension may only select TLS 1.3 in a ServerHello',
        { selected },
      );
    }
    if (serverHello.legacyVersion !== LEGACY_VERSION) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `server negotiated TLS 1.3 but set legacy_version to ${describeVersion(serverHello.legacyVersion)}, expected 0x0303`,
        { legacyVersion: serverHello.legacyVersion },
      );
    }
  } else {
    selected = serverHello.legacyVersion;
  }

  if (!offeredVersions.includes(selected)) {
    throw new TlsUnsupportedError(
      codes.TLS_VERSION_UNSUPPORTED,
      `server selected ${describeVersion(selected)}, which was not offered ` +
        `(offered ${offeredVersions.map(describeVersion).join(', ')}). ` +
        'TLS 1.0 and 1.1 are not implemented: their only cipher suites are RC4 and CBC ' +
        'MAC-then-encrypt, whose padding check cannot be made constant-time in JavaScript.',
      { selected, offeredVersions },
    );
  }

  if (selected === TLS12 && offeredVersions.includes(TLS13)) {
    const tail = serverHello.random.subarray(24, 32);
    if (timingSafeEqual(tail, DOWNGRADE_SENTINEL_12) || timingSafeEqual(tail, DOWNGRADE_SENTINEL_11)) {
      throw new TlsError(
        codes.TLS_VERSION_UNSUPPORTED,
        'server planted the RFC 8446 downgrade sentinel in ServerHello.random while negotiating ' +
          'TLS 1.2, which means a TLS 1.3 capable server saw a tampered ClientHello',
        { sentinel: true },
      );
    }
  }
  return selected;
}

export function negotiateCipher(serverHello, { offeredCiphers, version }) {
  const suite = serverHello.cipherSuite;
  if (!offeredCiphers.includes(suite)) {
    throw new TlsUnsupportedError(
      codes.TLS_CIPHER_UNSUPPORTED,
      `server selected cipher suite ${hex16(suite)}` +
        `${CIPHER_NAME[suite] ? ` (${CIPHER_NAME[suite]})` : ''} under ${describeVersion(version)}, ` +
        'which was not offered. This package negotiates AEAD suites only: CBC suites are ' +
        'MAC-then-encrypt and cannot be implemented without a Lucky13 padding oracle in JavaScript.',
      { cipherSuite: suite, version },
    );
  }
  const params = CIPHER_PARAMS[suite];
  if (!params) {
    throw new TlsUnsupportedError(
      codes.TLS_CIPHER_UNSUPPORTED,
      `cipher suite ${hex16(suite)} has no parameters; this is a bug in the offer list`,
      { cipherSuite: suite },
    );
  }
  const isTls13Suite = TLS13_CIPHERS.includes(suite) || suite === 0x1303;
  if (version === TLS13 && !isTls13Suite) {
    throw new TlsError(
      codes.TLS_CIPHER_UNSUPPORTED,
      `server selected TLS 1.2 cipher suite ${hex16(suite)} under TLS 1.3`,
      { cipherSuite: suite },
    );
  }
  if (version === TLS12 && isTls13Suite) {
    throw new TlsError(
      codes.TLS_CIPHER_UNSUPPORTED,
      `server selected TLS 1.3 cipher suite ${hex16(suite)} under TLS 1.2`,
      { cipherSuite: suite },
    );
  }
  return { suite, params };
}

/**
 * RFC 8446 s4.1.3: the server must echo legacy_session_id verbatim. A mismatch means the
 * ServerHello does not belong to our ClientHello.
 */
export function checkSessionIdEcho(serverHello, legacySessionId) {
  if (!equal(serverHello.legacySessionIdEcho, legacySessionId)) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'server did not echo legacy_session_id; the ServerHello does not match our ClientHello',
    );
  }
}

/** The server's chosen key share, validated against what we actually offered. */
export function selectServerKeyShare(serverHello, keyShares) {
  const ext = serverHello.extensions.get(EXTENSION.key_share);
  if (!ext) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'TLS 1.3 ServerHello has no key_share extension; PSK-only resumption is not supported',
    );
  }
  const { group, keyExchange } = decodeKeyShareEntry(ext, 'ServerHello');
  const mine = keyShares.find((k) => k.group === group);
  if (!mine) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server chose key_share group ${hex16(group)} for which no share was offered`,
      { group },
    );
  }
  return { group, keyExchange, privateKey: mine.privateKey };
}

/** HelloRetryRequest: the server names one group and expects a fresh ClientHello. */
export function parseHelloRetryRequest(serverHello, { offeredGroups }) {
  const ext = serverHello.extensions.get(EXTENSION.key_share);
  if (!ext) {
    throw new TlsError(codes.TLS_HANDSHAKE, 'HelloRetryRequest has no key_share extension');
  }
  const group = decodeKeyShareHrr(ext);
  if (!offeredGroups.includes(group)) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `HelloRetryRequest asked for group ${hex16(group)}, which was not in supported_groups`,
      { group },
    );
  }
  requireSupportedGroup(group, 'HelloRetryRequest');
  const cookie = serverHello.extensions.get(EXTENSION.cookie) ?? null;
  return { group, cookie };
}

// ------------------------------------------------------------------ Certificate

/** TLS 1.3 Certificate (RFC 8446 s4.4.2): context, then entries carrying per-cert extensions. */
export function parseCertificate13(body) {
  const c = new Cursor(body, 'Certificate');
  const context = c.vector(1, 'certificate_request_context');
  if (context.byteLength !== 0) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server Certificate has a ${context.byteLength}-byte certificate_request_context; must be empty`,
    );
  }
  const list = c.sub(3, 'certificate_list');
  const chain = [];
  while (!list.done) {
    const der = list.vector(3, 'cert_data');
    if (der.byteLength === 0) {
      throw new TlsError(codes.TLS_HANDSHAKE, 'Certificate entry has zero-length cert_data');
    }
    list.vector(2, 'certificate extensions'); // OCSP/SCT live here; unused, but must be consumed
    chain.push(der);
  }
  c.end('Certificate');
  if (chain.length === 0) {
    throw new CertificateError(codes.CERT_CHAIN_INCOMPLETE, 'server sent an empty certificate_list');
  }
  return chain;
}

/** TLS 1.2 Certificate (RFC 5246 s7.4.2): a bare list, no context and no per-cert extensions. */
export function parseCertificate12(body) {
  const c = new Cursor(body, 'Certificate');
  const list = c.sub(3, 'certificate_list');
  const chain = [];
  while (!list.done) {
    const der = list.vector(3, 'certificate');
    if (der.byteLength === 0) {
      throw new TlsError(codes.TLS_HANDSHAKE, 'Certificate entry has zero length');
    }
    chain.push(der);
  }
  c.end('Certificate');
  if (chain.length === 0) {
    throw new CertificateError(codes.CERT_CHAIN_INCOMPLETE, 'server sent an empty certificate_list');
  }
  return chain;
}

export function parseCertificateVerify(body) {
  const c = new Cursor(body, 'CertificateVerify');
  const algorithm = c.u16('signature algorithm');
  const signature = c.vector(2, 'signature');
  c.end('CertificateVerify');
  return { algorithm, signature };
}

/** RFC 8446 s4.4.3: 64 spaces, a context string, a zero byte, then the transcript hash. */
export function certificateVerifyContent(transcriptHash, isServer = true) {
  const label = isServer ? 'TLS 1.3, server CertificateVerify' : 'TLS 1.3, client CertificateVerify';
  return concat([new Uint8Array(64).fill(0x20), utf8(label), Uint8Array.from([0]), transcriptHash]);
}

/**
 * Verify a handshake signature with WebCrypto.
 * `spki` is the DER SubjectPublicKeyInfo lifted straight out of the leaf certificate, so the key
 * used to check the signature is provably the key the trust layer validated.
 */
export async function verifyHandshakeSignature({ scheme, spki, signature, content }) {
  const params = SIG_SCHEME_PARAMS[scheme];
  if (!params) {
    throw new TlsUnsupportedError(
      codes.TLS_SIGALG_UNSUPPORTED,
      `server signed the handshake with ${describeSigScheme(scheme)}, which is not implemented; ` +
        `offered ${SUPPORTED_SIG_SCHEMES.map(describeSigScheme).join(', ')}`,
      { scheme },
    );
  }
  let key;
  try {
    key = await crypto.subtle.importKey('spki', spki, params.import, false, ['verify']);
  } catch (cause) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `certificate public key cannot be used with ${describeSigScheme(scheme)}: ${cause?.message}`,
      { scheme },
    );
  }

  // TLS carries ECDSA signatures as a DER ECDSA-Sig-Value; WebCrypto accepts only the fixed-width
  // r||s concatenation. Omitting this conversion produces a client that verifies its own
  // signatures happily and fails against every real ECDSA server — which is most of them.
  const sigBytes =
    params.format === 'ecdsa-der'
      ? ecdsaDerToRaw(signature, params.curveOrderLen, (why) =>
          new TlsError(
            codes.TLS_HANDSHAKE,
            `handshake signature (${describeSigScheme(scheme)}) is not a well-formed ` +
              `ECDSA-Sig-Value: ${why}`,
            { scheme },
          ))
      : signature;

  const ok = await crypto.subtle.verify(params.verify, key, sigBytes, content);
  if (!ok) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `handshake signature (${describeSigScheme(scheme)}) does not verify against the certificate public key`,
      { scheme },
    );
  }
  return true;
}

// ------------------------------------------------------------------ TLS 1.2 ServerKeyExchange

/**
 * RFC 8422 s5.4. Only named-curve ECDHE is accepted: explicit curves are a decade-dead feature
 * and finite-field DHE would need bignum arithmetic WebCrypto does not expose.
 */
export function parseServerKeyExchangeEcdhe(body) {
  const c = new Cursor(body, 'ServerKeyExchange');
  const curveType = c.u8('curve_type');
  if (curveType !== 3) {
    throw new TlsUnsupportedError(
      codes.TLS_GROUP_UNSUPPORTED,
      `server used ECCurveType ${curveType} in ServerKeyExchange; only named_curve (3) is implemented`,
      { curveType },
    );
  }
  const group = c.u16('named_curve');
  const publicKey = c.vector(1, 'ECPoint');
  const signatureAlgorithm = c.u16('SignatureAndHashAlgorithm');
  const signature = c.vector(2, 'signature');
  c.end('ServerKeyExchange');
  // The signed blob is everything from curve_type through the public key.
  const signedParams = body.subarray(0, 4 + publicKey.byteLength);
  return { group, publicKey, signatureAlgorithm, signature, signedParams };
}

/** TLS 1.2 signs client_random || server_random || ServerECDHParams. */
export function serverKeyExchangeContent(clientRandom, serverRandom, signedParams) {
  return concat([clientRandom, serverRandom, signedParams]);
}

export function buildClientKeyExchange(publicKey) {
  return handshakeMessage(HANDSHAKE_TYPE.client_key_exchange, vector(1, publicKey));
}

export function buildFinished(verifyData) {
  return handshakeMessage(HANDSHAKE_TYPE.finished, verifyData);
}

/**
 * Compare a peer Finished against ours. Constant-time in intent: verify_data is derived from
 * secrets the peer must already know, so a timing leak is not a decryption oracle, but there is
 * no reason to leak the prefix length either.
 */
export function checkFinished(received, expected) {
  if (!timingSafeEqual(received, expected)) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'peer Finished verify_data does not match; the handshake transcript differs, which means ' +
        'the connection was tampered with or the peer is not speaking the negotiated parameters',
    );
  }
  return true;
}

/** The negotiated ALPN protocol, refusing anything we did not offer. */
export function checkAlpn(extensions, offeredAlpn, where) {
  const ext = extensions.get(EXTENSION.alpn);
  if (!ext) return null; // absent means the server declined; HTTP/1.1 is the default anyway
  const selected = decodeAlpn(ext);
  if (!offeredAlpn.includes(selected)) {
    throw new TlsError(
      codes.TLS_ALPN,
      `server selected ALPN protocol "${selected}" in ${where}, which was not offered ` +
        `(offered ${offeredAlpn.map((p) => `"${p}"`).join(', ')})`,
      { selected, offeredAlpn },
    );
  }
  return selected;
}

export { GROUP_PARAMS };
