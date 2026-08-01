// TLS wire constants, and the deliberate boundaries of what this package will negotiate.
//
// The selection below is not "what we got around to implementing" — it is a security position.
// Everything here is AEAD. There is no CBC, no RC4, no RSA key transport, and no TLS below 1.2:
//
//   * MAC-then-encrypt (every CBC suite, and all of TLS 1.0/1.1) needs constant-time padding
//     validation to resist Lucky13. JavaScript cannot promise constant time — JIT tiering and GC
//     see to that — so shipping CBC would mean shipping a padding oracle in the name of
//     compatibility. That argument does not weaken at TLS 1.2; RFC 7366 encrypt-then-MAC is too
//     rarely deployed to rely on.
//   * RSA key transport has no forward secrecy.
//   * ChaCha20-Poly1305 is absent from WebCrypto in this runtime, and buys nothing: a server can
//     only select a suite we offered, TLS 1.3 mandates AES-128-GCM (RFC 8446 s9.1), and AES-GCM is
//     universal in TLS 1.2 deployments.
//
// A server that cannot meet these terms gets a typed error naming the exact value it chose, not a
// downgrade.

export const RECORD_TYPE = {
  change_cipher_spec: 20,
  alert: 21,
  handshake: 22,
  application_data: 23,
};

export const HANDSHAKE_TYPE = {
  client_hello: 1,
  server_hello: 2,
  new_session_ticket: 4,
  end_of_early_data: 5,
  encrypted_extensions: 8,
  certificate: 11,
  server_key_exchange: 12,
  certificate_request: 13,
  server_hello_done: 14,
  certificate_verify: 15,
  client_key_exchange: 16,
  finished: 20,
  certificate_status: 22,
  key_update: 24,
  message_hash: 254,
};

/** Legacy record-layer version. Always 0x0303 on the wire after ClientHello (RFC 8446 s5.1). */
export const LEGACY_VERSION = 0x0303;
export const TLS12 = 0x0303;
export const TLS13 = 0x0304;

export const VERSION_NAME = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
};

export const EXTENSION = {
  server_name: 0,
  status_request: 5,
  supported_groups: 10,
  ec_point_formats: 11,
  signature_algorithms: 13,
  alpn: 16,
  signed_certificate_timestamp: 18,
  extended_master_secret: 23,
  session_ticket: 35,
  pre_shared_key: 41,
  early_data: 42,
  supported_versions: 43,
  cookie: 44,
  psk_key_exchange_modes: 45,
  certificate_authorities: 47,
  signature_algorithms_cert: 50,
  key_share: 51,
  renegotiation_info: 0xff01,
};

// -------------------------------------------------------------------- cipher suites

export const CIPHER = {
  // TLS 1.3
  TLS_AES_128_GCM_SHA256: 0x1301,
  TLS_AES_256_GCM_SHA384: 0x1302,
  TLS_CHACHA20_POLY1305_SHA256: 0x1303, // offered only when an implementation is injected
  // TLS 1.2, ECDHE + AEAD only
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: 0xc02b,
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: 0xc02f,
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: 0xc02c,
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: 0xc030,
};

/** Reverse map for error messages. A server that picks something unlisted still gets a hex code. */
export const CIPHER_NAME = Object.fromEntries(Object.entries(CIPHER).map(([k, v]) => [v, k]));

/** Offered in ClientHello, in preference order. */
// curl's order, captured off the wire: `0x1302 0x1303 0x1301`, AES-256 before AES-128. Everything
// through 1.3.0 offered the reverse — the extension order and the header order were matched to curl
// and the CIPHER order was never checked, though JA3 hashes it just as directly.
//
// Client preference is advisory: most servers impose their own, so what this mainly changes is the
// fingerprint. Where a server does follow the client it now picks AES-256, which on this runtime
// costs a little more CPU per byte than AES-128 and is what curl asks for.
export const TLS13_CIPHERS = [CIPHER.TLS_AES_256_GCM_SHA384, CIPHER.TLS_AES_128_GCM_SHA256];

/**
 * curl 8.21.0 / OpenSSL 3.6.3 offers its TLS 1.3 suites in this exact order — AES-256-GCM,
 * ChaCha20-Poly1305, AES-128-GCM — captured off the wire 2026-08-01 (`0x1302 0x1303 0x1301`).
 * ChaCha20 is SECOND, right after AES-256-GCM; that is "curl's position" for it.
 *
 * TLS13_CIPHERS above leads with AES-128, which is the order this package has always offered and
 * which the offline test server keys its default suite selection off; reordering it would change
 * the negotiated suite across the whole suite. So this curl-faithful order is used ONLY when a
 * ChaCha20 implementation has been injected — i.e. when the caller has opted into being able to
 * perform every suite curl offers — and never otherwise. See connect.js.
 */
export const TLS13_CIPHERS_WITH_CHACHA = [
  CIPHER.TLS_AES_256_GCM_SHA384,
  CIPHER.TLS_CHACHA20_POLY1305_SHA256,
  CIPHER.TLS_AES_128_GCM_SHA256,
];

// Likewise curl's relative order among the four suites this package implements: of its full list,
// `0xc02c 0xc030 ... 0xc02b 0xc02f` — ECDSA before RSA within each strength, AES-256 before AES-128.
export const TLS12_CIPHERS = [
  CIPHER.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  CIPHER.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
  CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/**
 * Per-suite parameters. `hash` drives the whole key schedule; `keyLen` the AEAD key size.
 * @typedef {object} CipherParams
 * @property {'SHA-256' | 'SHA-384'} hash the only hashes any negotiable suite selects
 * @property {number} hashLen
 * @property {number} keyLen
 * @property {number} ivLen
 * @property {number} tagLen
 * @property {number} [fixedIvLen] TLS 1.2 only: the 4-byte implicit GCM salt of RFC 5288
 * @property {'ecdsa' | 'rsa'} [sig] TLS 1.2 only: the authentication family the suite names
 */

/** @type {{ [suite: number]: CipherParams }} */
export const CIPHER_PARAMS = {
  [CIPHER.TLS_AES_128_GCM_SHA256]: { hash: 'SHA-256', hashLen: 32, keyLen: 16, ivLen: 12, tagLen: 16 },
  [CIPHER.TLS_AES_256_GCM_SHA384]: { hash: 'SHA-384', hashLen: 48, keyLen: 32, ivLen: 12, tagLen: 16 },
  // Parameters only. Deliberately NOT in TLS13_CIPHERS, so it is never offered unless a caller
  // supplies an implementation — this runtime has no WebCrypto ChaCha20, and its only native path
  // is node:crypto, which the package will not require. Having the parameters here lets the AEAD
  // layer refuse with "no implementation supplied" rather than "unknown suite", which is the
  // difference between a fixable configuration and an apparent dead end.
  [CIPHER.TLS_CHACHA20_POLY1305_SHA256]: {
    hash: 'SHA-256', hashLen: 32, keyLen: 32, ivLen: 12, tagLen: 16,
  },
  [CIPHER.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]: {
    hash: 'SHA-256', hashLen: 32, keyLen: 16, ivLen: 12, tagLen: 16, fixedIvLen: 4, sig: 'ecdsa',
  },
  [CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]: {
    hash: 'SHA-256', hashLen: 32, keyLen: 16, ivLen: 12, tagLen: 16, fixedIvLen: 4, sig: 'rsa',
  },
  [CIPHER.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384]: {
    hash: 'SHA-384', hashLen: 48, keyLen: 32, ivLen: 12, tagLen: 16, fixedIvLen: 4, sig: 'ecdsa',
  },
  [CIPHER.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]: {
    hash: 'SHA-384', hashLen: 48, keyLen: 32, ivLen: 12, tagLen: 16, fixedIvLen: 4, sig: 'rsa',
  },
};

// -------------------------------------------------------------------- groups

export const GROUP = {
  secp256r1: 0x0017,
  secp384r1: 0x0018,
  secp521r1: 0x0019,
  x25519: 0x001d,
  x448: 0x001e,
  ffdhe2048: 0x0100,
  // Post-quantum hybrid (draft-kwiatkowski-tls-ecdhe-mlkem): ML-KEM-768 + X25519. Reachable only
  // when an ML-KEM implementation is injected — its key exchange is not a WebCrypto primitive on
  // this runtime — so like ChaCha20 it is never offered unless the capability was supplied. The
  // combiner lives in hybrid.js; GROUP_PARAMS below records only the wire sizes, not an algorithm.
  x25519mlkem768: 0x11ec,
};

export const GROUP_NAME = Object.fromEntries(Object.entries(GROUP).map(([k, v]) => [v, k]));

/**
 * Offered in preference order. X25519 first because it is the modern default and the runtime's
 * WebCrypto has it; secp256r1 second because RFC 8446 s9.1 makes it mandatory to implement, so
 * offering both means no compliant server can fail to find a match.
 */
export const SUPPORTED_GROUPS = [GROUP.x25519, GROUP.secp256r1, GROUP.secp384r1, GROUP.secp521r1];

/**
 * WebCrypto parameters per group, discriminated on `kind` because X25519 sizes its shared
 * secret in bytes while ECDH sizes it in bits, and the ML-KEM hybrid is not a WebCrypto
 * primitive at all — it carries wire sizes only, and hybrid.js owns the crypto.
 * @typedef {{ kind: 'x25519', algorithm: { name: string }, publicLen: number, secretLen: number }
 *   | { kind: 'ec', algorithm: { name: string, namedCurve: string }, publicLen: number,
 *       secretBits: number }
 *   | { kind: 'hybrid', clientShareLen: number, serverShareLen: number, secretLen: number,
 *       mlkemPublicLen: number, mlkemSecretKeyLen: number, mlkemCiphertextLen: number,
 *       classicalPublicLen: number, classicalSecretLen: number }} GroupParams
 */

/**
 * WebCrypto parameters per group. x448 and the finite-field groups are absent by design.
 * @type {{ [group: number]: GroupParams }}
 */
export const GROUP_PARAMS = {
  [GROUP.x25519]: { kind: 'x25519', algorithm: { name: 'X25519' }, publicLen: 32, secretLen: 32 },
  [GROUP.secp256r1]: {
    kind: 'ec', algorithm: { name: 'ECDH', namedCurve: 'P-256' }, publicLen: 65, secretBits: 256,
  },
  [GROUP.secp384r1]: {
    kind: 'ec', algorithm: { name: 'ECDH', namedCurve: 'P-384' }, publicLen: 97, secretBits: 384,
  },
  [GROUP.secp521r1]: {
    kind: 'ec', algorithm: { name: 'ECDH', namedCurve: 'P-521' }, publicLen: 133, secretBits: 528,
  },
  // X25519MLKEM768 (draft-kwiatkowski-tls-ecdhe-mlkem). The wire sizes below are FIPS 203
  // ML-KEM-768 (ek 1184, ct 1088, dk 2400) alongside X25519 (32). The client's key_share is
  // 1184 + 32 = 1216 bytes and the server's is 1088 + 32 = 1120; the shared secret fed to the
  // key schedule is 32 + 32 = 64. Ordering (ML-KEM before X25519, in both the shares and the
  // secret) is spelled out and enforced in hybrid.js — it is the whole subtlety of this group.
  [GROUP.x25519mlkem768]: {
    kind: 'hybrid',
    clientShareLen: 1216, serverShareLen: 1120, secretLen: 64,
    mlkemPublicLen: 1184, mlkemSecretKeyLen: 2400, mlkemCiphertextLen: 1088,
    classicalPublicLen: 32, classicalSecretLen: 32,
  },
};

// -------------------------------------------------------------------- signature schemes

export const SIG_SCHEME = {
  rsa_pkcs1_sha256: 0x0401,
  rsa_pkcs1_sha384: 0x0501,
  rsa_pkcs1_sha512: 0x0601,
  ecdsa_secp256r1_sha256: 0x0403,
  ecdsa_secp384r1_sha384: 0x0503,
  ecdsa_secp521r1_sha512: 0x0603,
  rsa_pss_rsae_sha256: 0x0804,
  rsa_pss_rsae_sha384: 0x0805,
  rsa_pss_rsae_sha512: 0x0806,
  ed25519: 0x0807,
  ed448: 0x0808,
  rsa_pss_pss_sha256: 0x0809,
  rsa_pss_pss_sha384: 0x080a,
  rsa_pss_pss_sha512: 0x080b,
  rsa_pkcs1_sha1: 0x0201,
  ecdsa_sha1: 0x0203,
};

export const SIG_SCHEME_NAME = Object.fromEntries(
  Object.entries(SIG_SCHEME).map(([k, v]) => [v, k]),
);

/**
 * Offered in signature_algorithms. SHA-1 schemes are deliberately absent: they are forbidden in
 * TLS 1.3 handshake signatures and are not worth accepting in 1.2 either.
 */
export const SUPPORTED_SIG_SCHEMES = [
  SIG_SCHEME.ecdsa_secp256r1_sha256,
  SIG_SCHEME.ecdsa_secp384r1_sha384,
  SIG_SCHEME.ecdsa_secp521r1_sha512,
  SIG_SCHEME.rsa_pss_rsae_sha256,
  SIG_SCHEME.rsa_pss_rsae_sha384,
  SIG_SCHEME.rsa_pss_rsae_sha512,
  SIG_SCHEME.ed25519,
  SIG_SCHEME.rsa_pkcs1_sha256,
  SIG_SCHEME.rsa_pkcs1_sha384,
  SIG_SCHEME.rsa_pkcs1_sha512,
];

/**
 * How to verify one signature scheme with WebCrypto. `format: 'ecdsa-der'` marks the schemes
 * whose wire signatures need the DER-to-P1363 conversion before subtle.verify will take them.
 * @typedef {object} SigSchemeParams
 * @property {{ name: string, namedCurve?: string, hash?: string }} import importKey algorithm
 * @property {{ name: string, hash?: string, saltLength?: number }} verify verify() algorithm
 * @property {'ecdsa-der'} [format]
 * @property {number} [curveOrderLen] byte width of the curve order, ECDSA only
 */

/**
 * How to verify each scheme with WebCrypto. Absent entries are rejected with a named error.
 * @type {{ [scheme: number]: SigSchemeParams }}
 */
export const SIG_SCHEME_PARAMS = {
  [SIG_SCHEME.ecdsa_secp256r1_sha256]: {
    import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' },
    format: 'ecdsa-der', curveOrderLen: 32,
  },
  [SIG_SCHEME.ecdsa_secp384r1_sha384]: {
    import: { name: 'ECDSA', namedCurve: 'P-384' }, verify: { name: 'ECDSA', hash: 'SHA-384' },
    format: 'ecdsa-der', curveOrderLen: 48,
  },
  [SIG_SCHEME.ecdsa_secp521r1_sha512]: {
    import: { name: 'ECDSA', namedCurve: 'P-521' }, verify: { name: 'ECDSA', hash: 'SHA-512' },
    format: 'ecdsa-der', curveOrderLen: 66,
  },
  [SIG_SCHEME.rsa_pss_rsae_sha256]: {
    import: { name: 'RSA-PSS', hash: 'SHA-256' }, verify: { name: 'RSA-PSS', saltLength: 32 },
  },
  [SIG_SCHEME.rsa_pss_rsae_sha384]: {
    import: { name: 'RSA-PSS', hash: 'SHA-384' }, verify: { name: 'RSA-PSS', saltLength: 48 },
  },
  [SIG_SCHEME.rsa_pss_rsae_sha512]: {
    import: { name: 'RSA-PSS', hash: 'SHA-512' }, verify: { name: 'RSA-PSS', saltLength: 64 },
  },
  [SIG_SCHEME.rsa_pss_pss_sha256]: {
    import: { name: 'RSA-PSS', hash: 'SHA-256' }, verify: { name: 'RSA-PSS', saltLength: 32 },
  },
  [SIG_SCHEME.rsa_pss_pss_sha384]: {
    import: { name: 'RSA-PSS', hash: 'SHA-384' }, verify: { name: 'RSA-PSS', saltLength: 48 },
  },
  [SIG_SCHEME.rsa_pss_pss_sha512]: {
    import: { name: 'RSA-PSS', hash: 'SHA-512' }, verify: { name: 'RSA-PSS', saltLength: 64 },
  },
  [SIG_SCHEME.rsa_pkcs1_sha256]: {
    import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' },
  },
  [SIG_SCHEME.rsa_pkcs1_sha384]: {
    import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, verify: { name: 'RSASSA-PKCS1-v1_5' },
  },
  [SIG_SCHEME.rsa_pkcs1_sha512]: {
    import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, verify: { name: 'RSASSA-PKCS1-v1_5' },
  },
  [SIG_SCHEME.ed25519]: { import: { name: 'Ed25519' }, verify: { name: 'Ed25519' } },
};

// -------------------------------------------------------------------- alerts

export const ALERT_LEVEL = { warning: 1, fatal: 2 };

export const ALERT_DESC = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  21: 'decryption_failed',
  22: 'record_overflow',
  40: 'handshake_failure',
  41: 'no_certificate',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  86: 'inappropriate_fallback',
  90: 'user_canceled',
  109: 'missing_extension',
  110: 'unsupported_extension',
  112: 'unrecognized_name',
  113: 'bad_certificate_status_response',
  115: 'unknown_psk_identity',
  116: 'certificate_required',
  120: 'no_application_protocol',
};

/** RFC 8446 s5.1: plaintext fragments are at most 2^14 bytes; ciphertext adds at most 256. */
export const MAX_PLAINTEXT = 1 << 14;
export const MAX_CIPHERTEXT = (1 << 14) + 256;

/** The only protocol we will negotiate. Offering h2 we cannot speak would be a footgun. */
export const ALPN_HTTP11 = 'http/1.1';

/**
 * RFC 8446 s4.1.3: a TLS 1.2 server that is really 1.3-aware signals a downgrade attempt by
 * planting these in the last 8 bytes of ServerHello.random. A 1.3-capable client that lands on
 * 1.2 must abort when it sees them.
 */
export const DOWNGRADE_SENTINEL_12 = Uint8Array.from([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01]);
export const DOWNGRADE_SENTINEL_11 = Uint8Array.from([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00]);

/** RFC 8446 s4.1.3: HelloRetryRequest is a ServerHello whose random is this fixed value. */
export const HELLO_RETRY_REQUEST_RANDOM = Uint8Array.from([
  0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
  0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);
