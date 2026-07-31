// Minimal certificate factory for the TLS handshake tests.
//
// The handshake driver never parses X.509 itself — verifyPeer is injected — but it DOES check
// CertificateVerify against the SPKI the verifier returns, so these tests need a real key pair
// and a certificate whose SubjectPublicKeyInfo is genuinely that key's. Everything else about
// the certificate (chain building, names, validity) is the trust layer's problem and is kept to
// the minimum that still yields a well-formed DER leaf: handshake.test.js asserts that node's
// own X509Certificate parser accepts what this file mints, so a broken factory fails loudly
// instead of silently weakening every handshake test built on it.
//
// node:crypto is fine HERE (tests run under Node); repo-hygiene keeps it banned from src/.

import { constants, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { concat } from '../../src/util/bytes.js';
import { SIG_SCHEME } from '../../src/tls/constants.js';

// ------------------------------------------------------------------ tiny DER writer

function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

const tlv = (tag, body) => concat([Uint8Array.of(tag), derLen(body.byteLength), body]);
const seq = (...parts) => tlv(0x30, concat(parts));
const set = (...parts) => tlv(0x31, concat(parts));
const int = (n) => tlv(0x02, Uint8Array.of(n)); // small positive serials/versions only
const octetstr = (b) => tlv(0x04, b);
const nul = () => tlv(0x05, new Uint8Array(0));
const utf8str = (s) => tlv(0x0c, new TextEncoder().encode(s));
const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const utctime = (s) => tlv(0x17, ascii(s));
const ctx = (n, body) => tlv(0xa0 | n, body); // constructed context tag
const ctxPrim = (n, body) => tlv(0x80 | n, body); // primitive context tag
// BIT STRING with zero unused bits — the only shape a signature or SPKI needs.
const bitstr = (b) => tlv(0x03, concat([Uint8Array.of(0), b]));

function oid(dotted) {
  const arcs = dotted.split('.').map(Number);
  const body = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const vlq = [arc & 0x7f];
    let v = Math.floor(arc / 128);
    while (v > 0) {
      vlq.unshift(0x80 | (v & 0x7f));
      v = Math.floor(v / 128);
    }
    body.push(...vlq);
  }
  return tlv(0x06, Uint8Array.from(body));
}

// ------------------------------------------------------------------ key kinds

/**
 * Per-kind knowledge: how to make the key pair, which TLS SignatureScheme it answers to, how a
 * conforming server encodes a CertificateVerify signature on the wire, and how to self-sign the
 * certificate. The wire encodings matter more than they look:
 *
 *   * ECDSA travels as a DER ECDSA-Sig-Value (RFC 8446 s4.4.3 via RFC 8422 s5.10) — NOT the
 *     raw r||s that WebCrypto produces — so the signer here asks node for `dsaEncoding: 'der'`.
 *     A test server signing r||s would only ever prove the client can talk to itself.
 *   * rsa_pss_rsae_* means "PSS signature under a plain rsaEncryption SPKI" (RFC 8446 s4.2.3),
 *     so the certificate carries an ordinary RSA key and only the TLS signature uses PSS.
 *   * Ed25519 signatures are raw 64 bytes in both TLS and WebCrypto, and are deterministic,
 *     which is what the byte-for-byte reproducibility test leans on.
 */
const KINDS = {
  'ecdsa-p256': {
    generate: () => generateKeyPairSync('ec', { namedCurve: 'P-256' }),
    scheme: SIG_SCHEME.ecdsa_secp256r1_sha256,
    tlsSign: (key, content) =>
      new Uint8Array(nodeSign('sha256', content, { key, dsaEncoding: 'der' })),
    certAlg: seq(oid('1.2.840.10045.4.3.2')), // ecdsa-with-SHA256, parameters absent
    certSign: (key, tbs) => new Uint8Array(nodeSign('sha256', tbs, { key, dsaEncoding: 'der' })),
  },
  'ecdsa-p384': {
    generate: () => generateKeyPairSync('ec', { namedCurve: 'P-384' }),
    scheme: SIG_SCHEME.ecdsa_secp384r1_sha384,
    tlsSign: (key, content) =>
      new Uint8Array(nodeSign('sha384', content, { key, dsaEncoding: 'der' })),
    certAlg: seq(oid('1.2.840.10045.4.3.3')), // ecdsa-with-SHA384
    certSign: (key, tbs) => new Uint8Array(nodeSign('sha384', tbs, { key, dsaEncoding: 'der' })),
  },
  // P-521 matters beyond completeness: its ECDSA-Sig-Value is ~139 bytes, which forces a
  // LONG-FORM DER length octet — the edge a DER-to-raw signature conversion is likeliest to get
  // wrong — and its 66-byte order length is not a hash size, so it catches conflations too.
  'ecdsa-p521': {
    generate: () => generateKeyPairSync('ec', { namedCurve: 'P-521' }),
    scheme: SIG_SCHEME.ecdsa_secp521r1_sha512,
    tlsSign: (key, content) =>
      new Uint8Array(nodeSign('sha512', content, { key, dsaEncoding: 'der' })),
    certAlg: seq(oid('1.2.840.10045.4.3.4')), // ecdsa-with-SHA512
    certSign: (key, tbs) => new Uint8Array(nodeSign('sha512', tbs, { key, dsaEncoding: 'der' })),
  },
  'rsa-pss': {
    generate: () => generateKeyPairSync('rsa', { modulusLength: 2048 }),
    scheme: SIG_SCHEME.rsa_pss_rsae_sha256,
    tlsSign: (key, content) =>
      new Uint8Array(nodeSign('sha256', content, {
        key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32,
      })),
    certAlg: seq(oid('1.2.840.113549.1.1.11'), nul()), // sha256WithRSAEncryption + NULL
    certSign: (key, tbs) => new Uint8Array(nodeSign('sha256', tbs, key)),
  },
  ed25519: {
    generate: () => generateKeyPairSync('ed25519'),
    scheme: SIG_SCHEME.ed25519,
    tlsSign: (key, content) => new Uint8Array(nodeSign(null, content, key)),
    certAlg: seq(oid('1.3.101.112')), // id-Ed25519, parameters absent
    certSign: (key, tbs) => new Uint8Array(nodeSign(null, tbs, key)),
  },
};

// ------------------------------------------------------------------ the factory

/**
 * Mint a self-signed v3 leaf. Self-signed is enough: the handshake tests stub verifyPeer, so no
 * signature chain is ever walked — but the SPKI inside the DER is the real public half of the
 * key that signs CertificateVerify, which is the one binding these tests must not fake.
 *
 * @param {'ecdsa-p256' | 'ecdsa-p384' | 'ecdsa-p521' | 'rsa-pss' | 'ed25519'} kind
 * @param {string} [cn]
 * @returns {{ kind: string, cn: string, scheme: number, certDer: Uint8Array,
 *             spkiDer: Uint8Array, sign: (content: Uint8Array) => Uint8Array,
 *             publicKey: object, privateKey: object }}
 */
export function makeIdentity(kind, cn = 'server.test') {
  const k = KINDS[kind];
  if (!k) throw new Error(`unknown identity kind ${JSON.stringify(kind)}`);
  const { publicKey, privateKey } = k.generate();
  const spkiDer = new Uint8Array(publicKey.export({ type: 'spki', format: 'der' }));

  const name = seq(set(seq(oid('2.5.4.3'), utf8str(cn)))); // CN=<cn>, one RDN
  // Fixed validity keeps the DER independent of the wall clock; nothing here checks dates.
  const validity = seq(utctime('250101000000Z'), utctime('350101000000Z'));
  const san = seq(oid('2.5.29.17'), octetstr(seq(ctxPrim(2, ascii(cn))))); // dNSName
  const tbs = seq(
    ctx(0, int(2)), // version v3
    int(1), // serialNumber
    k.certAlg,
    name, // issuer == subject: self-signed
    validity,
    name,
    spkiDer,
    ctx(3, seq(san)),
  );
  const certDer = seq(tbs, k.certAlg, bitstr(k.certSign(privateKey, tbs)));

  return {
    kind,
    cn,
    scheme: k.scheme,
    certDer,
    spkiDer,
    sign: (content) => k.tlsSign(privateKey, content),
    publicKey,
    privateKey,
  };
}

/** Memoized identities: RSA keygen is the only slow operation in this suite; pay it once. */
const cache = new Map();
export function testIdentity(kind) {
  if (!cache.has(kind)) cache.set(kind, makeIdentity(kind));
  return cache.get(kind);
}
