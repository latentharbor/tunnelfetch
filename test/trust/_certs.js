// Certificate factory for the trust tests.
//
// Mints real, properly-signed certificates at test time with node:crypto (which is allowed in
// test/, never in src/): a hand-rolled DER writer builds the TBSCertificate, node signs it, and
// the result is a certificate that OpenSSL itself accepts — x509.test.js cross-checks that. The
// factory can also mint deliberately broken variants (weak hashes, missing CA bits, violated
// constraints) because the negative space is where a validator earns its keep.

import { generateKeyPairSync, sign as nodeSign, createHash, constants } from 'node:crypto';

// ------------------------------------------------------------------ DER writers

const concat = (parts) => {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/** One TLV. `tag` is the full identifier octet (0x30 = constructed SEQUENCE, 0xa0 = [0], ...). */
export function tlv(tag, ...contents) {
  const parts = contents.map((c) => (c instanceof Uint8Array ? c : Uint8Array.from(c)));
  const body = concat(parts);
  return concat([Uint8Array.of(tag), derLen(body.length), body]);
}

export const seq = (...c) => tlv(0x30, ...c);
export const set = (...c) => tlv(0x31, ...c);
export const nul = () => tlv(0x05);
export const octet = (b) => tlv(0x04, b);
export const bool = (v) => tlv(0x01, [v ? 0xff : 0x00]);
export const bitstr = (b, unused = 0) => tlv(0x03, [unused], b);
export const ctx = (n, ...c) => tlv(0xa0 | n, ...c); // constructed context tag
export const ctxPrim = (n, b) => tlv(0x80 | n, b); // primitive context tag

export function int(v) {
  if (v instanceof Uint8Array) return tlv(0x02, v);
  if (v < 0) throw new Error('factory only encodes non-negative INTEGERs');
  const bytes = [];
  let n = v;
  do {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  } while (n > 0);
  if (bytes[0] & 0x80) bytes.unshift(0); // keep it positive
  return tlv(0x02, bytes);
}

export function oid(dotted) {
  const arcs = dotted.split('.').map(Number);
  const body = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const vlq = [arc & 0x7f];
    let n = Math.floor(arc / 128);
    while (n > 0) {
      vlq.unshift(0x80 | (n & 0x7f));
      n = Math.floor(n / 128);
    }
    body.push(...vlq);
  }
  return tlv(0x06, body);
}

const ascii = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0));
export const utf8str = (s) => tlv(0x0c, new TextEncoder().encode(s));
export const printable = (s) => tlv(0x13, ascii(s));
export const ia5 = (s) => tlv(0x16, ascii(s));

function two(n) {
  return String(n).padStart(2, '0');
}

/** UTCTime for 1950-2049, GeneralizedTime outside, per the RFC 5280 profile. */
export function time(ms) {
  const d = new Date(ms);
  const y = d.getUTCFullYear();
  const rest =
    two(d.getUTCMonth() + 1) + two(d.getUTCDate()) + two(d.getUTCHours()) +
    two(d.getUTCMinutes()) + two(d.getUTCSeconds()) + 'Z';
  if (y >= 1950 && y < 2050) return tlv(0x17, ascii(String(y % 100).padStart(2, '0') + rest));
  return tlv(0x18, ascii(String(y).padStart(4, '0') + rest));
}

// ------------------------------------------------------------------ names

const ATTR_OID = {
  CN: '2.5.4.3', C: '2.5.4.6', L: '2.5.4.7', ST: '2.5.4.8', O: '2.5.4.10', OU: '2.5.4.11',
};

/** { CN: 'x', O: 'y' } -> DER Name. One attribute per RDN, encoded in insertion order. */
export function dn(attrs) {
  const rdns = Object.entries(attrs).map(([k, v]) =>
    set(seq(oid(ATTR_OID[k] ?? k), k === 'C' ? printable(v) : utf8str(v))));
  return seq(...rdns);
}

// ------------------------------------------------------------------ keys and signatures

export function makeKeys(keyType = 'ec-p256') {
  switch (keyType) {
    case 'ec-p256': return generateKeyPairSync('ec', { namedCurve: 'P-256' });
    case 'ec-p384': return generateKeyPairSync('ec', { namedCurve: 'P-384' });
    case 'rsa': return generateKeyPairSync('rsa', { modulusLength: 2048 });
    case 'ed25519': return generateKeyPairSync('ed25519');
    default: throw new Error(`unknown keyType ${keyType}`);
  }
}

const SIG_OIDS = {
  'ec-p256': { sha256: '1.2.840.10045.4.3.2', sha384: '1.2.840.10045.4.3.3', sha512: '1.2.840.10045.4.3.4', sha1: '1.2.840.10045.4.1' },
  'ec-p384': { sha256: '1.2.840.10045.4.3.2', sha384: '1.2.840.10045.4.3.3', sha512: '1.2.840.10045.4.3.4', sha1: '1.2.840.10045.4.1' },
  rsa: { sha256: '1.2.840.113549.1.1.11', sha384: '1.2.840.113549.1.1.12', sha512: '1.2.840.113549.1.1.13', sha1: '1.2.840.113549.1.1.5', md5: '1.2.840.113549.1.1.4' },
  ed25519: { any: '1.3.101.112' },
};

const MGF1_OID = '1.2.840.113549.1.1.8';
const HASH_OIDS = { sha256: '2.16.840.1.101.3.4.2.1', sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3', sha1: '1.3.14.3.2.26' };

export function pssParams(hash = 'sha256', saltLen = { sha256: 32, sha384: 48, sha512: 64, sha1: 20 }[hash], mgfHash = hash) {
  return seq(
    ctx(0, seq(oid(HASH_OIDS[hash]), nul())),
    ctx(1, seq(oid(MGF1_OID), seq(oid(HASH_OIDS[mgfHash]), nul()))),
    ctx(2, int(saltLen)),
  );
}

function sigAlgFor(keyType, sigHash, pss) {
  if (keyType === 'ed25519') return seq(oid(SIG_OIDS.ed25519.any));
  if (pss) return seq(oid('1.2.840.113549.1.1.10'), pssParams(sigHash));
  const o = SIG_OIDS[keyType]?.[sigHash];
  if (!o) throw new Error(`no signature algorithm for ${keyType}/${sigHash}`);
  return keyType === 'rsa' ? seq(oid(o), nul()) : seq(oid(o));
}

function signTbs(tbs, issuerKey, keyType, sigHash, pss) {
  if (keyType === 'ed25519') return new Uint8Array(nodeSign(null, tbs, issuerKey));
  const key = pss
    ? { key: issuerKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST }
    : issuerKey;
  try {
    return new Uint8Array(nodeSign(sigHash, tbs, key));
  } catch {
    // OpenSSL may refuse to actually SIGN with md5. That is fine: certificates claiming a weak
    // algorithm must be rejected by OID before any verification, so the bytes never get checked.
    return new Uint8Array(nodeSign('sha256', tbs, issuerKey));
  }
}

// ------------------------------------------------------------------ extensions

const KU_INDEX = {
  digitalSignature: 0, nonRepudiation: 1, keyEncipherment: 2, dataEncipherment: 3,
  keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8,
};

function keyUsageValue(names) {
  const idx = names.map((n) => {
    if (!(n in KU_INDEX)) throw new Error(`unknown key usage ${n}`);
    return KU_INDEX[n];
  });
  const maxBit = Math.max(...idx);
  const bytes = new Uint8Array((maxBit >> 3) + 1);
  for (const i of idx) bytes[i >> 3] |= 0x80 >> (i & 7);
  return bitstr(bytes, 7 - (maxBit & 7)); // DER named-bits: trailing zero bits trimmed
}

const EKU_OID = {
  serverAuth: '1.3.6.1.5.5.7.3.1', clientAuth: '1.3.6.1.5.5.7.3.2',
  codeSigning: '1.3.6.1.5.5.7.3.3', any: '2.5.29.37.0',
};

const extension = (extnOid, critical, value) =>
  seq(oid(extnOid), ...(critical ? [bool(true)] : []), octet(value));

export const ip4 = (s) => Uint8Array.from(s.split('.'), Number);

function generalName(entry) {
  if (entry.dns !== undefined) return ctxPrim(2, ascii(entry.dns));
  if (entry.ip !== undefined) return ctxPrim(7, entry.ip);
  if (entry.email !== undefined) return ctxPrim(1, ascii(entry.email));
  if (entry.uri !== undefined) return ctxPrim(6, ascii(entry.uri));
  throw new Error('unknown GeneralName spec');
}

function nameConstraintsValue(nc) {
  const subtree = (g) => seq(generalName(g));
  const fields = [];
  if (nc.permitted?.length) fields.push(ctx(0, ...nc.permitted.map(subtree)));
  if (nc.excluded?.length) fields.push(ctx(1, ...nc.excluded.map(subtree)));
  return seq(...fields);
}

// ------------------------------------------------------------------ certificates

let serialCounter = 1000;

/**
 * Mint one certificate. Returns a bundle usable as the `issuer` of further certificates.
 *
 * Options (all optional except subject):
 *   subject          {CN: ...} or DER bytes
 *   issuer           a bundle returned by makeCert; omitted = self-signed
 *   keyType          'ec-p256' | 'ec-p384' | 'rsa' | 'ed25519'
 *   keys             reuse an existing node key pair
 *   serial           number
 *   notBefore/notAfter  epoch ms
 *   ca               boolean; emits critical basicConstraints when true
 *   pathLen          number; requires ca
 *   omitBasicConstraints  suppress the extension even for ca certs
 *   keyUsage         array of bit names, null to omit (default: CA gets keyCertSign+cRLSign,
 *                    leaf gets digitalSignature)
 *   eku              array of EKU_OID keys or dotted OIDs, null to omit (leaf default serverAuth)
 *   san              { dns: [], ip: [Uint8Array] } — null omits the extension entirely
 *   ski/aki          booleans (default true): subject/authority key identifier extensions
 *   nameConstraints  { permitted: [{dns}|{ip}], excluded: [...], critical }
 *   extraExtensions  [{ oid, critical, value: Uint8Array }]
 *   sigHash          'sha256' (default) | 'sha384' | 'sha512' | 'sha1' | 'md5'
 *   pss              sign RSA with RSASSA-PSS and matching parameters
 *   version          3 (default) or 1 (bare v1 certificate, no extensions)
 *   tamper           (der) => der, applied to the finished certificate
 */
export function makeCert(opts) {
  const {
    subject, issuer = null, keyType = 'ec-p256', keys = makeKeys(keyType),
    serial = serialCounter++,
    notBefore = Date.now() - 24 * 3600 * 1000,
    notAfter = Date.now() + 30 * 24 * 3600 * 1000,
    ca = false, pathLen = null, omitBasicConstraints = false,
    keyUsage = ca ? ['keyCertSign', 'cRLSign'] : ['digitalSignature'],
    eku = ca ? null : ['serverAuth'],
    san = ca ? null : { dns: ['server.test'] },
    ski = true, aki = true,
    nameConstraints = null, extraExtensions = [],
    sigHash = 'sha256', pss = false, version = 3,
  } = opts;

  const subjectDn = subject instanceof Uint8Array ? subject : dn(subject);
  const issuerDn = issuer ? issuer.dnBytes : subjectDn;
  const signerKey = issuer ? issuer.privateKey : keys.privateKey;
  const signerType = issuer ? issuer.keyType : keyType;
  const spkiDer = new Uint8Array(keys.publicKey.export({ type: 'spki', format: 'der' }));
  const skiBytes = createHash('sha256').update(spkiDer).digest().subarray(0, 20);

  const extensions = [];
  if (version === 3) {
    if ((ca || pathLen !== null) && !omitBasicConstraints) {
      extensions.push(extension('2.5.29.19', true,
        seq(...(ca ? [bool(true)] : []), ...(pathLen !== null ? [int(pathLen)] : []))));
    }
    if (keyUsage) extensions.push(extension('2.5.29.15', true, keyUsageValue(keyUsage)));
    if (eku) {
      extensions.push(extension('2.5.29.37', false,
        seq(...eku.map((e) => oid(EKU_OID[e] ?? e)))));
    }
    if (san) {
      const entries = [
        ...(san.dns ?? []).map((d) => ({ dns: d })),
        ...(san.ip ?? []).map((i) => ({ ip: i })),
        ...(san.email ?? []).map((e) => ({ email: e })),
      ];
      extensions.push(extension('2.5.29.17', false, seq(...entries.map(generalName))));
    }
    if (ski) extensions.push(extension('2.5.29.14', false, octet(skiBytes)));
    if (aki && issuer?.ski) extensions.push(extension('2.5.29.35', false, seq(ctxPrim(0, issuer.ski))));
    if (nameConstraints) {
      extensions.push(extension('2.5.29.30', nameConstraints.critical ?? true,
        nameConstraintsValue(nameConstraints)));
    }
    for (const e of extraExtensions) extensions.push(extension(e.oid, e.critical ?? false, e.value));
  }

  const sigAlg = sigAlgFor(signerType, sigHash, pss);
  const tbs = seq(
    ...(version === 3 ? [ctx(0, int(2))] : []),
    int(serial),
    sigAlg,
    issuerDn,
    seq(time(notBefore), time(notAfter)),
    subjectDn,
    spkiDer,
    ...(extensions.length ? [ctx(3, seq(...extensions))] : []),
  );
  const signature = signTbs(tbs, signerKey, signerType, sigHash, pss);
  let der = seq(tbs, sigAlg, bitstr(signature, 0));
  if (opts.tamper) der = opts.tamper(der);

  return {
    der,
    dnBytes: subjectDn,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    keyType,
    spkiDer,
    ski: skiBytes,
    notBefore,
    notAfter,
  };
}

/** PEM-encode a DER certificate (for anchors-mode and root-store generator tests). */
export function toPem(der) {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n').trimEnd();
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

/**
 * The standard three-tier fixture: Root CA -> Intermediate CA -> leaf for server.test.
 * Options pass through to the leaf; `intermediate`/`root` option objects override those tiers.
 */
export function caFixture({ leaf = {}, intermediate = {}, root = {}, keyType = 'ec-p256' } = {}) {
  const rootB = makeCert({ subject: { CN: 'Test Root CA', O: 'tunnelfetch' }, ca: true, keyType, ...root });
  const intB = makeCert({ subject: { CN: 'Test Intermediate CA', O: 'tunnelfetch' }, issuer: rootB, ca: true, keyType, ...intermediate });
  const leafB = makeCert({ subject: { CN: 'server.test', O: 'tunnelfetch' }, issuer: intB, keyType, ...leaf });
  return { root: rootB, intermediate: intB, leaf: leafB };
}

/** Flip one byte inside the last `n` bytes of a DER blob (the signature lives at the end). */
export function flipSignatureByte(der) {
  const out = der.slice();
  out[out.length - 4] ^= 0x01;
  return out;
}
