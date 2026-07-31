// X.509 v3 certificate parsing (RFC 5280 s4), on top of the DER reader.
//
// Parsed from the raw bytes, deliberately not via any runtime helper: the runtime's certificate
// object was measured on the target edge and silently lacks pathLenConstraint, the signature
// algorithm, and real key-usage bits. A security check that reads `undefined` and shrugs is the
// failure mode this package exists to close, so every field consumed by path validation comes
// from our own DER walk of the original bytes.
//
// parseCertificate() is a parser, not a judge: it records what the certificate says (including
// weak algorithms and unknown critical extensions) and throws only on malformed or self-
// contradictory encodings. Judgement lives in path.js, which consults resolveSignatureScheme()
// and unknownCriticalExtensions for exactly the certificates whose signatures actually anchor
// trust — a server may ship a stale SHA-1 self-signed root alongside a modern chain, and that
// root's own signature is never consumed, so it must not be able to break the connection.

import { CertificateError, codes } from '../errors.js';
import { equal, toHex } from '../util/bytes.js';
import { SIG_SCHEME } from '../tls/constants.js';
import {
  TAG, CLS, readTlv, readAll, readSequence, children, content, element, expectTlv,
  readInteger, readOid, readBitString, readBoolean, readTime, readString, parseError, tagName,
} from './der.js';

export const OID = /** @type {const} */ ({
  // public key algorithms
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  ed25519: '1.3.101.112',
  ed448: '1.3.101.113',
  // named curves
  secp256r1: '1.2.840.10045.3.1.7',
  secp384r1: '1.3.132.0.34',
  secp521r1: '1.3.132.0.35',
  // signature algorithms
  sha256WithRsa: '1.2.840.113549.1.1.11',
  sha384WithRsa: '1.2.840.113549.1.1.12',
  sha512WithRsa: '1.2.840.113549.1.1.13',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
  ecdsaWithSha512: '1.2.840.10045.4.3.4',
  // digests (referenced by RSA-PSS parameters)
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  mgf1: '1.2.840.113549.1.1.8',
  // extensions
  subjectKeyIdentifier: '2.5.29.14',
  keyUsage: '2.5.29.15',
  subjectAltName: '2.5.29.17',
  issuerAltName: '2.5.29.18',
  basicConstraints: '2.5.29.19',
  nameConstraints: '2.5.29.30',
  crlDistributionPoints: '2.5.29.31',
  certificatePolicies: '2.5.29.32',
  authorityKeyIdentifier: '2.5.29.35',
  extendedKeyUsage: '2.5.29.37',
  freshestCrl: '2.5.29.46',
  authorityInfoAccess: '1.3.6.1.5.5.7.1.1',
  subjectInfoAccess: '1.3.6.1.5.5.7.1.11',
  sctList: '1.3.6.1.4.1.11129.2.4.2',
  // extended key usage members
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
  ocspSigning: '1.3.6.1.5.5.7.3.9',
  anyExtendedKeyUsage: '2.5.29.37.0',
  // OCSP (RFC 6960)
  ocspBasic: '1.3.6.1.5.5.7.48.1.1',
  ocspNonce: '1.3.6.1.5.5.7.48.1.2',
  ocspNocheck: '1.3.6.1.5.5.7.48.1.5',
});

/** Signature algorithms rejected outright: collisions are practical or near-practical. */
const WEAK_SIG_OIDS = {
  '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
  '1.2.840.113549.1.1.3': 'md4WithRSAEncryption',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.3.14.3.2.29': 'sha1WithRSAEncryption (OIW)',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10040.4.3': 'dsa-with-sha1',
};

/**
 * Extensions this validator understands, or has deliberately judged safe to leave unprocessed
 * even when marked critical. Everything else that is critical causes rejection in path.js
 * (RFC 5280 s6.1: a relying party MUST reject on unrecognised critical extensions — ignoring
 * them is the classic fail-open).
 *
 * certificatePolicies is listed because with no required policy set, RFC 5280 policy processing
 * cannot fail; policyConstraints / inhibitAnyPolicy are deliberately NOT listed, because they
 * make policy processing mandatory and we do not implement it — they are always critical, so
 * their presence in a path rejects it.
 */
export const KNOWN_EXTENSIONS = new Set([
  OID.subjectKeyIdentifier, OID.keyUsage, OID.subjectAltName, OID.issuerAltName,
  OID.basicConstraints, OID.nameConstraints, OID.crlDistributionPoints, OID.certificatePolicies,
  OID.authorityKeyIdentifier, OID.extendedKeyUsage, OID.freshestCrl,
  OID.authorityInfoAccess, OID.subjectInfoAccess, OID.sctList,
]);

// ------------------------------------------------------------------ names

const ATTR_NAME = {
  '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C', '2.5.4.7': 'L',
  '2.5.4.8': 'ST', '2.5.4.9': 'street', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.15': 'businessCategory',
  '2.5.4.17': 'postalCode', '2.5.4.42': 'GN', '2.5.4.97': 'organizationIdentifier',
  '1.2.840.113549.1.9.1': 'emailAddress', '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
};

/**
 * A parsed X.500 Name. `bytes` is the exact DER of the whole Name — the canonical identity for
 * every comparison; `rdns` and `text` exist for constraint checks and log lines respectively.
 * @typedef {object} DistinguishedName
 * @property {Uint8Array} bytes
 * @property {Array<Array<{ oid: string, value: string }>>} rdns one array per RDN, in order;
 *   non-string attribute values are rendered as '#hex'
 * @property {string} text human-readable 'CN=..., O=...' form
 */

/**
 * Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue).
 *
 * `bytes` is the exact DER of the whole Name and is the canonical form used for all issuer ==
 * subject comparisons. RFC 5280 s7.1 also allows caseIgnore/whitespace-folded matching, but a CA
 * that spells its own name two different ways between certificates breaks every deployed
 * validator that matters (they compare bytes too), and a lax comparator is one more place to
 * confuse two names. Exact bytes, fail closed.
 *
 * @param {Uint8Array} bytes
 * @param {import('./der.js').Tlv} tlv
 * @returns {DistinguishedName}
 */
export function parseName(bytes, tlv) {
  expectTlv(tlv, { tag: TAG.SEQUENCE, constructed: true }, 'Name');
  const rdns = [];
  const parts = [];
  for (const rdn of children(bytes, tlv, 'Name')) {
    expectTlv(rdn, { tag: TAG.SET, constructed: true }, 'RelativeDistinguishedName');
    const avas = [];
    const kids = children(bytes, rdn, 'RelativeDistinguishedName');
    if (kids.length === 0) throw parseError(rdn.start, 'empty RelativeDistinguishedName');
    for (const ava of kids) {
      expectTlv(ava, { tag: TAG.SEQUENCE, constructed: true }, 'AttributeTypeAndValue');
      const [typeTlv, valueTlv, ...extra] = children(bytes, ava, 'AttributeTypeAndValue');
      if (!typeTlv || !valueTlv || extra.length) {
        throw parseError(ava.start, 'AttributeTypeAndValue must be exactly { type, value }');
      }
      const oid = readOid(bytes, typeTlv, 'attribute type');
      let value = null;
      try {
        value = readString(bytes, valueTlv, `attribute ${oid}`);
      } catch {
        // Non-string attribute values are legal (rare); render as hex rather than fail a
        // certificate over an attribute we only ever display.
        value = `#${toHex(content(bytes, valueTlv))}`;
      }
      avas.push({ oid, value });
      parts.push(`${ATTR_NAME[oid] ?? oid}=${value}`);
    }
    rdns.push(avas);
  }
  return { bytes: element(bytes, tlv), rdns, text: parts.join(', ') || '<empty name>' };
}

// ------------------------------------------------------------------ GeneralName

/**
 * GeneralName (RFC 5280 s4.2.1.6), used by subjectAltName and nameConstraints. `ipLens` differs
 * by context: SAN carries bare addresses (4/16), name constraints carry address+mask (8/32).
 */
function parseGeneralName(bytes, tlv, ipLens, what) {
  if (tlv.cls !== CLS.CONTEXT) {
    throw parseError(tlv.start,
      `expected context-tagged GeneralName in ${what}, got ${tagName(tlv.cls, tlv.tag)}`);
  }
  const c = content(bytes, tlv);
  switch (tlv.tag) {
    case 1: // rfc822Name, IA5String
    case 2: // dNSName, IA5String
    case 6: { // uniformResourceIdentifier, IA5String
      let s = '';
      for (let i = 0; i < c.byteLength; i++) {
        const b = c[i];
        // An embedded NUL is the null-prefix attack ("example.com\0.evil.test"): parsers that
        // stop at NUL and parsers that do not will disagree about this name. Never tolerated.
        if (b === 0x00) throw parseError(tlv.contentStart + i, `NUL byte in ${what} GeneralName`);
        if (b > 0x7f) {
          throw parseError(tlv.contentStart + i, `non-ASCII byte 0x${b.toString(16)} in ${what} IA5String`);
        }
        s += String.fromCharCode(b);
      }
      return { type: tlv.tag === 1 ? 'email' : tlv.tag === 2 ? 'dns' : 'uri', value: s };
    }
    case 7: { // iPAddress, OCTET STRING
      if (!ipLens.includes(c.byteLength)) {
        throw parseError(
          tlv.start,
          `iPAddress in ${what} must be ${ipLens.join(' or ')} bytes, got ${c.byteLength}`,
        );
      }
      return { type: 'ip', bytes: c };
    }
    case 4: // directoryName (EXPLICIT Name)
      return { type: 'dirName', bytes: c };
    default:
      // otherName [0], x400Address [3], ediPartyName [5], registeredID [8]: recorded so that
      // name-constraint processing can refuse to ignore them when the extension is critical.
      return { type: 'other', tag: tlv.tag };
  }
}

// ------------------------------------------------------------------ extensions

function parseBasicConstraints(valueBytes) {
  const seq = readSequence(valueBytes, 0, 'BasicConstraints');
  if (seq.end !== valueBytes.byteLength) throw parseError(seq.end, 'trailing bytes in BasicConstraints');
  const kids = children(valueBytes, seq, 'BasicConstraints');
  let i = 0;
  let ca = false;
  if (i < kids.length && kids[i].tag === TAG.BOOLEAN && kids[i].cls === CLS.UNIVERSAL) {
    ca = readBoolean(valueBytes, kids[i], 'cA');
    // DER forbids encoding a DEFAULT value; cA FALSE spelled out is a second encoding of the
    // same meaning, which is exactly the ambiguity class this parser exists to refuse.
    if (!ca) throw parseError(kids[i].start, 'cA FALSE must be omitted in DER');
    i++;
  }
  let pathLenConstraint = null;
  if (i < kids.length) {
    const { value, negative } = readInteger(valueBytes, kids[i], 'pathLenConstraint');
    if (negative || value === null) {
      throw parseError(kids[i].start, 'pathLenConstraint must be a small non-negative integer');
    }
    if (!ca) {
      // RFC 5280 s4.2.1.9: pathLenConstraint is only meaningful with cA=TRUE. A constraint on a
      // non-CA is self-contradictory; guessing which half to believe would be failing open.
      throw parseError(kids[i].start, 'pathLenConstraint present without cA TRUE');
    }
    pathLenConstraint = value;
    i++;
  }
  if (i !== kids.length) throw parseError(kids[i].start, 'unexpected extra field in BasicConstraints');
  return { present: true, ca, pathLenConstraint };
}

const KEY_USAGE_BITS = [
  'digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly',
];

/**
 * The nine RFC 5280 s4.2.1.3 bits, each explicit so a validator reads `false`, never
 * `undefined` — an absent bit and an unset bit must be indistinguishable.
 * @typedef {object} KeyUsage
 * @property {boolean} digitalSignature
 * @property {boolean} nonRepudiation
 * @property {boolean} keyEncipherment
 * @property {boolean} dataEncipherment
 * @property {boolean} keyAgreement
 * @property {boolean} keyCertSign
 * @property {boolean} cRLSign
 * @property {boolean} encipherOnly
 * @property {boolean} decipherOnly
 */

/** @returns {KeyUsage} */
function parseKeyUsage(valueBytes) {
  const tlv = readAll(valueBytes, 'KeyUsage');
  const { bytes: bits, unusedBits } = readBitString(valueBytes, tlv, 'KeyUsage');
  const usage = {};
  let any = false;
  for (let i = 0; i < KEY_USAGE_BITS.length; i++) {
    const byte = i >> 3;
    const set =
      byte < bits.byteLength &&
      (byte < bits.byteLength - 1 || (7 - (i & 7)) >= unusedBits) &&
      (bits[byte] & (0x80 >> (i & 7))) !== 0;
    usage[KEY_USAGE_BITS[i]] = set;
    any = any || set;
  }
  // RFC 5280 s4.2.1.3: when the extension appears, at least one bit MUST be set. An all-zero
  // keyUsage asserts "this key may do nothing", which cannot coexist with using the key.
  if (!any) throw parseError(tlv.start, 'KeyUsage extension with no bits set');
  return Object.freeze(usage);
}

function parseExtendedKeyUsage(valueBytes) {
  const seq = readSequence(valueBytes, 0, 'ExtKeyUsageSyntax');
  if (seq.end !== valueBytes.byteLength) throw parseError(seq.end, 'trailing bytes in ExtendedKeyUsage');
  const kids = children(valueBytes, seq, 'ExtKeyUsageSyntax');
  if (kids.length === 0) throw parseError(seq.start, 'empty ExtendedKeyUsage');
  return Object.freeze(kids.map((k) => readOid(valueBytes, k, 'KeyPurposeId')));
}

/**
 * The SAN entries identity matching consults. `present` distinguishes "no SAN extension"
 * (matches nothing, by policy) from "SAN with no entries of this type".
 * @typedef {object} SubjectAltNames
 * @property {boolean} present
 * @property {ReadonlyArray<string>} dns
 * @property {ReadonlyArray<Uint8Array>} ip raw 4- or 16-byte addresses
 * @property {ReadonlyArray<string>} uri
 * @property {ReadonlyArray<string>} email
 */

/** @returns {SubjectAltNames} */
function parseSubjectAltName(valueBytes) {
  const seq = readSequence(valueBytes, 0, 'GeneralNames');
  if (seq.end !== valueBytes.byteLength) throw parseError(seq.end, 'trailing bytes in SubjectAltName');
  const kids = children(valueBytes, seq, 'GeneralNames');
  // RFC 5280 s4.2.1.6: if present, the SAN sequence MUST contain at least one entry.
  if (kids.length === 0) throw parseError(seq.start, 'empty SubjectAltName');
  const dns = [];
  const ip = [];
  const uri = [];
  const email = [];
  for (const k of kids) {
    const gn = parseGeneralName(valueBytes, k, [4, 16], 'subjectAltName');
    if (gn.type === 'dns') dns.push(gn.value);
    else if (gn.type === 'ip') ip.push(gn.bytes);
    else if (gn.type === 'uri') uri.push(gn.value);
    else if (gn.type === 'email') email.push(gn.value);
    // dirName / other entries are legal; nothing in this package matches on them.
  }
  return Object.freeze({ present: true, dns: Object.freeze(dns), ip: Object.freeze(ip),
    uri: Object.freeze(uri), email: Object.freeze(email) });
}

function parseSubjectKeyIdentifier(valueBytes) {
  const tlv = readAll(valueBytes, 'SubjectKeyIdentifier');
  expectTlv(tlv, { tag: TAG.OCTET_STRING, constructed: false }, 'SubjectKeyIdentifier');
  return content(valueBytes, tlv);
}

function parseAuthorityKeyIdentifier(valueBytes) {
  const seq = readSequence(valueBytes, 0, 'AuthorityKeyIdentifier');
  if (seq.end !== valueBytes.byteLength) {
    throw parseError(seq.end, 'trailing bytes in AuthorityKeyIdentifier');
  }
  let keyId = null;
  for (const k of children(valueBytes, seq, 'AuthorityKeyIdentifier')) {
    if (k.cls !== CLS.CONTEXT) {
      throw parseError(k.start, 'AuthorityKeyIdentifier fields must be context-tagged');
    }
    if (k.tag === 0) keyId = content(valueBytes, k); // [0] IMPLICIT KeyIdentifier
    // [1] authorityCertIssuer / [2] authorityCertSerialNumber: parsed past, not used — chain
    // building matches on DN plus keyIdentifier, which is what CAs actually populate.
  }
  return keyId;
}

/**
 * One GeneralSubtree, reduced to what constraint enforcement can act on. 'other' entries are
 * forms this validator cannot enforce; path.js rejects the path when a critical extension
 * carries one, which is why they are preserved rather than dropped.
 * @typedef {{ type: 'dns', value: string } | { type: 'email', value: string }
 *   | { type: 'uri', value: string } | { type: 'ip', addr: Uint8Array, mask: Uint8Array }
 *   | { type: 'other', tag: number }} NameConstraintSubtree
 */

/**
 * @typedef {object} NameConstraints
 * @property {ReadonlyArray<NameConstraintSubtree> | null} permitted
 * @property {ReadonlyArray<NameConstraintSubtree> | null} excluded
 */

/**
 * NameConstraints (RFC 5280 s4.2.1.10). Subtrees we cannot enforce are preserved as
 * `{type:'other'}` entries so path.js can refuse to ignore them when the extension is critical.
 * A GeneralSubtree with minimum != 0 or maximum present is demoted to unsupported for the same
 * reason: RFC 5280 forbids them, and enforcing a constraint we cannot interpret is worse than
 * rejecting.
 *
 * @param {Uint8Array} valueBytes the extnValue content
 * @returns {NameConstraints}
 */
export function parseNameConstraints(valueBytes) {
  const seq = readSequence(valueBytes, 0, 'NameConstraints');
  if (seq.end !== valueBytes.byteLength) throw parseError(seq.end, 'trailing bytes in NameConstraints');
  const kids = children(valueBytes, seq, 'NameConstraints');
  if (kids.length === 0) {
    throw parseError(seq.start, 'NameConstraints with neither permitted nor excluded subtrees');
  }
  const out = { permitted: null, excluded: null };
  for (const k of kids) {
    if (k.cls !== CLS.CONTEXT || (k.tag !== 0 && k.tag !== 1) || !k.constructed) {
      throw parseError(k.start, 'NameConstraints fields must be [0] or [1] GeneralSubtrees');
    }
    const which = k.tag === 0 ? 'permitted' : 'excluded';
    if (out[which] !== null) throw parseError(k.start, `duplicate ${which}Subtrees`);
    const subtrees = [];
    const trees = children(valueBytes, k, 'GeneralSubtrees');
    if (trees.length === 0) throw parseError(k.start, `empty ${which}Subtrees`);
    for (const t of trees) {
      expectTlv(t, { tag: TAG.SEQUENCE, constructed: true }, 'GeneralSubtree');
      const fields = children(valueBytes, t, 'GeneralSubtree');
      if (fields.length === 0) throw parseError(t.start, 'empty GeneralSubtree');
      const gn = parseGeneralName(valueBytes, fields[0], [8, 32], 'nameConstraints');
      const boundsOk = fields.length === 1; // minimum defaults to 0, maximum must be absent
      if (!boundsOk || gn.type === 'dirName') {
        subtrees.push({ type: 'other', tag: fields[0].tag });
      } else if (gn.type === 'ip') {
        const half = gn.bytes.byteLength / 2;
        subtrees.push({ type: 'ip', addr: gn.bytes.subarray(0, half), mask: gn.bytes.subarray(half) });
      } else {
        subtrees.push(gn); // dns / email / uri / other
      }
    }
    out[which] = Object.freeze(subtrees);
  }
  return Object.freeze(out);
}

// ------------------------------------------------------------------ algorithm identifiers

/**
 * AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }.
 *
 * Exported for the OCSP checker, which meets the same structure in BasicOCSPResponse and CertID
 * and must read it with the same strictness rather than a second, slightly different walk.
 *
 * @param {Uint8Array} bytes
 * @param {import('./der.js').Tlv} tlv
 * @param {string} what
 * @returns {AlgorithmId}
 */
export function parseAlgorithmIdentifier(bytes, tlv, what) {
  expectTlv(tlv, { tag: TAG.SEQUENCE, constructed: true }, what);
  const kids = children(bytes, tlv, what);
  if (kids.length < 1 || kids.length > 2) {
    throw parseError(tlv.start, `${what} must be { algorithm, parameters? }`);
  }
  const oid = readOid(bytes, kids[0], `${what} algorithm`);
  const params = kids.length === 2 ? kids[1] : null;
  return {
    oid,
    paramsTlv: params,
    paramsBytes: params ? element(bytes, params) : null,
    bytes: element(bytes, tlv),
  };
}

/**
 * RSASSA-PSS-params (RFC 4055). All fields are EXPLICIT-tagged with SHA-1 defaults, so an absent
 * field *means* SHA-1 — which is why "assume the modern default" is not an option here and every
 * field is resolved before the algorithm is accepted.
 */
function parsePssParams(algo) {
  const empty = { hashOid: OID.sha1, mgfHashOid: OID.sha1, saltLength: 20, trailer: 1 };
  if (!algo.paramsTlv) return empty;
  const bytes = algo.paramsBytes;
  const seq = readAll(bytes, 'RSASSA-PSS-params');
  expectTlv(seq, { tag: TAG.SEQUENCE, constructed: true }, 'RSASSA-PSS-params');
  const out = { ...empty };
  for (const field of children(bytes, seq, 'RSASSA-PSS-params')) {
    if (field.cls !== CLS.CONTEXT || !field.constructed) {
      throw parseError(field.start, 'RSASSA-PSS-params fields must be explicit context tags');
    }
    const inner = readTlv(bytes, field.contentStart);
    if (inner.end !== field.contentEnd) throw parseError(inner.end, 'trailing bytes in PSS parameter');
    switch (field.tag) {
      case 0:
        out.hashOid = parseAlgorithmIdentifier(bytes, inner, 'PSS hashAlgorithm').oid;
        break;
      case 1: {
        const mgf = parseAlgorithmIdentifier(bytes, inner, 'PSS maskGenAlgorithm');
        if (mgf.oid !== OID.mgf1 || !mgf.paramsTlv) {
          throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
            `RSA-PSS mask generation function ${mgf.oid} is not MGF1, refusing`, { oid: mgf.oid });
        }
        out.mgfHashOid = parseAlgorithmIdentifier(bytes, mgf.paramsTlv, 'MGF1 hash').oid;
        break;
      }
      case 2: {
        const { value, negative } = readInteger(bytes, inner, 'PSS saltLength');
        if (negative || value === null) throw parseError(inner.start, 'PSS saltLength out of range');
        out.saltLength = value;
        break;
      }
      case 3: {
        const { value } = readInteger(bytes, inner, 'PSS trailerField');
        out.trailer = value;
        break;
      }
      default:
        throw parseError(field.start, `unknown RSASSA-PSS-params field [${field.tag}]`);
    }
  }
  return out;
}

const PSS_BY_HASH = {
  [OID.sha256]: { scheme: SIG_SCHEME.rsa_pss_rsae_sha256, hash: 'SHA-256', saltLength: 32 },
  [OID.sha384]: { scheme: SIG_SCHEME.rsa_pss_rsae_sha384, hash: 'SHA-384', saltLength: 48 },
  [OID.sha512]: { scheme: SIG_SCHEME.rsa_pss_rsae_sha512, hash: 'SHA-512', saltLength: 64 },
};

const DIRECT_SCHEMES = {
  [OID.sha256WithRsa]: { kind: 'rsa-pkcs1', scheme: SIG_SCHEME.rsa_pkcs1_sha256, name: 'rsa_pkcs1_sha256' },
  [OID.sha384WithRsa]: { kind: 'rsa-pkcs1', scheme: SIG_SCHEME.rsa_pkcs1_sha384, name: 'rsa_pkcs1_sha384' },
  [OID.sha512WithRsa]: { kind: 'rsa-pkcs1', scheme: SIG_SCHEME.rsa_pkcs1_sha512, name: 'rsa_pkcs1_sha512' },
  [OID.ed25519]: { kind: 'ed25519', scheme: SIG_SCHEME.ed25519, name: 'ed25519' },
};

const ECDSA_HASH = {
  [OID.ecdsaWithSha256]: 'SHA-256',
  [OID.ecdsaWithSha384]: 'SHA-384',
  [OID.ecdsaWithSha512]: 'SHA-512',
};

/**
 * How to verify one certificate signature. `scheme` indexes SIG_SCHEME_PARAMS where the OID
 * fully determines it; for ECDSA only the hash is known here and path.js completes the plan
 * from the issuer's curve.
 * @typedef {object} SignaturePlan
 * @property {'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'ed25519'} kind
 * @property {number} [scheme]
 * @property {'SHA-256' | 'SHA-384' | 'SHA-512'} [hash] weaker hashes died in the OID check
 * @property {string} name for error messages
 */

/**
 * Map a certificate's signature algorithm to a verification plan, or throw.
 *
 * Called by path.js exactly when a certificate's signature is about to anchor trust, and by the
 * OCSP checker for a response's own signature — the parameter is therefore the structural subset
 * both can supply, and a full Certificate qualifies as-is. Weak algorithms (MD2/MD4/MD5, SHA-1)
 * are rejected here by OID, before any cryptography runs — some runtimes' verifiers still accept
 * SHA-1 and this one must provably not be among them. ECDSA returns only the hash: in X.509
 * (unlike TLS) the curve belongs to the issuer's key, so path.js completes the plan from the
 * issuer's SPKI.
 *
 * @param {{ signatureAlgorithm: AlgorithmId, subject: { text: string } }} cert
 * @returns {SignaturePlan}
 */
export function resolveSignatureScheme(cert) {
  const { oid } = cert.signatureAlgorithm;
  const weak = WEAK_SIG_OIDS[oid];
  if (weak) {
    throw new CertificateError(codes.CERT_SIGNATURE_WEAK,
      `certificate "${cert.subject.text}" is signed with ${weak} (${oid}); ` +
        'MD-family and SHA-1 signatures are refused',
      { oid, algorithm: weak, subject: cert.subject.text });
  }
  const direct = DIRECT_SCHEMES[oid];
  if (direct) return direct;
  const ecdsaHash = ECDSA_HASH[oid];
  if (ecdsaHash) return { kind: 'ecdsa', hash: ecdsaHash, name: `ecdsa-with-${ecdsaHash}` };
  if (oid === OID.rsassaPss) {
    const p = parsePssParams(cert.signatureAlgorithm);
    if (p.hashOid === OID.sha1 || p.mgfHashOid === OID.sha1) {
      throw new CertificateError(codes.CERT_SIGNATURE_WEAK,
        `certificate "${cert.subject.text}" uses RSA-PSS with SHA-1 ` +
          `(hash ${p.hashOid}, MGF1 hash ${p.mgfHashOid}); SHA-1 signatures are refused`,
        { oid, subject: cert.subject.text });
    }
    const entry = PSS_BY_HASH[p.hashOid];
    if (!entry) {
      throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
        `RSA-PSS hash ${p.hashOid} on "${cert.subject.text}" is not supported`, { oid: p.hashOid });
    }
    // RFC 4055 consistency: MGF1 must run the same hash, the salt must be one hash-length, and
    // the trailer must be 0xBC. Every real PSS certificate satisfies this; the exceptions are
    // parameter-confusion experiments we refuse rather than approximate.
    if (p.mgfHashOid !== p.hashOid) {
      throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
        `RSA-PSS with MGF1 hash ${p.mgfHashOid} != message hash ${p.hashOid}, refusing`,
        { hash: p.hashOid, mgfHash: p.mgfHashOid });
    }
    if (p.saltLength !== entry.saltLength) {
      throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
        `RSA-PSS salt length ${p.saltLength} != hash length ${entry.saltLength}, refusing`,
        { saltLength: p.saltLength, expected: entry.saltLength });
    }
    if (p.trailer !== 1) {
      throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
        `RSA-PSS trailer field ${p.trailer} != 1, refusing`, { trailer: p.trailer });
    }
    return { kind: 'rsa-pss', scheme: entry.scheme, hash: entry.hash, name: `rsa_pss_${entry.hash}` };
  }
  throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
    `signature algorithm ${oid} on "${cert.subject.text}" is not supported`,
    { oid, subject: cert.subject.text });
}

// ------------------------------------------------------------------ SPKI

/**
 * A parsed SubjectPublicKeyInfo. `spkiDer` is the exact original element — the bytes WebCrypto
 * imports and the bytes SPKI pinning hashes, so it must never be a re-encoding.
 * @typedef {object} Spki
 * @property {string} algorithmOid
 * @property {string | null} curveOid named curve, EC keys only
 * @property {Uint8Array} keyBytes the subjectPublicKey payload
 * @property {Uint8Array} spkiDer
 */

/**
 * @param {Uint8Array} bytes
 * @param {import('./der.js').Tlv} tlv
 * @returns {Spki}
 */
function parseSpki(bytes, tlv) {
  expectTlv(tlv, { tag: TAG.SEQUENCE, constructed: true }, 'SubjectPublicKeyInfo');
  const kids = children(bytes, tlv, 'SubjectPublicKeyInfo');
  if (kids.length !== 2) {
    throw parseError(tlv.start, 'SubjectPublicKeyInfo must be { algorithm, subjectPublicKey }');
  }
  const algo = parseAlgorithmIdentifier(bytes, kids[0], 'SPKI algorithm');
  const { unusedBits, bytes: keyBytes } = readBitString(bytes, kids[1], 'subjectPublicKey');
  // Every key type this package can use (RSA, EC points, Ed25519) is a whole number of octets.
  if (unusedBits !== 0) throw parseError(kids[1].start, `subjectPublicKey has ${unusedBits} unused bits`);
  let curveOid = null;
  if (algo.oid === OID.ecPublicKey) {
    if (!algo.paramsTlv || algo.paramsTlv.tag !== TAG.OID) {
      // RFC 5480 allows explicit curve parameters; no public CA uses them, and accepting an
      // attacker-described curve is a known validation trap. Named curves only.
      throw parseError(kids[0].start, 'EC key without a named curve (explicit parameters are refused)');
    }
    curveOid = readOid(bytes, algo.paramsTlv, 'EC named curve');
  }
  return {
    algorithmOid: algo.oid,
    curveOid,
    keyBytes,
    spkiDer: element(bytes, tlv),
  };
}

/**
 * Parse a bare SubjectPublicKeyInfo element (as stored for trust anchors, which persist only the
 * SPKI rather than a whole certificate). Same walk as inside a certificate.
 * @param {Uint8Array} spkiDer
 * @returns {Spki}
 */
export function parseSubjectPublicKeyInfo(spkiDer) {
  return parseSpki(spkiDer, readAll(spkiDer, 'SubjectPublicKeyInfo'));
}

// ------------------------------------------------------------------ certificate

/**
 * The certificate's signatureAlgorithm, with parameters kept both raw and as a Tlv because
 * RSA-PSS resolution has to re-walk them.
 * @typedef {object} AlgorithmId
 * @property {string} oid
 * @property {Uint8Array | null} paramsBytes
 * @property {import('./der.js').Tlv | null} paramsTlv
 * @property {Uint8Array} bytes the whole AlgorithmIdentifier element
 */

/**
 * A fully parsed certificate. Frozen; every byte field is a subarray of the original `der`.
 * This is the complete shape behind the trimmed `ParsedCertificate` documented on the public
 * verifyChain surface.
 * @typedef {object} Certificate
 * @property {Uint8Array} der the original bytes, never re-encoded
 * @property {Uint8Array} tbsBytes exact TBSCertificate slice the signature covers
 * @property {number} version 1, 2 or 3
 * @property {string} serialNumber hex of the INTEGER content bytes
 * @property {boolean} serialNegative negative serials are misissuance but must still parse
 * @property {AlgorithmId} signatureAlgorithm
 * @property {Uint8Array} signature
 * @property {DistinguishedName} issuer
 * @property {DistinguishedName} subject
 * @property {number} notBefore epoch ms
 * @property {number} notAfter epoch ms
 * @property {Spki} spki
 * @property {Map<string, { critical: boolean, valueBytes: Uint8Array }>} extensions by OID
 * @property {{ present: boolean, ca: boolean, pathLenConstraint: number | null }} basicConstraints
 * @property {KeyUsage | null} keyUsage null when the extension is absent
 * @property {ReadonlyArray<string> | null} extendedKeyUsage KeyPurposeId OIDs
 * @property {SubjectAltNames} subjectAltNames
 * @property {Uint8Array | null} subjectKeyIdentifier
 * @property {Uint8Array | null} authorityKeyIdentifier keyIdentifier field only
 * @property {NameConstraints | null} nameConstraints
 * @property {ReadonlyArray<string>} unknownCriticalExtensions OIDs path.js must reject on
 * @property {boolean} isSelfIssued subject DER equals issuer DER
 */

/**
 * Parse one DER certificate into a frozen, fully-walked structure. Throws CertificateError
 * (CERT_PARSE) on malformed or self-contradictory encodings; judgement about what the
 * certificate MAY do lives in path.js.
 *
 * `tbsBytes` is the exact original slice of the TBSCertificate element — signature verification
 * happens over these bytes and never over anything re-encoded.
 *
 * @param {Uint8Array} der
 * @returns {Certificate}
 */
export function parseCertificate(der) {
  if (!(der instanceof Uint8Array)) {
    throw new CertificateError(codes.CERT_PARSE, 'certificate must be a Uint8Array of DER');
  }
  const cert = readAll(der, 'Certificate');
  expectTlv(cert, { tag: TAG.SEQUENCE, constructed: true }, 'Certificate');
  const [tbsTlv, sigAlgTlv, sigTlv, ...extraTop] = children(der, cert, 'Certificate');
  if (!tbsTlv || !sigAlgTlv || !sigTlv || extraTop.length) {
    throw parseError(cert.start,
      'Certificate must be { tbsCertificate, signatureAlgorithm, signatureValue }');
  }
  expectTlv(tbsTlv, { tag: TAG.SEQUENCE, constructed: true }, 'TBSCertificate');
  const outerAlg = parseAlgorithmIdentifier(der, sigAlgTlv, 'signatureAlgorithm');
  const { bytes: signature } = readBitString(der, sigTlv, 'signatureValue');

  const fields = children(der, tbsTlv, 'TBSCertificate');
  let i = 0;
  const next = (what) => {
    if (i >= fields.length) throw parseError(tbsTlv.end, `TBSCertificate ends before ${what}`);
    return fields[i++];
  };

  // version [0] EXPLICIT INTEGER DEFAULT v1(0)
  let version = 1;
  if (fields[0] && fields[0].cls === CLS.CONTEXT && fields[0].tag === 0) {
    const wrapper = next('version');
    if (!wrapper.constructed) throw parseError(wrapper.start, 'version [0] must be constructed (EXPLICIT)');
    const inner = readTlv(der, wrapper.contentStart);
    if (inner.end !== wrapper.contentEnd) throw parseError(inner.end, 'trailing bytes in version');
    const { value, negative } = readInteger(der, inner, 'version');
    if (negative || value === null || value > 2) {
      throw parseError(inner.start, `unsupported certificate version ${negative ? 'negative' : value}`);
    }
    // DER forbids encoding the DEFAULT: version v1 must be expressed by omission.
    if (value === 0) throw parseError(inner.start, 'version v1 must be omitted, not encoded');
    version = value + 1;
  }

  const serialTlv = next('serialNumber');
  const serial = readInteger(der, serialTlv, 'serialNumber');
  const innerAlg = parseAlgorithmIdentifier(der, next('signature'), 'TBSCertificate signature');

  // RFC 5280 s4.1.1.2: outer signatureAlgorithm MUST equal the TBS signature field. A mismatch
  // means someone re-wrapped a signed body under a different algorithm claim — the textbook
  // algorithm-substitution forgery — so the comparison is over full DER bytes, not just OIDs.
  if (!equal(outerAlg.bytes, innerAlg.bytes)) {
    throw new CertificateError(codes.CERT_PARSE,
      `signatureAlgorithm mismatch: outer ${outerAlg.oid} vs tbsCertificate ${innerAlg.oid}` +
        (outerAlg.oid === innerAlg.oid ? ' (same OID, different parameters)' : ''),
      { outer: outerAlg.oid, inner: innerAlg.oid });
  }

  const issuer = parseName(der, next('issuer'));
  const validityTlv = next('validity');
  expectTlv(validityTlv, { tag: TAG.SEQUENCE, constructed: true }, 'Validity');
  const times = children(der, validityTlv, 'Validity');
  if (times.length !== 2) throw parseError(validityTlv.start, 'Validity must be { notBefore, notAfter }');
  // RFC 5280 wants UTCTime through 2049 and GeneralizedTime after; both encodings name an
  // unambiguous instant, so a cert that picked the wrong one is accepted — rejecting it would
  // add availability risk and zero security.
  const notBefore = readTime(der, times[0], 'notBefore');
  const notAfter = readTime(der, times[1], 'notAfter');
  if (notAfter < notBefore) {
    throw parseError(validityTlv.start,
      `notAfter precedes notBefore (${new Date(notAfter).toISOString()} < ` +
        `${new Date(notBefore).toISOString()})`);
  }
  const subject = parseName(der, next('subject'));
  const spki = parseSpki(der, next('subjectPublicKeyInfo'));

  // issuerUniqueID [1] / subjectUniqueID [2] IMPLICIT: legal in v2/v3, obsolete, skipped.
  while (i < fields.length && fields[i].cls === CLS.CONTEXT &&
         (fields[i].tag === 1 || fields[i].tag === 2)) {
    if (version === 1) {
      throw parseError(fields[i].start, 'unique identifiers are not allowed in v1 certificates');
    }
    i++;
  }

  const extensions = new Map();
  let basicConstraints = Object.freeze({ present: false, ca: false, pathLenConstraint: null });
  let keyUsage = null;
  let extendedKeyUsage = null;
  let subjectAltNames = Object.freeze({ present: false, dns: Object.freeze([]), ip: Object.freeze([]),
    uri: Object.freeze([]), email: Object.freeze([]) });
  let subjectKeyIdentifier = null;
  let authorityKeyIdentifier = null;
  let nameConstraints = null;
  const unknownCriticalExtensions = [];

  if (i < fields.length) {
    const wrapper = fields[i++];
    if (wrapper.cls !== CLS.CONTEXT || wrapper.tag !== 3 || !wrapper.constructed) {
      throw parseError(wrapper.start, `unexpected TBSCertificate field ${tagName(wrapper.cls, wrapper.tag)}`);
    }
    if (version !== 3) {
      throw parseError(wrapper.start, `extensions are not allowed in v${version} certificates`);
    }
    const listTlv = readTlv(der, wrapper.contentStart);
    if (listTlv.end !== wrapper.contentEnd) throw parseError(listTlv.end, 'trailing bytes in extensions');
    expectTlv(listTlv, { tag: TAG.SEQUENCE, constructed: true }, 'Extensions');
    const extTlvs = children(der, listTlv, 'Extensions');
    if (extTlvs.length === 0) throw parseError(listTlv.start, 'empty Extensions sequence');
    for (const extTlv of extTlvs) {
      expectTlv(extTlv, { tag: TAG.SEQUENCE, constructed: true }, 'Extension');
      const parts = children(der, extTlv, 'Extension');
      if (parts.length < 2 || parts.length > 3) {
        throw parseError(extTlv.start, 'Extension must be { extnID, critical?, extnValue }');
      }
      const extnId = readOid(der, parts[0], 'extnID');
      let critical = false;
      let valueIdx = 1;
      if (parts.length === 3) {
        critical = readBoolean(der, parts[1], 'critical');
        // DER: critical FALSE is the DEFAULT and must be omitted.
        if (!critical) throw parseError(parts[1].start, 'critical FALSE must be omitted in DER');
        valueIdx = 2;
      }
      expectTlv(parts[valueIdx], { tag: TAG.OCTET_STRING, constructed: false }, 'extnValue');
      const valueBytes = content(der, parts[valueIdx]);
      // RFC 5280 s4.2: at most one instance of each extension. Two copies of keyUsage is two
      // policies for one key; whichever a validator reads, the other was the lie.
      if (extensions.has(extnId)) {
        throw parseError(extTlv.start, `duplicate extension ${extnId}`);
      }
      extensions.set(extnId, Object.freeze({ critical, valueBytes }));

      switch (extnId) {
        case OID.basicConstraints: basicConstraints = Object.freeze(parseBasicConstraints(valueBytes)); break;
        case OID.keyUsage: keyUsage = parseKeyUsage(valueBytes); break;
        case OID.extendedKeyUsage: extendedKeyUsage = parseExtendedKeyUsage(valueBytes); break;
        case OID.subjectAltName: subjectAltNames = parseSubjectAltName(valueBytes); break;
        case OID.subjectKeyIdentifier:
          subjectKeyIdentifier = parseSubjectKeyIdentifier(valueBytes);
          break;
        case OID.authorityKeyIdentifier:
          authorityKeyIdentifier = parseAuthorityKeyIdentifier(valueBytes);
          break;
        case OID.nameConstraints: nameConstraints = parseNameConstraints(valueBytes); break;
        default:
          if (critical && !KNOWN_EXTENSIONS.has(extnId)) unknownCriticalExtensions.push(extnId);
      }
    }
  }
  if (i !== fields.length) {
    throw parseError(fields[i].start, 'unexpected trailing TBSCertificate field');
  }

  return Object.freeze({
    der,
    tbsBytes: element(der, tbsTlv),
    version,
    serialNumber: toHex(serial.bytes),
    serialNegative: serial.negative,
    signatureAlgorithm: Object.freeze({
      oid: outerAlg.oid,
      paramsBytes: outerAlg.paramsBytes,
      paramsTlv: outerAlg.paramsTlv,
      bytes: outerAlg.bytes,
    }),
    signature,
    issuer: Object.freeze(issuer),
    subject: Object.freeze(subject),
    notBefore,
    notAfter,
    spki: Object.freeze(spki),
    extensions,
    basicConstraints,
    keyUsage,
    extendedKeyUsage,
    subjectAltNames,
    subjectKeyIdentifier,
    authorityKeyIdentifier,
    nameConstraints,
    unknownCriticalExtensions: Object.freeze(unknownCriticalExtensions),
    isSelfIssued: equal(subject.bytes, issuer.bytes),
  });
}

// ------------------------------------------------------------------ PEM

const PEM_RE = /-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----/g;

/**
 * Extract every CERTIFICATE block from PEM text as DER. Used for user-supplied trust anchors;
 * TLS itself always delivers DER. Throws CERT_PARSE on bad base64 or when no block is found.
 * @param {string} text
 * @returns {Uint8Array[]}
 */
export function decodePem(text) {
  const out = [];
  for (const match of String(text).matchAll(PEM_RE)) {
    const b64 = match[1].replace(/\s+/g, '');
    let bin;
    try {
      bin = atob(b64);
    } catch {
      throw new CertificateError(codes.CERT_PARSE,
        `PEM certificate block ${out.length + 1} is not valid base64`);
    }
    const der = new Uint8Array(bin.length);
    for (let j = 0; j < bin.length; j++) der[j] = bin.charCodeAt(j);
    out.push(der);
  }
  if (out.length === 0) {
    throw new CertificateError(codes.CERT_PARSE, 'no CERTIFICATE blocks found in PEM input');
  }
  return out;
}
