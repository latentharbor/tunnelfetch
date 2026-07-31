// Stapled OCSP response verification (RFC 6960), on the strict DER reader.
//
// Why stapling, and only stapling. Revocation information can also be fetched from the CA's own
// responder or pulled as CRLs, and both are wrong for this package: a responder fetch is an
// extra network round trip in the middle of a metered handshake, made through the caller's
// proxy, and it tells the CA which origins the caller talks to — an unacceptable default twice
// over; CRLs are megabytes of list to download and cache on a runtime with no cross-request
// storage. A stapled response costs nothing extra: the server includes a CA-signed, time-stamped
// OCSP response in the handshake it was already sending (RFC 6066 s8 for TLS 1.2, RFC 8446
// s4.4.2.1 for TLS 1.3), and this module decides whether that response actually proves anything.
//
// The threat model, which dictates every check below: the staple arrives from THE SAME PEER we
// are trying to authenticate. Until its signature is verified against a key the certification
// path already vouches for, it is attacker-controlled bytes shaped like good news. So a staple
// is believed only when ALL of the following hold, and every other outcome is a typed error:
//
//   1. It parses as strict DER (this is a hostile-input parser exactly like x509.js, and is held
//      to the same standard: reject ambiguity, reject trailing bytes, reject encoded DEFAULTs).
//   2. Its CertID matches the certificate in hand — issuer name hash, issuer key hash, and
//      serial — computed from OUR copy of the validated path, not from anything the response
//      says about itself.
//   3. Its signature verifies against the issuing CA's key, or against a delegated responder
//      certificate that the issuing CA signed DIRECTLY and marked with the id-kp-OCSPSigning
//      extended key usage (RFC 6960 s4.2.2.2). Without the EKU requirement, any TLS certificate
//      the CA ever issued could mint "good" responses for its siblings.
//   4. Its validity window (thisUpdate / nextUpdate) covers the caller-injected `now` — never a
//      wall clock, which on the target runtime is frozen per-slice and lies.
//
// Only then is the verdict read, and the verdict is not negotiable: `good` continues, `revoked`
// and `unknown` both refuse the connection. Treating `unknown` as anything but a failure would
// let a responder shrug a revoked serial back to life.
//
// What stapling deliberately cannot do — an attacker who can strip the staple entirely — is a
// policy question, not a verification one, and lives with the trust configuration in index.js.

import { CertificateError, codes } from '../errors.js';
import { equal, toHex } from '../util/bytes.js';
import {
  TAG,
  CLS,
  readTlv,
  readAll,
  children,
  content,
  element,
  expectTlv,
  readInteger,
  readOid,
  readBitString,
  readBoolean,
  readGeneralizedTime,
  parseError,
  tagName,
} from './der.js';
import {
  OID,
  parseAlgorithmIdentifier,
  parseCertificate,
  parseSubjectPublicKeyInfo,
} from './x509.js';
import { verifySignedObject } from './path.js';

// Clock skew tolerated when judging the validity window. The responder's clock and the caller's
// injected `now` are different machines; a response produced seconds ago must not read as "from
// the future" on a slightly slow clock. Five minutes is the ballpark every deployed validator
// uses, and it is far below the days-long windows real responders publish.
const CLOCK_SKEW_MS = 5 * 60 * 1000;

// RFC 6960 s2.4 reads an absent nextUpdate as "newer revocation information is available all the
// time", which taken literally makes every such response stale the moment it is stapled. Real
// CAs that omit nextUpdate expect polling clients; for a staple the fail-closed reading with a
// tolerance is a hard age cap from thisUpdate. Ten days matches mozilla::pkix's
// maxOCSPLifetimeInDays, the most-reviewed fail-closed figure in deployment.
const MAX_AGE_WITHOUT_NEXT_UPDATE_MS = 10 * 24 * 3600 * 1000;

const RESPONSE_STATUS_NAME = {
  0: 'successful',
  1: 'malformedRequest',
  2: 'internalError',
  3: 'tryLater',
  5: 'sigRequired',
  6: 'unauthorized',
};

/** RFC 5280 s5.3.1 CRLReason values, for naming why a certificate was revoked. */
const CRL_REASON_NAME = {
  0: 'unspecified',
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  8: 'removeFromCRL',
  9: 'privilegeWithdrawn',
  10: 'aACompromise',
};

/**
 * CertID hash algorithms understood, with the digest length each must produce.
 *
 * SHA-1 is accepted HERE and nowhere else in this package, deliberately: the CertID hash is a
 * lookup key, not a trust decision. What binds the response to the certificate is the CA's
 * signature over the whole ResponseData; the hashes only say which issuer/serial the signed
 * statement is about, the serial itself travels unhashed, and both hash inputs (issuer name,
 * issuer key) are fixed by the CA rather than attacker-chosen — so a SHA-1 collision buys
 * nothing. Meanwhile RFC 5019, the profile production responders actually implement, mandates
 * SHA-1 CertIDs; refusing them would refuse essentially every real staple.
 */
const CERTID_HASH = {
  [OID.sha1]: { name: 'SHA-1', length: 20 },
  [OID.sha256]: { name: 'SHA-256', length: 32 },
  [OID.sha384]: { name: 'SHA-384', length: 48 },
  [OID.sha512]: { name: 'SHA-512', length: 64 },
};

const iso = (ms) => new Date(ms).toISOString();

const ocspError = (code, message, detail) => new CertificateError(code, message, detail);

/** ENUMERATED with the small non-negative range OCSP uses. Anything else is out of protocol. */
function readEnumerated(bytes, tlv, what) {
  expectTlv(tlv, { tag: TAG.ENUMERATED, constructed: false }, what);
  const c = content(bytes, tlv);
  // INTEGER encoding rules apply; every value the protocol defines fits one non-negative byte,
  // so a longer (or high-bit) encoding is either non-minimal or out of range. Both are refused.
  if (c.byteLength !== 1 || c[0] > 0x7f) {
    throw parseError(tlv.start, `${what} must be a single byte in 0..127`);
  }
  return c[0];
}

/** NULL parameters (or absent) — the only AlgorithmIdentifier parameters a digest OID takes. */
function requireNullOrAbsentParams(algo, what) {
  const p = algo.paramsTlv;
  if (p === null) return;
  if (p.cls === CLS.UNIVERSAL && p.tag === TAG.NULL && !p.constructed &&
      p.contentStart === p.contentEnd) {
    return;
  }
  throw parseError(p.start, `${what} parameters must be NULL or absent`);
}

/**
 * Extension walk shared by responseExtensions and singleExtensions. `recognized` names the OIDs
 * whose semantics this module has judged and may ignore; an unrecognized CRITICAL extension
 * rejects the response (RFC 6960 s4.4, same fail-closed stance as RFC 5280 s6.1) because an
 * extension we cannot read may change the meaning of everything we can.
 */
function checkExtensions(bytes, wrapper, recognized, what) {
  const inner = explicitInner(bytes, wrapper, what);
  expectTlv(inner, { tag: TAG.SEQUENCE, constructed: true }, what);
  const seen = new Set();
  for (const extTlv of children(bytes, inner, what)) {
    expectTlv(extTlv, { tag: TAG.SEQUENCE, constructed: true }, 'Extension');
    const parts = children(bytes, extTlv, 'Extension');
    if (parts.length < 2 || parts.length > 3) {
      throw parseError(extTlv.start, 'Extension must be { extnID, critical?, extnValue }');
    }
    const extnId = readOid(bytes, parts[0], 'extnID');
    let critical = false;
    if (parts.length === 3) {
      critical = readBoolean(bytes, parts[1], 'critical');
      if (!critical) throw parseError(parts[1].start, 'critical FALSE must be omitted in DER');
    }
    expectTlv(parts[parts.length - 1], { tag: TAG.OCTET_STRING, constructed: false }, 'extnValue');
    if (seen.has(extnId)) throw parseError(extTlv.start, `duplicate extension ${extnId} in ${what}`);
    seen.add(extnId);
    if (critical && !recognized.has(extnId)) {
      throw ocspError(codes.OCSP_PARSE,
        `stapled OCSP response carries unrecognized critical extension ${extnId} in ${what}; ` +
          'RFC 6960 s4.4 requires rejection rather than a guess at its meaning',
        { oid: extnId, where: what });
    }
  }
}

// A nonce (RFC 6960 s4.4.1) binds a response to the request that carried the nonce. A staple
// answers no request of ours, so there is nothing to match and the extension imposes nothing —
// recognized, and deliberately inert.
const RECOGNIZED_RESPONSE_EXTENSIONS = new Set([OID.ocspNonce]);
const RECOGNIZED_SINGLE_EXTENSIONS = new Set();

/**
 * CertID (RFC 6960 s4.1.1): which certificate a SingleResponse is talking about.
 * @typedef {object} OcspCertId
 * @property {string} hashOid
 * @property {Uint8Array} issuerNameHash
 * @property {Uint8Array} issuerKeyHash
 * @property {Uint8Array} serialBytes INTEGER content bytes, minimal DER
 */

/**
 * One SingleResponse, parsed. Times are epoch ms.
 * @typedef {object} OcspSingleResponse
 * @property {OcspCertId} certId
 * @property {{ kind: 'good' } | { kind: 'unknown' }
 *   | { kind: 'revoked', revocationTime: number, reason: number | null }} status
 * @property {number} thisUpdate
 * @property {number | null} nextUpdate
 */

/**
 * A parsed BasicOCSPResponse. `tbsBytes` is the exact original ResponseData element — the bytes
 * the signature covers, never re-encoded.
 * @typedef {object} OcspBasicResponse
 * @property {Uint8Array} tbsBytes
 * @property {import('./x509.js').AlgorithmId} signatureAlgorithm
 * @property {Uint8Array} signature
 * @property {{ kind: 'name', nameBytes: Uint8Array } | { kind: 'key', keyHash: Uint8Array }} responderId
 * @property {number} producedAt epoch ms
 * @property {OcspSingleResponse[]} singles
 * @property {import('./x509.js').Certificate[]} certs attached responder certificates, parsed
 */

/**
 * @typedef {object} OcspResponse
 * @property {number} responseStatus
 * @property {string} responseStatusName
 * @property {OcspBasicResponse | null} basic null exactly when responseStatus != successful
 */

function parseCertId(bytes, tlv) {
  expectTlv(tlv, { tag: TAG.SEQUENCE, constructed: true }, 'CertID');
  const kids = children(bytes, tlv, 'CertID');
  if (kids.length !== 4) {
    throw parseError(tlv.start,
      'CertID must be { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }');
  }
  const algo = parseAlgorithmIdentifier(bytes, kids[0], 'CertID hashAlgorithm');
  requireNullOrAbsentParams(algo, 'CertID hashAlgorithm');
  expectTlv(kids[1], { tag: TAG.OCTET_STRING, constructed: false }, 'issuerNameHash');
  expectTlv(kids[2], { tag: TAG.OCTET_STRING, constructed: false }, 'issuerKeyHash');
  const serial = readInteger(bytes, kids[3], 'CertID serialNumber');
  return {
    hashOid: algo.oid,
    issuerNameHash: content(bytes, kids[1]),
    issuerKeyHash: content(bytes, kids[2]),
    serialBytes: serial.bytes,
  };
}

function parseCertStatus(bytes, tlv) {
  if (tlv.cls !== CLS.CONTEXT) {
    throw parseError(tlv.start,
      `expected a context-tagged CertStatus, got ${tagName(tlv.cls, tlv.tag)}`);
  }
  switch (tlv.tag) {
    case 0: // good [0] IMPLICIT NULL
    case 2: { // unknown [2] IMPLICIT UnknownInfo (NULL)
      if (tlv.constructed || tlv.contentStart !== tlv.contentEnd) {
        throw parseError(tlv.start, `CertStatus [${tlv.tag}] must be an empty primitive (NULL)`);
      }
      return tlv.tag === 0 ? { kind: 'good' } : { kind: 'unknown' };
    }
    case 1: { // revoked [1] IMPLICIT RevokedInfo
      if (!tlv.constructed) throw parseError(tlv.start, 'RevokedInfo must be constructed');
      const kids = children(bytes, tlv, 'RevokedInfo');
      if (kids.length < 1 || kids.length > 2) {
        throw parseError(tlv.start, 'RevokedInfo must be { revocationTime, revocationReason? }');
      }
      const revocationTime = readGeneralizedTime(bytes, kids[0], 'revocationTime');
      let reason = null;
      if (kids.length === 2) {
        const wrap = kids[1];
        if (wrap.cls !== CLS.CONTEXT || wrap.tag !== 0 || !wrap.constructed) {
          throw parseError(wrap.start, 'revocationReason must be [0] EXPLICIT CRLReason');
        }
        reason = readEnumerated(bytes, explicitInner(bytes, wrap, 'revocationReason'), 'CRLReason');
      }
      return { kind: 'revoked', revocationTime, reason };
    }
    default:
      throw parseError(tlv.start, `unknown CertStatus tag [${tlv.tag}]`);
  }
}

function parseSingleResponse(bytes, tlv) {
  expectTlv(tlv, { tag: TAG.SEQUENCE, constructed: true }, 'SingleResponse');
  const kids = children(bytes, tlv, 'SingleResponse');
  let i = 0;
  const next = (what) => {
    if (i >= kids.length) throw parseError(tlv.end, `SingleResponse ends before ${what}`);
    return kids[i++];
  };
  const certId = parseCertId(bytes, next('certID'));
  const status = parseCertStatus(bytes, next('certStatus'));
  const thisUpdate = readGeneralizedTime(bytes, next('thisUpdate'), 'thisUpdate');
  let nextUpdate = null;
  if (i < kids.length && kids[i].cls === CLS.CONTEXT && kids[i].tag === 0) {
    const wrap = kids[i++];
    if (!wrap.constructed) throw parseError(wrap.start, 'nextUpdate must be [0] EXPLICIT');
    nextUpdate = readGeneralizedTime(bytes, explicitInner(bytes, wrap, 'nextUpdate'), 'nextUpdate');
    if (nextUpdate < thisUpdate) {
      // A window that ends before it begins is self-contradictory; there is no correct half to
      // believe, so neither is believed.
      throw parseError(wrap.start,
        `nextUpdate ${iso(nextUpdate)} precedes thisUpdate ${iso(thisUpdate)}`);
    }
  }
  if (i < kids.length && kids[i].cls === CLS.CONTEXT && kids[i].tag === 1) {
    checkExtensions(bytes, kids[i++], RECOGNIZED_SINGLE_EXTENSIONS, 'singleExtensions');
  }
  if (i !== kids.length) throw parseError(kids[i].start, 'unexpected trailing SingleResponse field');
  return { certId, status, thisUpdate, nextUpdate };
}

/** [tag] EXPLICIT wrapper: exactly one inner element filling the wrapper's content. */
function explicitInner(bytes, wrap, what) {
  const inner = readTlv(bytes, wrap.contentStart);
  if (inner.end !== wrap.contentEnd) throw parseError(inner.end, `trailing bytes in ${what}`);
  return inner;
}

function parseResponseData(bytes, tlv) {
  expectTlv(tlv, { tag: TAG.SEQUENCE, constructed: true }, 'ResponseData');
  const kids = children(bytes, tlv, 'ResponseData');
  let i = 0;
  const next = (what) => {
    if (i >= kids.length) throw parseError(tlv.end, `ResponseData ends before ${what}`);
    return kids[i++];
  };
  if (i < kids.length && kids[i].cls === CLS.CONTEXT && kids[i].tag === 0 && kids[i].constructed) {
    // version [0] EXPLICIT Version DEFAULT v1. Only v1 exists, so an encoded version is either
    // the forbidden DEFAULT (DER: must be omitted) or a version this parser cannot promise to
    // understand. Both die, each with its own accurate story.
    const inner = explicitInner(bytes, next('version'), 'version');
    const { value, negative } = readInteger(bytes, inner, 'ResponseData version');
    if (!negative && value === 0) {
      throw parseError(inner.start, 'ResponseData version v1 must be omitted (DEFAULT) in DER');
    }
    throw parseError(inner.start,
      `unsupported ResponseData version ${negative ? 'negative' : value}; only v1 is defined`);
  }
  const ridTlv = next('responderID');
  let responderId;
  if (ridTlv.cls === CLS.CONTEXT && ridTlv.tag === 1 && ridTlv.constructed) {
    const inner = explicitInner(bytes, ridTlv, 'responderID');
    expectTlv(inner, { tag: TAG.SEQUENCE, constructed: true }, 'ResponderID byName');
    responderId = { kind: 'name', nameBytes: element(bytes, inner) };
  } else if (ridTlv.cls === CLS.CONTEXT && ridTlv.tag === 2 && ridTlv.constructed) {
    const inner = explicitInner(bytes, ridTlv, 'responderID');
    expectTlv(inner, { tag: TAG.OCTET_STRING, constructed: false }, 'ResponderID byKey');
    const keyHash = content(bytes, inner);
    // KeyHash is defined as the SHA-1 of the responder's public key; any other length cannot be
    // one and could never match anything, so it is refused at parse rather than mismatched later.
    if (keyHash.byteLength !== 20) {
      throw parseError(inner.start, `ResponderID byKey must be a 20-byte SHA-1 KeyHash, got ${keyHash.byteLength}`);
    }
    responderId = { kind: 'key', keyHash };
  } else {
    throw parseError(ridTlv.start,
      `responderID must be [1] byName or [2] byKey, got ${tagName(ridTlv.cls, ridTlv.tag)}`);
  }
  const producedAt = readGeneralizedTime(bytes, next('producedAt'), 'producedAt');
  const listTlv = next('responses');
  expectTlv(listTlv, { tag: TAG.SEQUENCE, constructed: true }, 'responses');
  const singles = children(bytes, listTlv, 'responses').map((s) => parseSingleResponse(bytes, s));
  if (i < kids.length && kids[i].cls === CLS.CONTEXT && kids[i].tag === 1) {
    checkExtensions(bytes, kids[i++], RECOGNIZED_RESPONSE_EXTENSIONS, 'responseExtensions');
  }
  if (i !== kids.length) throw parseError(kids[i].start, 'unexpected trailing ResponseData field');
  return { responderId, producedAt, singles };
}

function parseBasicResponse(bytes) {
  const outer = readAll(bytes, 'BasicOCSPResponse');
  expectTlv(outer, { tag: TAG.SEQUENCE, constructed: true }, 'BasicOCSPResponse');
  const kids = children(bytes, outer, 'BasicOCSPResponse');
  if (kids.length < 3 || kids.length > 4) {
    throw parseError(outer.start,
      'BasicOCSPResponse must be { tbsResponseData, signatureAlgorithm, signature, certs? }');
  }
  const tbsTlv = expectTlv(kids[0], { tag: TAG.SEQUENCE, constructed: true }, 'tbsResponseData');
  const { responderId, producedAt, singles } = parseResponseData(bytes, tbsTlv);
  const signatureAlgorithm = parseAlgorithmIdentifier(bytes, kids[1], 'OCSP signatureAlgorithm');
  const { bytes: signature } = readBitString(bytes, kids[2], 'OCSP signature');
  const certs = [];
  if (kids.length === 4) {
    const wrap = kids[3];
    if (wrap.cls !== CLS.CONTEXT || wrap.tag !== 0 || !wrap.constructed) {
      throw parseError(wrap.start, 'BasicOCSPResponse certs must be [0] EXPLICIT');
    }
    const inner = explicitInner(bytes, wrap, 'certs');
    expectTlv(inner, { tag: TAG.SEQUENCE, constructed: true }, 'certs');
    for (const [index, certTlv] of children(bytes, inner, 'certs').entries()) {
      try {
        certs.push(parseCertificate(element(bytes, certTlv)));
      } catch (e) {
        // An attached blob that is not a certificate cannot vouch for anything, and tolerating
        // it would mean carrying unparseable bytes into a trust decision.
        throw new CertificateError(codes.CERT_PARSE,
          `attached certificate ${index} in BasicOCSPResponse.certs does not parse: ` +
            `${e?.message ?? e}`,
          { index });
      }
    }
  }
  return {
    tbsBytes: element(bytes, tbsTlv),
    signatureAlgorithm,
    signature,
    responderId,
    producedAt,
    singles,
    certs,
  };
}

/**
 * Parse a DER OCSPResponse (RFC 6960 s4.2.1) into a fully-walked structure.
 *
 * A parser, not a judge, exactly like parseCertificate: it throws OCSP_PARSE on malformed or
 * self-contradictory bytes and on constructs this package refuses to interpret (unknown
 * responseType, unrecognized critical extensions); whether the parsed response is TRUE is
 * verifyOcspStaple's problem.
 *
 * @param {Uint8Array} der
 * @returns {OcspResponse}
 */
export function parseOcspResponse(der) {
  try {
    if (!(der instanceof Uint8Array)) {
      throw parseError(0, 'OCSP response must be a Uint8Array of DER');
    }
    const outer = readAll(der, 'OCSPResponse');
    expectTlv(outer, { tag: TAG.SEQUENCE, constructed: true }, 'OCSPResponse');
    const kids = children(der, outer, 'OCSPResponse');
    if (kids.length < 1 || kids.length > 2) {
      throw parseError(outer.start, 'OCSPResponse must be { responseStatus, responseBytes? }');
    }
    const responseStatus = readEnumerated(der, kids[0], 'responseStatus');
    const responseStatusName = RESPONSE_STATUS_NAME[responseStatus] ?? 'unknown status';
    if (responseStatus !== 0) {
      if (kids.length !== 1) {
        // RFC 6960 s4.2.1: on error the responseBytes field is not set. A non-success status
        // dragging a response body along is two stories in one message.
        throw parseError(kids[1].start,
          `OCSPResponse with responseStatus ${responseStatusName}(${responseStatus}) must not carry responseBytes`);
      }
      return { responseStatus, responseStatusName, basic: null };
    }
    if (kids.length !== 2) {
      throw parseError(outer.start, 'successful OCSPResponse is missing responseBytes');
    }
    const wrap = kids[1];
    if (wrap.cls !== CLS.CONTEXT || wrap.tag !== 0 || !wrap.constructed) {
      throw parseError(wrap.start, 'responseBytes must be [0] EXPLICIT');
    }
    const inner = explicitInner(der, wrap, 'responseBytes');
    expectTlv(inner, { tag: TAG.SEQUENCE, constructed: true }, 'ResponseBytes');
    const [typeTlv, respTlv, ...extra] = children(der, inner, 'ResponseBytes');
    if (!typeTlv || !respTlv || extra.length) {
      throw parseError(inner.start, 'ResponseBytes must be { responseType, response }');
    }
    const responseType = readOid(der, typeTlv, 'responseType');
    if (responseType !== OID.ocspBasic) {
      throw parseError(typeTlv.start,
        `responseType ${responseType} is not id-pkix-ocsp-basic (${OID.ocspBasic}); no other ` +
          'response type is defined for stapling');
    }
    expectTlv(respTlv, { tag: TAG.OCTET_STRING, constructed: false }, 'response');
    const basic = parseBasicResponse(content(der, respTlv));
    return { responseStatus, responseStatusName, basic };
  } catch (e) {
    // Low-level DER failures arrive as CERT_PARSE from der.js/x509.js; re-badge them so a caller
    // switching on codes sees one story for "the staple did not parse", with the byte-precise
    // message preserved.
    if (e instanceof CertificateError && e.code === codes.CERT_PARSE) {
      throw ocspError(codes.OCSP_PARSE,
        `stapled OCSP response is malformed: ${e.message}`, e.detail);
    }
    throw e;
  }
}

/**
 * The issuer of the certificate under check, reduced to what OCSP verification needs. Built by
 * the caller from the VALIDATED path — the certificate that actually signed the leaf, or the
 * trust anchor when the leaf sits directly under one — never from the unverified wire chain.
 * @typedef {object} OcspIssuer
 * @property {Uint8Array} subjectBytes exact subject Name DER
 * @property {Uint8Array} spkiDer SubjectPublicKeyInfo DER
 * @property {string} subjectText for error messages
 */

/**
 * What a verified `good` staple reports. Every other outcome throws; there is no boolean.
 * @typedef {object} OcspVerdict
 * @property {'good'} status
 * @property {number} producedAt epoch ms
 * @property {number} thisUpdate epoch ms
 * @property {number | null} nextUpdate epoch ms
 * @property {boolean} delegated whether a delegated responder certificate signed, rather than
 *   the CA key itself
 */

const describeResponderId = (rid) =>
  rid.kind === 'name'
    ? `responder name ${toHex(rid.nameBytes).slice(0, 40)}…`
    : `responder key hash ${toHex(rid.keyHash)}`;

/**
 * Verify a stapled OCSP response against the certificate it must vouch for.
 *
 * Every check the module comment promises happens here, in this order: parse, match the CertID
 * to `leaf`/`issuer`, establish the signer (the CA itself or an RFC 6960 s4.2.2.2 delegated
 * responder), verify the signature over the original tbsResponseData bytes, and only then read
 * the verdict and its freshness window. `revoked` and `unknown` always throw; `good` throws
 * unless the window covers `now`.
 *
 * @param {object} args
 * @param {Uint8Array} args.staple DER OCSPResponse, exactly as the peer stapled it
 * @param {import('./x509.js').Certificate} args.leaf the validated leaf the staple must cover
 * @param {OcspIssuer} args.issuer the leaf's issuer, from the validated path
 * @param {number} args.now epoch ms, injected — never a wall clock read here
 * @returns {Promise<OcspVerdict>} every failure throws a typed CertificateError (OCSP_* codes)
 */
export async function verifyOcspStaple({ staple, leaf, issuer, now }) {
  const parsed = parseOcspResponse(staple);
  const serialHex = leaf.serialNumber;
  if (parsed.responseStatus !== 0) {
    // tryLater and friends are unsigned refusals. As a staple they prove nothing about the
    // certificate — and an attacker holding a revoked certificate would love them to count as
    // "checked". A server that staples one has stapled nothing of value, and a staple that IS
    // present must be valid (see the policy in trust/index.js).
    throw ocspError(codes.OCSP_UNVERIFIED,
      `stapled OCSPResponse has responseStatus ${parsed.responseStatusName}` +
        `(${parsed.responseStatus}); only successful(0) carries a signed certificate status, so ` +
        `it cannot vouch for serial 0x${serialHex}`,
      { responseStatus: parsed.responseStatus, serial: serialHex });
  }
  const basic = /** @type {OcspBasicResponse} */ (parsed.basic);

  // --- 1. CertID: is this response about the certificate in hand? -----------------------------
  // The hashes are recomputed from OUR validated material: the leaf's issuer Name exactly as the
  // leaf encodes it (RFC 6960 s4.1.1 hashes the issuer field of the certificate being checked)
  // and the issuer's public key bit-string content from the validated path. Nothing the response
  // asserts about identity is taken at its word.
  const issuerKeyBytes = parseSubjectPublicKeyInfo(issuer.spkiDer).keyBytes;
  /** @type {Map<string, { nameHash: Uint8Array, keyHash: Uint8Array }>} */
  const digestCache = new Map();
  const hashesFor = async (name) => {
    let entry = digestCache.get(name);
    if (!entry) {
      entry = {
        nameHash: new Uint8Array(await crypto.subtle.digest(name, leaf.issuer.bytes)),
        keyHash: new Uint8Array(await crypto.subtle.digest(name, issuerKeyBytes)),
      };
      digestCache.set(name, entry);
    }
    return entry;
  };

  let single = null;
  const covered = [];
  for (const s of basic.singles) {
    const alg = CERTID_HASH[s.certId.hashOid];
    if (!alg) {
      throw ocspError(codes.OCSP_PARSE,
        `stapled OCSP response uses CertID hash algorithm ${s.certId.hashOid}, which is not ` +
          'supported (SHA-1, SHA-256, SHA-384 and SHA-512 are)',
        { oid: s.certId.hashOid });
    }
    if (s.certId.issuerNameHash.byteLength !== alg.length ||
        s.certId.issuerKeyHash.byteLength !== alg.length) {
      throw ocspError(codes.OCSP_PARSE,
        `stapled OCSP response CertID declares ${alg.name} but carries ` +
          `${s.certId.issuerNameHash.byteLength}/${s.certId.issuerKeyHash.byteLength}-byte hashes`,
        { oid: s.certId.hashOid });
    }
    covered.push(`serial 0x${toHex(s.certId.serialBytes)} (${alg.name})`);
    if (toHex(s.certId.serialBytes) !== serialHex) continue;
    const { nameHash, keyHash } = await hashesFor(alg.name);
    if (equal(nameHash, s.certId.issuerNameHash) && equal(keyHash, s.certId.issuerKeyHash)) {
      single = s;
      break;
    }
  }
  if (single === null) {
    throw ocspError(codes.OCSP_MISMATCH,
      `stapled OCSP response does not cover certificate serial 0x${serialHex} issued by ` +
        `"${issuer.subjectText}"; it covers ${covered.length ? covered.join(', ') : 'no certificates'}. ` +
        'A response for a different certificate proves nothing about this one',
      { serial: serialHex, covered });
  }

  // --- 2. Who signed, and are they allowed to? ------------------------------------------------
  const sha1 = async (b) => new Uint8Array(await crypto.subtle.digest('SHA-1', b));
  const rid = basic.responderId;
  const signedByIssuer = rid.kind === 'name'
    ? equal(rid.nameBytes, issuer.subjectBytes)
    : equal(rid.keyHash, await sha1(issuerKeyBytes));

  let signerSpkiDer;
  let signerText;
  let delegated = false;
  if (signedByIssuer) {
    signerSpkiDer = issuer.spkiDer;
    signerText = issuer.subjectText;
  } else {
    // RFC 6960 s4.2.2.2 (Authorized Responders): a responder other than the CA must present a
    // certificate that the CA that issued the leaf issued DIRECTLY, carrying id-kp-OCSPSigning.
    // Each requirement below closes a specific hole, named where it is enforced.
    let responder = null;
    for (const cert of basic.certs) {
      const match = rid.kind === 'name'
        ? equal(cert.subject.bytes, rid.nameBytes)
        : equal(await sha1(cert.spki.keyBytes), rid.keyHash);
      if (match) {
        responder = cert;
        break;
      }
    }
    if (responder === null) {
      throw ocspError(codes.OCSP_UNVERIFIED,
        `stapled OCSP response is signed by ${describeResponderId(rid)}, which is neither the ` +
          `issuing CA "${issuer.subjectText}" nor any certificate attached to the response; ` +
          'there is no key to verify it against',
        { serial: serialHex });
    }
    const subject = responder.subject.text;
    if (!equal(responder.issuer.bytes, issuer.subjectBytes)) {
      // Without direct issuance, any CA anywhere could bless a "responder" for this CA's
      // certificates. The trust in a delegated responder flows from exactly one place: the CA
      // whose certificate is being checked.
      throw ocspError(codes.OCSP_UNVERIFIED,
        `OCSP responder certificate "${subject}" was issued by "${responder.issuer.text}", not ` +
          `by "${issuer.subjectText}" which issued the certificate being checked; RFC 6960 ` +
          's4.2.2.2 requires direct issuance',
        { responder: subject });
    }
    // The EKU must name id-kp-OCSPSigning explicitly; anyExtendedKeyUsage does not count here.
    // Without this check, every ordinary TLS certificate the CA issued could sign "good"
    // responses for every other — key compromise of any customer would defeat revocation itself.
    if (!responder.extendedKeyUsage || !responder.extendedKeyUsage.includes(OID.ocspSigning)) {
      throw ocspError(codes.OCSP_UNVERIFIED,
        `OCSP responder certificate "${subject}" does not carry the id-kp-OCSPSigning extended ` +
          `key usage (has: ${responder.extendedKeyUsage?.join(', ') ?? 'no EKU'}); a certificate ` +
          'the CA did not designate for OCSP signing cannot answer for its revocations',
        { responder: subject, eku: responder.extendedKeyUsage ? [...responder.extendedKeyUsage] : null });
    }
    if (now < responder.notBefore || now > responder.notAfter) {
      throw ocspError(codes.OCSP_UNVERIFIED,
        `OCSP responder certificate "${subject}" is not valid at ${iso(now)} ` +
          `(validity ${iso(responder.notBefore)} .. ${iso(responder.notAfter)})`,
        { responder: subject, notBefore: responder.notBefore, notAfter: responder.notAfter });
    }
    if (responder.keyUsage && !responder.keyUsage.digitalSignature) {
      throw ocspError(codes.OCSP_UNVERIFIED,
        `OCSP responder certificate "${subject}" has a keyUsage without digitalSignature, ` +
          'which signing a response requires',
        { responder: subject });
    }
    // id-pkix-ocsp-nocheck asks relying parties not to check the responder certificate's own
    // revocation status — which is already this module's behaviour (there is no recursion to
    // suppress), so the extension is recognized rather than fatal even when marked critical.
    const unknownCritical = responder.unknownCriticalExtensions.filter((o) => o !== OID.ocspNocheck);
    if (unknownCritical.length > 0) {
      throw ocspError(codes.OCSP_UNVERIFIED,
        `OCSP responder certificate "${subject}" carries unrecognized critical extension(s) ` +
          `${unknownCritical.join(', ')}`,
        { responder: subject, oids: unknownCritical });
    }
    try {
      await verifySignedObject(responder, issuer.spkiDer, issuer.subjectText);
    } catch (e) {
      throw ocspError(codes.OCSP_UNVERIFIED,
        `OCSP responder certificate "${subject}" does not verify under the CA key: ` +
          `${e?.message ?? e}`,
        { responder: subject, cause: e?.code });
    }
    signerSpkiDer = responder.spki.spkiDer;
    signerText = `${subject} (delegated OCSP responder)`;
    delegated = true;
  }

  // --- 3. The signature itself, over the peer's exact tbsResponseData bytes -------------------
  // This is the moment the staple stops being attacker-controlled bytes: everything matched and
  // selected above is only believed because this signature covers it. verifySignedObject is the
  // same verifier certificates go through, so weak algorithms die by OID before any cryptography
  // runs, and ECDSA/PSS handling cannot drift from the path validator's.
  try {
    await verifySignedObject(
      {
        tbsBytes: basic.tbsBytes,
        signature: basic.signature,
        signatureAlgorithm: basic.signatureAlgorithm,
        subject: { text: 'the stapled OCSP response' },
      },
      signerSpkiDer,
      signerText,
    );
  } catch (e) {
    throw ocspError(codes.OCSP_UNVERIFIED,
      `stapled OCSP response for serial 0x${serialHex} cannot be trusted: ${e?.message ?? e}`,
      { serial: serialHex, cause: e?.code });
  }

  // --- 4. The verdict — revoked and unknown first, so neither can hide behind staleness -------
  if (single.status.kind === 'revoked') {
    const reason = single.status.reason;
    const reasonText = reason === null
      ? 'no reason given'
      : `reason ${CRL_REASON_NAME[reason] ?? 'unrecognized'}(${reason})`;
    // Age does not soften this one: a CA once said "revoked" about this serial, and revocations
    // effectively never un-happen (certificateHold aside, and failing closed on a hold is the
    // right side to be wrong on).
    throw ocspError(codes.OCSP_REVOKED,
      `OCSP: certificate serial 0x${serialHex} ("${leaf.subject.text}") is revoked, ` +
        `${reasonText}, since ${iso(single.status.revocationTime)}`,
      {
        serial: serialHex,
        subject: leaf.subject.text,
        revocationTime: single.status.revocationTime,
        reason,
        reasonName: reason === null ? null : CRL_REASON_NAME[reason] ?? null,
      });
  }
  if (single.status.kind === 'unknown') {
    throw ocspError(codes.OCSP_UNKNOWN,
      `OCSP: the responder for "${issuer.subjectText}" does not know certificate serial ` +
        `0x${serialHex}; a serial the CA's own responder cannot vouch for is not treated as good`,
      { serial: serialHex });
  }

  // --- 5. Freshness of the `good`, against the injected clock ---------------------------------
  if (single.thisUpdate > now + CLOCK_SKEW_MS) {
    throw ocspError(codes.OCSP_STALE,
      `stapled OCSP response for serial 0x${serialHex} is from the future: thisUpdate ` +
        `${iso(single.thisUpdate)} vs now ${iso(now)} (skew allowance ${CLOCK_SKEW_MS / 1000}s)`,
      { serial: serialHex, thisUpdate: single.thisUpdate, now });
  }
  if (single.nextUpdate !== null) {
    if (now > single.nextUpdate + CLOCK_SKEW_MS) {
      // An expired "good" is a replayable one: without this check, one captured response would
      // vouch for a certificate forever, which is precisely what revocation exists to end.
      throw ocspError(codes.OCSP_STALE,
        `stapled OCSP response for serial 0x${serialHex} expired: nextUpdate ` +
          `${iso(single.nextUpdate)} vs now ${iso(now)} (window ${iso(single.thisUpdate)} .. ` +
          `${iso(single.nextUpdate)})`,
        { serial: serialHex, thisUpdate: single.thisUpdate, nextUpdate: single.nextUpdate, now });
    }
  } else if (now - single.thisUpdate > MAX_AGE_WITHOUT_NEXT_UPDATE_MS) {
    throw ocspError(codes.OCSP_STALE,
      `stapled OCSP response for serial 0x${serialHex} has no nextUpdate and its thisUpdate ` +
        `${iso(single.thisUpdate)} is older than the ${MAX_AGE_WITHOUT_NEXT_UPDATE_MS / 86400000}-day ` +
        `cap at now ${iso(now)}`,
      { serial: serialHex, thisUpdate: single.thisUpdate, now });
  }

  return {
    status: 'good',
    producedAt: basic.producedAt,
    thisUpdate: single.thisUpdate,
    nextUpdate: single.nextUpdate,
    delegated,
  };
}
