// RFC 5280 s6.1 certification path building and validation.
//
// The chain arrives leaf-first, but nothing else about it is trusted: real servers ship
// intermediates out of order, append irrelevant certificates, and include their own root. The
// path is therefore rebuilt here from the leaf up — issuer matched to subject by exact DN bytes,
// disambiguated by key identifiers, terminated at a caller-supplied trust anchor — and only the
// certificates on that rebuilt path are judged.
//
// A trust anchor is a (name, public key, constraints) triple per RFC 5280 s6.1.1, not a
// certificate: the anchor's own self-signature proves nothing (anyone can self-sign any name)
// and is never verified. For the same reason an anchor's notBefore/notAfter are recorded but not
// enforced — expiring a root out from under otherwise-valid chains is exactly the failure that
// took down half the internet when AddTrust expired; root lifetime is store-curation policy, not
// path validity.
//
// Deliberately not implemented, and why that is safe or announced rather than silent:
//   * Policy processing (certificatePolicies / policyConstraints / inhibitAnyPolicy): with no
//     required policy set, RFC 5280 policy processing cannot fail a path. policyConstraints and
//     inhibitAnyPolicy — which would change that — are always critical and are NOT in
//     KNOWN_EXTENSIONS, so a path carrying them is rejected, never quietly mis-validated.
//   * Revocation (CRL/OCSP): unreachable from a metered edge runtime mid-handshake. This is a
//     documented gap, not a silent one.

import { CertificateError, ConfigError, codes } from '../errors.js';
import { equal, toHex } from '../util/bytes.js';
import { SIG_SCHEME, SIG_SCHEME_PARAMS } from '../tls/constants.js';
import {
  OID, parseCertificate, parseNameConstraints, parseSubjectPublicKeyInfo, resolveSignatureScheme,
} from './x509.js';
import {
  TAG,
  readAll,
  expectTlv,
  children,
  readInteger,
  ecdsaDerToRaw as derEcdsaToRaw,
} from './der.js';
import { matchesIdentity, dnsWithinSubtree, ipWithinSubtree } from './name.js';

const constraintError = (message, detail) =>
  new CertificateError(codes.CERT_CONSTRAINT, message, detail);

// ------------------------------------------------------------------ anchors

/**
 * Strip a parsed certificate down to the RFC 5280 s6.1.1 trust-anchor triple. Used for the
 * `mode:'anchors'` knob and by the root-store generator, so both feed path validation through
 * the identical shape.
 */
export function anchorFromCertificate(cert) {
  return Object.freeze({
    subjectBytes: cert.subject.bytes,
    subjectText: cert.subject.text,
    spkiDer: cert.spki.spkiDer,
    subjectKeyIdentifier: cert.subjectKeyIdentifier,
    nameConstraints: cert.nameConstraints,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
  });
}

/** Accept an anchor object (from roots.js or anchorFromCertificate), DER, or a parsed cert. */
function normalizeAnchor(a, index) {
  if (a instanceof Uint8Array) return anchorFromCertificate(parseCertificate(a));
  if (a && a.tbsBytes) return anchorFromCertificate(a);
  if (a && a.subjectBytes instanceof Uint8Array && a.spkiDer instanceof Uint8Array) {
    return {
      subjectBytes: a.subjectBytes,
      subjectText: a.subjectText ?? '<anchor>',
      spkiDer: a.spkiDer,
      subjectKeyIdentifier: a.subjectKeyIdentifier ?? null,
      // roots.js stores the raw extension value and defers parsing to the one anchor a
      // handshake actually lands on.
      nameConstraints: a.nameConstraints ??
        (a.nameConstraintsBytes ? parseNameConstraints(a.nameConstraintsBytes) : null),
      notBefore: a.notBefore ?? null,
      notAfter: a.notAfter ?? null,
    };
  }
  throw new ConfigError(codes.CONFIG_INVALID,
    `trust anchor at index ${index} is neither DER, a parsed certificate, nor an anchor object`);
}

/**
 * Normalise `anchors` into a lookup source. An array is scanned; an object with `forIssuer` is
 * used as-is — the bundled root store implements it with a subject-hash index so a handshake
 * touches one anchor, not the whole store.
 */
function toAnchorSource(anchors) {
  if (anchors && typeof anchors.forIssuer === 'function') return anchors;
  if (!Array.isArray(anchors)) {
    throw new ConfigError(codes.CONFIG_INVALID,
      'anchors must be an array or an anchor source with forIssuer()');
  }
  const normalized = anchors.map(normalizeAnchor);
  return {
    forIssuer: async (dnBytes) => normalized.filter((a) => equal(a.subjectBytes, dnBytes)),
  };
}

// ------------------------------------------------------------------ signature verification

const CURVE_TO_SCHEME = {
  [OID.secp256r1]: SIG_SCHEME.ecdsa_secp256r1_sha256,
  [OID.secp384r1]: SIG_SCHEME.ecdsa_secp384r1_sha384,
  [OID.secp521r1]: SIG_SCHEME.ecdsa_secp521r1_sha512,
};

/**
 * ECDSA-Sig-Value to the fixed-width r||s form WebCrypto verifies. The conversion itself lives in
 * der.js because the TLS CertificateVerify path needs exactly the same one, and two copies of a
 * signature parser is two chances to be subtly different.
 */
function ecdsaDerToRaw(sig, orderLen, subject) {
  return derEcdsaToRaw(sig, orderLen, (why) =>
    new CertificateError(codes.CERT_SIGNATURE_INVALID,
      `ECDSA signature on "${subject}" is malformed: ${why}`, { subject }));
}

/**
 * Verify `cert`'s signature over its original TBSCertificate bytes with the issuer's public key.
 *
 * The scheme comes from resolveSignatureScheme (which is where MD5/SHA-1 die, before any
 * cryptography runs). For ECDSA the curve belongs to the issuer's key, not the OID, so the
 * WebCrypto import parameters are chosen from the issuer's SPKI and only the hash from the OID —
 * both looked up in SIG_SCHEME_PARAMS rather than re-declared here.
 */
async function verifyCertSignature(cert, issuerSpkiDer, issuerText) {
  const scheme = resolveSignatureScheme(cert); // throws CERT_SIGNATURE_WEAK / _UNSUPPORTED
  const issuerSpki = parseSubjectPublicKeyInfo(issuerSpkiDer);
  const mismatch = (why) =>
    new CertificateError(codes.CERT_SIGNATURE_INVALID,
      `signature on "${cert.subject.text}" (${scheme.name}) cannot be by issuer "${issuerText}": ${why}`,
      { subject: cert.subject.text, issuer: issuerText, scheme: scheme.name });

  let importParams;
  let verifyParams;
  let sigBytes = cert.signature;
  if (scheme.kind === 'ecdsa') {
    if (issuerSpki.algorithmOid !== OID.ecPublicKey) throw mismatch('issuer key is not an EC key');
    const schemeId = CURVE_TO_SCHEME[issuerSpki.curveOid];
    if (!schemeId) {
      throw new CertificateError(codes.CERT_SIGNATURE_UNSUPPORTED,
        `issuer "${issuerText}" uses EC curve ${issuerSpki.curveOid}, which is not supported`,
        { curveOid: issuerSpki.curveOid });
    }
    const table = SIG_SCHEME_PARAMS[schemeId];
    importParams = table.import;
    verifyParams = { name: 'ECDSA', hash: scheme.hash };
    sigBytes = ecdsaDerToRaw(cert.signature, table.curveOrderLen, cert.subject.text);
  } else if (scheme.kind === 'rsa-pkcs1') {
    // An RSASSA-PSS-restricted key must never validate PKCS#1 v1.5 signatures (RFC 4055 s1.2) —
    // accepting cross-protocol use of one key is a known signature-confusion primitive.
    if (issuerSpki.algorithmOid !== OID.rsaEncryption) {
      throw mismatch('issuer key is not an rsaEncryption key');
    }
    const table = SIG_SCHEME_PARAMS[scheme.scheme];
    importParams = table.import;
    verifyParams = table.verify;
  } else if (scheme.kind === 'rsa-pss') {
    if (issuerSpki.algorithmOid !== OID.rsaEncryption && issuerSpki.algorithmOid !== OID.rsassaPss) {
      throw mismatch('issuer key is not an RSA key');
    }
    const table = SIG_SCHEME_PARAMS[scheme.scheme];
    importParams = table.import;
    verifyParams = table.verify;
  } else if (scheme.kind === 'ed25519') {
    if (issuerSpki.algorithmOid !== OID.ed25519) throw mismatch('issuer key is not an Ed25519 key');
    importParams = SIG_SCHEME_PARAMS[SIG_SCHEME.ed25519].import;
    verifyParams = SIG_SCHEME_PARAMS[SIG_SCHEME.ed25519].verify;
  } else {
    throw mismatch(`unhandled scheme kind ${scheme.kind}`);
  }

  let ok = false;
  try {
    const key = await crypto.subtle.importKey('spki', issuerSpkiDer, importParams, false, ['verify']);
    ok = await crypto.subtle.verify(verifyParams, key, sigBytes, cert.tbsBytes);
  } catch (e) {
    throw mismatch(`WebCrypto refused the key or signature (${e?.message ?? e})`);
  }
  if (!ok) {
    throw new CertificateError(codes.CERT_SIGNATURE_INVALID,
      `signature on "${cert.subject.text}" by "${issuerText}" (${scheme.name}) did not verify`,
      { subject: cert.subject.text, issuer: issuerText, scheme: scheme.name });
  }
}

// ------------------------------------------------------------------ path building

/** Key-identifier compatibility: a constraint only when both sides actually carry one. */
const kidCompatible = (childAki, parentSki) => !childAki || !parentSki || equal(childAki, parentSki);

/**
 * Build the path leaf-to-anchor. Anchors are preferred at every step, so a self-signed (or
 * cross-signed) root the server helpfully included is simply never reached. Where several
 * same-named candidates exist (cross-signs, key rollovers), signatures disambiguate; a lone
 * candidate is accepted structurally and verified in the validation pass, where failure produces
 * the precise CERT_SIGNATURE_INVALID rather than a vague "no path".
 */
async function buildPath(certs, anchorSource, maxPathLength) {
  const leaf = certs[0];
  const path = [leaf];
  const used = new Set([0]);
  let current = leaf;
  let sigFailure = null;

  for (;;) {
    if (path.length > maxPathLength) {
      throw constraintError(
        `certification path exceeded ${maxPathLength} certificates without reaching a trust anchor`,
        { maxPathLength });
    }

    // 1) Trust anchors for the current issuer name. The anchor link is verified eagerly: it both
    // selects among same-named anchors and lets a failed anchor fall back to a supplied
    // cross-sign, which is how root rollovers actually deploy. Every anchor a source returns is
    // re-normalised here — the bundled store hands back packed records whose name constraints
    // are still raw bytes, and consuming those un-normalised would silently drop the
    // constraints (found the hard way by the generator's integration test).
    const anchorCandidates = (await anchorSource.forIssuer(current.issuer.bytes))
      .map(normalizeAnchor)
      .filter((a) => kidCompatible(current.authorityKeyIdentifier, a.subjectKeyIdentifier ?? null));
    for (const anchor of anchorCandidates) {
      try {
        await verifyCertSignature(current, anchor.spkiDer, anchor.subjectText ?? '<anchor>');
        return { path, anchor, topVerified: true };
      } catch (e) {
        // Only "this particular key did not make this signature" keeps the search going; a weak
        // or unsupported algorithm is a property of the child and no other parent can fix it.
        if (e.code !== codes.CERT_SIGNATURE_INVALID) throw e;
        sigFailure = e;
      }
    }

    // 2) Supplied certificates.
    const candidates = [];
    for (let i = 0; i < certs.length; i++) {
      if (used.has(i)) continue;
      const c = certs[i];
      if (!equal(c.subject.bytes, current.issuer.bytes)) continue;
      if (!kidCompatible(current.authorityKeyIdentifier, c.subjectKeyIdentifier)) continue;
      if (equal(c.der, current.der)) continue; // a duplicate of current can only build a loop
      candidates.push(i);
    }
    let chosen = -1;
    if (candidates.length === 1) {
      chosen = candidates[0];
    } else if (candidates.length > 1) {
      for (const i of candidates) {
        try {
          await verifyCertSignature(current, certs[i].spki.spkiDer, certs[i].subject.text);
          chosen = i;
          break;
        } catch (e) {
          if (e.code !== codes.CERT_SIGNATURE_INVALID) throw e;
          sigFailure = e;
        }
      }
    }
    if (chosen === -1) {
      // Dead end. Prefer the most specific story: a candidate existed but its key did not make
      // the signature; the chain ends at an untrusted self-signed cert; or the issuer is simply
      // absent from both the chain and the store.
      if (sigFailure) throw sigFailure;
      if (current.isSelfIssued) {
        throw new CertificateError(codes.CERT_UNTRUSTED_ROOT,
          `certification path ends at self-signed "${current.subject.text}", which is not a trust anchor`,
          { subject: current.subject.text });
      }
      throw new CertificateError(codes.CERT_CHAIN_INCOMPLETE,
        `no certificate for issuer "${current.issuer.text}" of "${current.subject.text}" was ` +
          'supplied, and no trust anchor has that subject',
        { subject: current.subject.text, issuer: current.issuer.text });
    }
    used.add(chosen);
    path.push(certs[chosen]);
    current = certs[chosen];
  }
}

// ------------------------------------------------------------------ name-constraint state

/**
 * Constraint state as layers: each certificate that imposes permittedSubtrees adds one layer per
 * name type, and a name is acceptable only if EVERY layer of its type covers it. Keeping layers
 * instead of computing intersections is exactly RFC 5280's intersection semantics without the
 * subtlety of intersecting suffix sets. Exclusions are a flat union — one hit anywhere rejects.
 */
function makeConstraintState(anchor) {
  const state = {
    dnsPermittedLayers: [], // {bases: string[], by: string}[]
    ipPermittedLayers: [], // {bases: {addr, mask}[], by: string}[]
    dnsExcluded: [], // {base: string, by: string}
    ipExcluded: [], // {addr, mask, by}
  };
  if (anchor.nameConstraints) {
    addConstraints(state, anchor.nameConstraints, anchor.subjectText ?? '<anchor>', true);
  }
  return state;
}

function addConstraints(state, nc, by, critical) {
  const collect = (subtrees, which) => {
    const dns = [];
    const ip = [];
    for (const t of subtrees) {
      if (t.type === 'dns') dns.push(t.value);
      else if (t.type === 'ip') ip.push({ addr: t.addr, mask: t.mask });
      else if (critical) {
        // RFC 5280 s4.2.1.10: constraint forms we cannot enforce (directoryName, rfc822Name,
        // URI, otherName, or out-of-spec minimum/maximum) in a CRITICAL extension must reject
        // the path — silently ignoring a constraint the CA insisted on is failing open.
        throw constraintError(
          `"${by}" imposes a ${which} name constraint of an unsupported type in a critical ` +
            'nameConstraints extension; refusing to ignore it',
          { by, which });
      }
    }
    return { dns, ip };
  };
  if (nc.permitted) {
    const { dns, ip } = collect(nc.permitted, 'permitted');
    if (dns.length) state.dnsPermittedLayers.push({ bases: dns, by });
    if (ip.length) state.ipPermittedLayers.push({ bases: ip, by });
  }
  if (nc.excluded) {
    const { dns, ip } = collect(nc.excluded, 'excluded');
    for (const base of dns) state.dnsExcluded.push({ base, by });
    for (const e of ip) state.ipExcluded.push({ ...e, by });
  }
}

/** Check every SAN name of `cert` against the accumulated constraint state. */
function checkConstraints(state, cert) {
  const subject = cert.subject.text;
  for (const name of cert.subjectAltNames.dns) {
    for (const layer of state.dnsPermittedLayers) {
      if (!layer.bases.some((b) => dnsWithinSubtree(name, b))) {
        throw constraintError(
          `dNSName "${name}" of "${subject}" is outside the permitted subtrees imposed by ` +
            `"${layer.by}" (permitted: ${layer.bases.join(', ')})`,
          { name, subject, by: layer.by });
      }
    }
    for (const ex of state.dnsExcluded) {
      if (dnsWithinSubtree(name, ex.base)) {
        throw constraintError(
          `dNSName "${name}" of "${subject}" is inside the subtree "${ex.base}" excluded by "${ex.by}"`,
          { name, subject, by: ex.by });
      }
    }
  }
  for (const ip of cert.subjectAltNames.ip) {
    const shown = toHex(ip);
    for (const layer of state.ipPermittedLayers) {
      if (!layer.bases.some((b) => ipWithinSubtree(ip, b.addr, b.mask))) {
        throw constraintError(
          `iPAddress ${shown} of "${subject}" is outside the permitted subtrees imposed by "${layer.by}"`,
          { subject, by: layer.by });
      }
    }
    for (const ex of state.ipExcluded) {
      if (ipWithinSubtree(ip, ex.addr, ex.mask)) {
        throw constraintError(
          `iPAddress ${shown} of "${subject}" is inside a subtree excluded by "${ex.by}"`,
          { subject, by: ex.by });
      }
    }
  }
}

// ------------------------------------------------------------------ validation

/**
 * Build and validate a certification path.
 *
 * @param {object} opts
 * @param {Array<Uint8Array|object>} opts.chain DER (or already-parsed) certificates, leaf first,
 *   in whatever order and with whatever extras the server chose to send
 * @param {Array|{forIssuer: Function}} opts.anchors trust anchors, or an indexed anchor source
 * @param {string} [opts.hostname] identity to require of the leaf; omit to skip (index.js never omits)
 * @param {number} [opts.now] epoch ms
 * @param {number} [opts.maxPathLength] hard cap on path certificates — this runs on a metered
 *   runtime and a pathological chain must cost O(cap), not O(chain²)
 * @returns {Promise<{leaf: object, path: object[], anchor: object}>} parsed leaf, the validated
 *   path (leaf first), and the anchor that terminated it
 */
export async function validatePath(
  { chain, anchors, hostname = null, now = Date.now(), maxPathLength = 10 },
) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new CertificateError(codes.CERT_CHAIN_INCOMPLETE, 'the peer supplied no certificates');
  }
  const certs = chain.map((c, i) => {
    if (c instanceof Uint8Array) return parseCertificate(c);
    if (c && c.tbsBytes) return c;
    throw new ConfigError(codes.CONFIG_INVALID, `chain[${i}] is neither DER nor a parsed certificate`);
  });
  const anchorSource = toAnchorSource(anchors);
  const { path, anchor, topVerified } = await buildPath(certs, anchorSource, maxPathLength);

  const state = makeConstraintState(anchor);
  // RFC 5280 s6.1.4 (l): the working constraint starts at the path length; each non-self-issued
  // intermediate consumes one slot, and any certificate may lower — never raise — the remainder.
  let pathLenRemaining = { value: maxPathLength, by: null };

  // Process from the certificate under the anchor down to the leaf, as s6.1.3/6.1.4 do: state
  // (name constraints, path length) flows downward.
  for (let j = path.length - 1; j >= 0; j--) {
    const cert = path[j];
    const isLeaf = j === 0;
    const subject = cert.subject.text;

    // RFC 5280 s6.1: an unrecognised critical extension anywhere on the path is a hard stop.
    // This check runs before any use of the certificate — an extension we cannot read may change
    // the meaning of everything we can.
    if (cert.unknownCriticalExtensions.length > 0) {
      throw constraintError(
        `certificate "${subject}" carries unrecognised critical extension(s) ` +
          `${cert.unknownCriticalExtensions.join(', ')}; RFC 5280 s6.1 requires rejection`,
        { subject, oids: [...cert.unknownCriticalExtensions] });
    }

    const parent = j === path.length - 1 ? null : path[j + 1];
    if (!(topVerified && parent === null)) {
      await verifyCertSignature(
        cert,
        parent ? parent.spki.spkiDer : anchor.spkiDer,
        parent ? parent.subject.text : (anchor.subjectText ?? '<anchor>'),
      );
    }

    if (now < cert.notBefore) {
      throw new CertificateError(codes.CERT_NOT_YET_VALID,
        `certificate "${subject}" is not valid until ${new Date(cert.notBefore).toISOString()} ` +
          `(now ${new Date(now).toISOString()})`,
        { subject, notBefore: cert.notBefore, now });
    }
    if (now > cert.notAfter) {
      throw new CertificateError(codes.CERT_EXPIRED,
        `certificate "${subject}" expired ${new Date(cert.notAfter).toISOString()} ` +
          `(now ${new Date(now).toISOString()})`,
        { subject, notAfter: cert.notAfter, now });
    }

    // Name constraints bind every certificate below the imposer. Self-issued intermediates are
    // exempt (s6.1.3 (b)) — they re-certify the same CA, not a new name — but the leaf never is.
    if (isLeaf || !cert.isSelfIssued) checkConstraints(state, cert);

    if (!isLeaf) {
      // s6.1.4 (k): every intermediate must be a v3 CA. A certificate without basicConstraints
      // (v1 certs included) never gets to issue — "it is old" is not a capability grant.
      if (!cert.basicConstraints.present || !cert.basicConstraints.ca) {
        throw constraintError(
          `certificate "${subject}" signed others but ` +
            (cert.basicConstraints.present
              ? 'its basicConstraints do not assert cA'
              : 'has no basicConstraints extension'),
          { subject });
      }
      // s6.1.4 (n): a CA that carries keyUsage must include keyCertSign.
      if (cert.keyUsage && !cert.keyUsage.keyCertSign) {
        throw constraintError(
          `certificate "${subject}" signed others but its keyUsage lacks keyCertSign`, { subject });
      }
      // s6.1.4 (l)/(m): path length accounting. Self-issued intermediates do not consume a slot.
      if (!cert.isSelfIssued) {
        if (pathLenRemaining.value <= 0) {
          throw constraintError(
            `pathLenConstraint ${pathLenRemaining.limit} imposed by "${pathLenRemaining.by}" ` +
              `does not allow "${subject}" to appear as a further intermediate`,
            { subject, by: pathLenRemaining.by });
        }
        pathLenRemaining = { ...pathLenRemaining, value: pathLenRemaining.value - 1 };
      }
      const pl = cert.basicConstraints.pathLenConstraint;
      if (pl !== null && pl < pathLenRemaining.value) {
        pathLenRemaining = { value: pl, limit: pl, by: subject };
      }
      if (cert.nameConstraints) {
        addConstraints(state, cert.nameConstraints, subject,
          cert.extensions.get(OID.nameConstraints)?.critical ?? false);
      }
    } else {
      // End-entity role checks. A leaf that is also a CA is legal (s6.1 has no prohibition);
      // what matters is that its stated purposes include TLS server authentication.
      if (cert.extendedKeyUsage &&
          !cert.extendedKeyUsage.includes(OID.serverAuth) &&
          !cert.extendedKeyUsage.includes(OID.anyExtendedKeyUsage)) {
        throw constraintError(
          `certificate "${subject}" has an extendedKeyUsage (${cert.extendedKeyUsage.join(', ')}) ` +
            'that does not include serverAuth or anyExtendedKeyUsage',
          { subject, eku: [...cert.extendedKeyUsage] });
      }
      // Every key-exchange this package negotiates (TLS 1.3, TLS 1.2 ECDHE) authenticates the
      // server with a handshake signature, which keyUsage must permit when present.
      if (cert.keyUsage && !cert.keyUsage.digitalSignature) {
        throw constraintError(
          `certificate "${subject}" has a keyUsage without digitalSignature, which every ` +
            'supported key exchange requires',
          { subject });
      }
      if (hostname !== null) matchesIdentity(cert, hostname);
    }
  }

  return { leaf: path[0], path, anchor };
}
