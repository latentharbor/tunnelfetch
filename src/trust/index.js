// Public certificate-trust entry point.
//
// The runtime hands this package a tunnelled TLS peer it refuses to verify; this module is the
// entire difference between "encrypted to the server" and "encrypted to whoever answered". Its
// contract is shaped so misuse fails loudly:
//
//   * verifyChain returns the parsed leaf or THROWS. There is no boolean — a caller cannot
//     forget to check one.
//   * Disabling verification requires `mode:'none'` AND `insecureAcceptAnyCertificate:true`.
//     One flag can be a typo or a copy-paste; the pair is a signed confession.
//   * Config nonsense (unknown mode, pins on the wrong mode, an unpopulated root store) is
//     CONFIG_INVALID at call time, never a silent downgrade.

import { CertificateError, ConfigError, codes } from '../errors.js';
import { timingSafeEqual } from '../util/bytes.js';
import { parseCertificate, decodePem } from './x509.js';
import { validatePath, anchorFromCertificate } from './path.js';
import { verifyOcspStaple } from './ocsp.js';
import { matchesIdentity } from './name.js';
import { systemAnchors, provenance } from './roots.js';

export { parseCertificate, decodePem } from './x509.js';
export { validatePath, anchorFromCertificate } from './path.js';
export { verifyOcspStaple, parseOcspResponse } from './ocsp.js';
export { matchesIdentity } from './name.js';
export { systemAnchors, provenance as rootStoreProvenance } from './roots.js';

const MODES = ['system', 'anchors', 'pinned', 'none', 'custom'];

const invalid = (message) => new ConfigError(codes.CONFIG_INVALID, message);

// ------------------------------------------------------------------ revocation policy
//
// Revocation is checked via stapled OCSP only (see src/trust/ocsp.js for why fetching is not an
// option here), which forces a policy DECISION about the case stapling cannot cover: most
// servers simply do not staple, and an attacker who holds a revoked-but-otherwise-valid
// certificate can present it WITHOUT a staple. The choices and their costs:
//
//   * Hard-fail (no staple = no connection) is the only stance with teeth against that attacker
//     — and it breaks the majority of the honest web, which would make this package unusable as
//     a default and teach every consumer to switch the check off, the worst outcome of all.
//   * Soft-fail (tolerate absence) is what every browser ships, and it is honestly close to
//     worthless against an active attacker, who can just omit the staple. Its real value is
//     against the common non-adversarial case: an honestly-compromised or mis-issued certificate
//     on a well-run server that DOES staple gets caught.
//
// The default here is therefore: ABSENCE of a staple is not a failure, but a staple that IS
// present must verify completely, and a verified `revoked` (or `unknown`) is always fatal —
// there is no configuration that ignores a revoked verdict, the same way there is no single
// flag that disables verification. This asymmetry is principled, not timid: the staple is the
// server operator's own signed statement about their certificate, so a present-but-invalid one
// is either misconfiguration worth failing loudly on or an attack, while a missing one is
// overwhelmingly just a server that never opted in.
//
// A caller whose peers are known to staple buys the real guarantee with
// `revocation: 'require-staple'`, which turns absence into OCSP_REQUIRED — the OCSP equivalent
// of pinning: opt-in strictness where the deployment can afford it. There is deliberately NO
// 'off' value: the weakest expressible policy still refuses a revoked certificate, because a
// caller who wants to talk to a peer the CA has disowned should have to say `mode: 'none'` and
// own everything that implies.
const REVOCATION_MODES = ['staple', 'require-staple'];

/** Validate the `revocation` knob for the modes that verify chains. */
function revocationPolicy(trust, mode) {
  const value = trust.revocation ?? 'staple';
  if (!REVOCATION_MODES.includes(value)) {
    throw invalid(`trust.revocation must be one of ${REVOCATION_MODES.map((m) => `'${m}'`).join(', ')} ` +
      `with mode '${mode}', got ${JSON.stringify(value)}. There is no value that ignores a ` +
      'revoked certificate.');
  }
  return value;
}

/**
 * Enforce the policy above for one validated path: judge the staple when present, and demand one
 * when the caller opted into 'require-staple'.
 *
 * The issuer handed to the OCSP checker comes from the VALIDATED path — the certificate that
 * actually signed the leaf, or the trust anchor when the leaf sits directly under one — because
 * a staple's signature is only meaningful against a key that is already trusted to speak for
 * the leaf's issuer.
 */
async function checkRevocation({ ocspResponse, revocation, leaf, path, anchor, hostname, now }) {
  if (ocspResponse == null) {
    if (revocation === 'require-staple') {
      throw new CertificateError(codes.OCSP_REQUIRED,
        `no OCSP response was stapled for "${hostname}" and trust.revocation is ` +
          "'require-staple'; without a staple this certificate's revocation status is unknown. " +
          'Either the server must enable OCSP stapling or this policy must be relaxed',
        { hostname });
    }
    return; // absence tolerated by default; the policy comment above is the argument
  }
  const issuer = path.length > 1
    ? {
        subjectBytes: path[1].subject.bytes,
        spkiDer: path[1].spki.spkiDer,
        subjectText: path[1].subject.text,
      }
    : {
        subjectBytes: anchor.subjectBytes,
        spkiDer: anchor.spkiDer,
        subjectText: anchor.subjectText ?? '<anchor>',
      };
  await verifyOcspStaple({ staple: ocspResponse, leaf, issuer, now });
}

/** Refuse config keys that belong to a different mode: a mismatched knob is a misunderstanding. */
function forbidKeys(trust, mode, keys) {
  for (const key of keys) {
    if (trust[key] !== undefined) {
      throw invalid(`trust.${key} is not meaningful with mode '${mode}'; refusing a config that ` +
        'says two different things');
    }
  }
}

/** 'sha256/BASE64' -> 32 raw bytes, rejecting anything that is not exactly that. */
function parsePins(pins) {
  if (!Array.isArray(pins) || pins.length === 0) {
    throw invalid("trust.pins must be a non-empty array of 'sha256/BASE64' strings");
  }
  return pins.map((p) => {
    if (typeof p !== 'string' || !p.startsWith('sha256/')) {
      throw invalid(`pin ${JSON.stringify(p)} must look like 'sha256/BASE64'`);
    }
    let raw;
    try {
      raw = atob(p.slice('sha256/'.length));
    } catch {
      throw invalid(`pin "${p}" is not valid base64`);
    }
    if (raw.length !== 32) {
      throw invalid(`pin "${p}" decodes to ${raw.length} bytes; a SHA-256 pin must be 32`);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = raw.charCodeAt(i);
    return out;
  });
}

async function spkiSha256(cert) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', cert.spki.spkiDer));
}

const toPinString = (bytes) => `sha256/${btoa(String.fromCharCode(...bytes))}`;

/**
 * Require at least one certificate in `certs` (plus optionally the anchor SPKI) to match a pin.
 * HPKP semantics: a pin may name any element of the chain, so operators can pin an intermediate
 * or root and survive leaf rotation. Comparison is timing-safe — the pins themselves may be
 * secret-adjacent config even though the certificates are public.
 */
async function checkPins(pins, certs, anchor) {
  const observed = [];
  for (const cert of certs) {
    const digest = await spkiSha256(cert);
    if (pins.some((p) => timingSafeEqual(p, digest))) return;
    observed.push(toPinString(digest));
  }
  if (anchor) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', anchor.spkiDer));
    if (pins.some((p) => timingSafeEqual(p, digest))) return;
    observed.push(toPinString(digest));
  }
  throw new CertificateError(codes.CERT_PIN_MISMATCH,
    `no certificate in the chain matches any configured pin (observed: ${observed.join(', ')})`,
    { observed });
}

/** Expand user anchors: PEM text (possibly many blocks), DER, parsed certs, or anchor objects. */
function expandAnchors(list) {
  if (!Array.isArray(list) || list.length === 0) {
    throw invalid('trust.anchors must be a non-empty array of PEM/DER certificates or anchors');
  }
  const out = [];
  for (const entry of list) {
    if (typeof entry === 'string') {
      for (const der of decodePem(entry)) out.push(anchorFromCertificate(parseCertificate(der)));
    } else if (entry instanceof Uint8Array) {
      out.push(anchorFromCertificate(parseCertificate(entry)));
    } else {
      out.push(entry); // parsed certificate or anchor object; validatePath vets the shape
    }
  }
  return out;
}

/** The bundled store, refusing to pass off "never generated" as "trust nothing". */
function requireSystemStore() {
  if (provenance.anchorCount === 0) {
    throw invalid('the bundled root store is unpopulated; run `npm run roots:refresh` to generate ' +
      "it, or supply anchors explicitly with trust mode 'anchors'");
  }
  return systemAnchors;
}

/**
 * A trust anchor as supplied by a caller: PEM text or raw DER.
 * @typedef {string | Uint8Array} AnchorInput
 */

/**
 * Revocation policy, for the modes that validate chains. Checking is via stapled OCSP only, so
 * the knob decides what a MISSING staple means: `'staple'` (the default) tolerates absence but
 * fully verifies any staple that is present; `'require-staple'` makes absence OCSP_REQUIRED.
 * A verified `revoked` or `unknown` verdict is fatal under both — no value ignores it.
 * @typedef {'staple' | 'require-staple'} RevocationPolicy
 */

/**
 * Verify against the bundled CCADB root store. The default.
 * @typedef {{ mode?: 'system', revocation?: RevocationPolicy }} SystemTrust
 */

/**
 * Verify against exactly these anchors and nothing else. The bundled store is not consulted.
 * @typedef {{ mode: 'anchors', anchors: AnchorInput[],
 *             revocation?: RevocationPolicy }} AnchorsTrust
 */

/**
 * Full path validation, plus a requirement that some certificate in the accepted path (or its
 * anchor) match one of `pins`. Pins are `sha256/` followed by the base64 SHA-256 of a
 * SubjectPublicKeyInfo, the same spelling HPKP used.
 * @typedef {{ mode: 'pinned', pins: string[], anchors?: AnchorInput[],
 *             revocation?: RevocationPolicy }} PinnedTrust
 */

/**
 * No path validation at all. `insecureAcceptAnyCertificate` is mandatory and must be `true`, so
 * that this mode can never be reached by a typo in `mode`. Supplying `pins` turns it into
 * pin-only trust: no chain is built, but a pin must still match. `revocation` is refused here:
 * without a validated issuer there is no trusted key to verify a staple against, so the check
 * cannot be performed honestly and pretending otherwise would be worse.
 * @typedef {{ mode: 'none', insecureAcceptAnyCertificate: true, pins?: string[] }} NoTrust
 */

/**
 * Caller-supplied policy. Returning normally accepts the chain; throwing rejects it. The third
 * argument carries the peer's stapled OCSP response (DER, or null) so a custom policy can judge
 * revocation itself — `verifyOcspStaple` is exported for exactly that.
 * @typedef {{ mode: 'custom',
 *             verify: (chain: ParsedCertificate[], hostname: string,
 *                      details?: { ocspResponse: Uint8Array | null })
 *               => void | Promise<void> }} CustomTrust
 */

/**
 * The `verify=` knob, in httpx's spirit. Written as a discriminated union so that a TypeScript
 * caller cannot ask for pinning without pins, or reach `mode: 'none'` without spelling out the
 * flag that says they meant it — both of which are otherwise runtime errors discovered in
 * production rather than compile errors discovered while typing.
 * @typedef {SystemTrust | AnchorsTrust | PinnedTrust | NoTrust | CustomTrust} TrustConfig
 */

/**
 * A parsed certificate, as returned by `parseCertificate`. Only the members other layers rely on
 * are named here; the object carries the full parse.
 * @typedef {object} ParsedCertificate
 * @property {Uint8Array} der the original bytes, never re-encoded
 * @property {Uint8Array} tbsBytes exact TBSCertificate slice the signature covers
 * @property {{ spkiDer: Uint8Array, algorithmOid: string, keyBytes: Uint8Array }} spki
 * @property {{ text: string }} subject
 * @property {{ text: string }} issuer
 * @property {number} notBefore epoch ms
 * @property {number} notAfter epoch ms
 * @property {{ dns: string[], ip: Uint8Array[], uri: string[], email: string[] }} subjectAltNames
 */

/**
 * Verify a TLS-delivered certificate chain for `hostname`.
 *
 * @param {object} opts
 * @param {Uint8Array[]} opts.chain DER certificates, leaf first, as the peer sent them
 * @param {string} opts.hostname identity from the request URL (DNS name or IP literal)
 * @param {TrustConfig} [opts.trust] the verification policy; defaults to the bundled roots
 * @param {number} [opts.now] epoch ms, for tests and for callers with a better clock
 * @param {Uint8Array | null} [opts.ocspResponse] the peer's stapled DER OCSPResponse, when the
 *   handshake carried one; judged under `trust.revocation` (see the policy comment above)
 * @returns {Promise<ParsedCertificate>} the parsed leaf. Every other outcome throws.
 */
export async function verifyChain({
  chain, hostname, trust = { mode: 'system' }, now = Date.now(), ocspResponse = null,
}) {
  if (trust === null || typeof trust !== 'object') {
    throw invalid("trust must be an object like { mode: 'system' }");
  }
  const mode = trust.mode ?? 'system';
  if (!MODES.includes(mode)) {
    throw invalid(`unknown trust mode ${JSON.stringify(mode)}; expected one of ${MODES.join(', ')}`);
  }
  if (mode !== 'none' && trust.insecureAcceptAnyCertificate !== undefined) {
    throw invalid(`trust.insecureAcceptAnyCertificate is not meaningful with mode '${mode}'`);
  }
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new CertificateError(codes.CERT_CHAIN_INCOMPLETE, 'the peer supplied no certificates');
  }

  if (mode === 'none') {
    // Reaching "no verification" by accident must be impossible: the mode alone is refused
    // without its explicit confession flag.
    if (trust.insecureAcceptAnyCertificate !== true) {
      throw invalid("trust mode 'none' additionally requires insecureAcceptAnyCertificate: true; " +
        'refusing to disable certificate verification on a single flag');
    }
    forbidKeys(trust, 'none', ['anchors', 'verify', 'revocation']);
    if (trust.pins !== undefined) {
      // Pin-only trust: no path validation, but the pin check itself must not fail open — a
      // chain we cannot parse cannot be pinned, so it throws.
      const pins = parsePins(trust.pins);
      const parsed = chain.map((der) => parseCertificate(der));
      await checkPins(pins, parsed, null);
      return parsed[0];
    }
    // Even here the leaf must parse, and the reason is not about trust: the handshake authenticates
    // the key exchange with a signature it checks against the leaf's public key, so a certificate
    // whose SPKI cannot be read leaves nothing to check the signature against. 'none' switches off
    // deciding whether to BELIEVE the certificate; it cannot conjure a key out of bytes that are
    // not a certificate.
    //
    // This used to return null and let the drivers refuse a few frames later with CONFIG_INVALID
    // ("verifyPeer must resolve with the validated leaf"), which blamed the caller's configuration
    // for the peer's malformed certificate — precisely the sort of error that sends someone
    // auditing their own code for an hour.
    try {
      return parseCertificate(chain[0]);
    } catch (cause) {
      throw new CertificateError(
        codes.CERT_PARSE,
        'the peer\'s leaf certificate could not be parsed, so its public key is unavailable and ' +
          'the handshake signature cannot be checked against anything. Verification is disabled ' +
          `(trust mode 'none'), which does not help here: ${cause?.message ?? cause}`,
        { mode: 'none', cause: cause?.message ?? String(cause) },
      );
    }
  }

  if (mode === 'custom') {
    // `revocation` is refused for the same reason `pins` is: custom mode owns policy entirely.
    // The staple is handed to the callback instead, with verifyOcspStaple exported so a custom
    // policy can run the standard check against whichever issuer its own validation blessed.
    forbidKeys(trust, 'custom', ['anchors', 'pins', 'revocation']);
    if (typeof trust.verify !== 'function') {
      throw invalid("trust mode 'custom' requires a verify(chain, hostname) function");
    }
    const parsed = chain.map((der) => parseCertificate(der));
    // The callback owns policy entirely: throwing rejects the connection, returning accepts it.
    // Its errors propagate untouched so callers see their own diagnostics.
    await trust.verify(parsed, hostname, { ocspResponse });
    return parsed[0];
  }

  let anchors;
  let pins = null;
  if (mode === 'system') {
    forbidKeys(trust, 'system', ['anchors', 'pins', 'verify']);
    anchors = requireSystemStore();
  } else if (mode === 'anchors') {
    forbidKeys(trust, 'anchors', ['pins', 'verify']);
    anchors = expandAnchors(trust.anchors);
  } else { // pinned
    forbidKeys(trust, 'pinned', ['verify']);
    pins = parsePins(trust.pins);
    anchors = trust.anchors !== undefined ? expandAnchors(trust.anchors) : requireSystemStore();
  }
  // Validated before any network-derived bytes are judged, like every other config error: a
  // misspelled policy must fail the connection even when the peer stapled nothing.
  const revocation = revocationPolicy(trust, mode);

  const { leaf, path, anchor } = await validatePath({ chain, anchors, hostname, now });
  if (pins) await checkPins(pins, path, anchor);
  await checkRevocation({ ocspResponse, revocation, leaf, path, anchor, hostname, now });
  return leaf;
}
