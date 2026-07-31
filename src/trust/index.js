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
import { matchesIdentity } from './name.js';
import { systemAnchors, provenance } from './roots.js';

export { parseCertificate, decodePem } from './x509.js';
export { validatePath, anchorFromCertificate } from './path.js';
export { matchesIdentity } from './name.js';
export { systemAnchors, provenance as rootStoreProvenance } from './roots.js';

const MODES = ['system', 'anchors', 'pinned', 'none', 'custom'];

const invalid = (message) => new ConfigError(codes.CONFIG_INVALID, message);

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
 * Verify a TLS-delivered certificate chain for `hostname`.
 *
 * @param {object} opts
 * @param {Uint8Array[]} opts.chain DER certificates, leaf first, as the peer sent them
 * @param {string} opts.hostname identity from the request URL (DNS name or IP literal)
 * @param {object} [opts.trust] the verification knob:
 *   {mode:'system'}                          bundled CCADB anchors (default)
 *   {mode:'anchors', anchors:[pem|der|...]}  exactly these anchors
 *   {mode:'pinned', pins:['sha256/..'], anchors?} full validation plus an SPKI pin set
 *   {mode:'none', insecureAcceptAnyCertificate:true, pins?} no validation (optionally pins only)
 *   {mode:'custom', verify: async (chain, hostname) => void} caller-supplied policy
 * @param {number} [opts.now] epoch ms, for tests and for callers with a better clock
 * @returns {Promise<object>} the parsed leaf certificate. Every other outcome throws.
 */
export async function verifyChain({ chain, hostname, trust = { mode: 'system' }, now = Date.now() }) {
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
    forbidKeys(trust, 'none', ['anchors', 'verify']);
    if (trust.pins !== undefined) {
      // Pin-only trust: no path validation, but the pin check itself must not fail open — a
      // chain we cannot parse cannot be pinned, so it throws.
      const pins = parsePins(trust.pins);
      const parsed = chain.map((der) => parseCertificate(der));
      await checkPins(pins, parsed, null);
      return parsed[0];
    }
    try {
      return parseCertificate(chain[0]);
    } catch {
      // With verification explicitly disabled, an unparseable leaf is not a failure — but it is
      // also not a certificate we can describe.
      return null;
    }
  }

  if (mode === 'custom') {
    forbidKeys(trust, 'custom', ['anchors', 'pins']);
    if (typeof trust.verify !== 'function') {
      throw invalid("trust mode 'custom' requires a verify(chain, hostname) function");
    }
    const parsed = chain.map((der) => parseCertificate(der));
    // The callback owns policy entirely: throwing rejects the connection, returning accepts it.
    // Its errors propagate untouched so callers see their own diagnostics.
    await trust.verify(parsed, hostname);
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

  const { leaf, path, anchor } = await validatePath({ chain, anchors, hostname, now });
  if (pins) await checkPins(pins, path, anchor);
  return leaf;
}
