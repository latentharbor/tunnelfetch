// Fingerprint profiles: one coherent network identity, instead of a dozen knobs that can disagree.
//
// Every field a fingerprinter reads is individually configurable — cipher list, groups, signature
// algorithms, ALPN, TLS versions, ClientHello extension order, GREASE, request header order,
// HTTP/2 SETTINGS, pseudo-header order, HPACK indexing, Accept-Encoding. That is necessary and it
// is also a trap: nothing stopped a caller assembling a Chrome User-Agent on top of curl's TLS and
// curl's HTTP/2, which is a combination no real client produces and a detector reads instantly.
//
// A profile is the whole identity or none of it. It supplies defaults for every layer at once, and
// it declares what it REQUIRES — because a profile that quietly drops the half of itself this
// runtime cannot perform would recreate exactly the incoherence it exists to prevent.
//
// The values are captured, not recalled. curl 8.21.0 / OpenSSL 3.6.3 and Chromium, both read off
// the wire on 2026-08-01. See test/tls/fingerprint.test.js and test/tls/grease.test.js.

import { ConfigError, codes } from './errors.js';
import { CURL_EXTENSION_ORDER, SHUFFLE_EXTENSIONS } from './tls/handshake-messages.js';
import { CURL_HEADER_ORDER } from './client/header-order.js';

/**
 * @typedef {object} FingerprintProfile
 * @property {string} name
 * @property {object} [tls] merged into `tls`
 * @property {readonly string[]} [headerOrder]
 * @property {Array<[number, number]>} [http2Settings]
 * @property {string[]} [http2PseudoHeaderOrder]
 * @property {Record<string, string>} [http2HpackIndexing]
 * @property {Array<[string, string]>} [headers] default request headers, in order
 * @property {string[]} [requires] capabilities the caller must inject for this identity to be
 *   honest: `'cipher:chacha20'`, `'group:x25519mlkem768'`, `'decoder:br'`, `'decoder:zstd'`
 */

/**
 * curl 8.21.0 / OpenSSL 3.6.3. Complete: every layer was captured, and everything it offers is
 * something this package can actually perform. This is the default identity.
 */
export const curl = Object.freeze({
  name: 'curl/8.21.0',
  tls: Object.freeze({
    alpn: ['h2', 'http/1.1'],
    extensionOrder: CURL_EXTENSION_ORDER,
    grease: false, // curl does not GREASE
  }),
  headerOrder: CURL_HEADER_ORDER,
  headers: Object.freeze([['User-Agent', 'curl/8.21.0']]),
  // Captured: MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, ENABLE_PUSH, in that order.
  http2Settings: Object.freeze([[3, 100], [4, 10485760], [2, 0]]),
  http2PseudoHeaderOrder: Object.freeze([':method', ':scheme', ':authority', ':path']),
  http2HpackIndexing: Object.freeze({ ':path': 'without' }),
  requires: Object.freeze([]),
});

/**
 * Chromium, TLS layer captured off the wire.
 *
 * INCOMPLETE ON PURPOSE, and it refuses to be used as though it were not. Two things are missing
 * and neither can be papered over:
 *
 *   * Chromium offers TLS_CHACHA20_POLY1305_SHA256 and the X25519MLKEM768 group, and this package
 *     implements neither. A ClientHello is an OFFER: a server may take either, and a client that
 *     then cannot complete the handshake has traded a fingerprint mismatch for a dead connection.
 *     Both are reachable by injection, which is why they are listed in `requires` rather than
 *     silently dropped.
 *   * Chromium's HTTP/2 preface was not captured — capturing it needs a TLS server the browser
 *     will trust, which is a different exercise. So this profile carries no h2 layer, and using it
 *     with HTTP/2 enabled would produce a Chromium ClientHello above a curl h2 preface: precisely
 *     the split identity a profile exists to prevent.
 *
 * `applyProfile` refuses both cases with a message naming what is missing.
 */
export const chrome = Object.freeze({
  name: 'chrome/150',
  tls: Object.freeze({
    // 16 suites, GREASE excluded — it is added by the grease option, not carried in the list.
    ciphers: Object.freeze([
      0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
      0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ]),
    groups: Object.freeze([0x11ec, 0x001d, 0x0017, 0x0018]),
    // Chrome sends real key_shares for X25519MLKEM768 and X25519 (a GREASE entry leads, added by
    // the grease option). Both must be generated, so both are named here; the hybrid entry is
    // stripped, and this whole profile refused, unless an ML-KEM implementation was injected.
    offerGroups: Object.freeze([0x11ec, 0x001d]),
    sigSchemes: Object.freeze([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
    alpn: ['h2', 'http/1.1'],
    // Measured: two hellos, identical extension set, entirely different orders. Chromium shuffles.
    extensionOrder: SHUFFLE_EXTENSIONS,
    grease: true,
  }),
  // Captured off the wire the same way as the TLS layer: Chrome 150 driven at this package's own
  // TLS test server with --ignore-certificate-errors, so no root CA was installed anywhere. The
  // ClientHello precedes certificate validation and ALPN is negotiated inside the handshake, so
  // both fingerprints are exactly what the browser normally sends.
  http2Settings: Object.freeze([[1, 65536], [2, 0], [4, 6291456], [6, 262144]]),
  http2ConnectionWindow: 15663105 + 65535,
  // m,a,s,p — NOT curl's m,s,a,p. Measured, and a difference that would have been easy to miss.
  http2PseudoHeaderOrder: Object.freeze([':method', ':authority', ':scheme', ':path']),
  headerOrder: Object.freeze([
    'host',
    'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'upgrade-insecure-requests', 'user-agent', 'accept',
    'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest',
    'accept-encoding', 'accept-language', 'priority',
    '*',
    'content-length', 'content-type',
  ]),
  headers: Object.freeze([['Accept-Encoding', 'gzip, deflate, br, zstd']]),
  // http2:captured is gone — it is captured now. What remains is what this package cannot yet
  // PERFORM, which is a different kind of gap and the only kind that can make an offer dishonest.
  requires: Object.freeze([
    'cipher:chacha20',
    'group:x25519mlkem768',
    'decoder:br',
    'decoder:zstd',
  ]),
});

/** @type {Record<string, FingerprintProfile>} */
export const profiles = Object.freeze({ curl, chrome });

/**
 * Fold a profile into a Client's options, and refuse an identity that cannot be honoured.
 *
 * Explicit options WIN over the profile: a caller who names a field meant to name it, and silently
 * overriding them would make the profile impossible to adjust. The profile fills what was not said.
 *
 * @param {object} options as given to the Client
 * @returns {object} options with the profile folded in
 */
export function applyProfile(options) {
  const p = options.profile;
  if (!p) return options;
  if (typeof p !== 'object' || !p.name) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      'profile must be a fingerprint profile object; see `profiles` for the built-in ones',
    );
  }

  const missing = [];
  for (const need of p.requires ?? []) {
    const [kind, what] = need.split(':');
    if (kind === 'decoder' && !options.decoders?.[what]) missing.push(need);
    if (kind === 'cipher' && !options.ciphers?.[what]) missing.push(need);
    if (kind === 'group' && !options.groups?.[what]) missing.push(need);
    // A profile with no captured h2 layer must not be run over HTTP/2, or it presents this
    // identity's ClientHello above a different client's preface.
    if (kind === 'http2' && options.http2 !== false) missing.push(need);
  }
  if (missing.length) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `the "${p.name}" profile cannot be presented honestly: ${missing.join(', ')} ` +
        `${missing.length === 1 ? 'is' : 'are'} missing. A fingerprint field this package cannot ` +
        'perform is an offer a server may take and then find unhonoured, which fails the ' +
        'connection rather than merely looking wrong. Supply the missing pieces (see `decoders`, ' +
        '`ciphers`, `groups`) or set `http2: false`, or use a profile that is complete.',
      { profile: p.name, missing },
    );
  }

  const out = { ...options };
  if (p.tls) out.tls = { ...p.tls, ...(options.tls ?? {}) };
  for (const key of ['headerOrder', 'http2Settings', 'http2PseudoHeaderOrder', 'http2HpackIndexing']) {
    if (options[key] === undefined && p[key] != null) out[key] = p[key];
  }
  // Profile headers are DEFAULTS: a request that sets its own User-Agent keeps it. They are folded
  // in per request rather than here, so this only records them.
  if (p.headers) out.profileHeaders = p.headers;
  return out;
}
