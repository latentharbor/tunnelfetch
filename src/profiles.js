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
// The values are captured, not recalled — and as of 1.6.2 the captures are COMMITTED, in
// test/tls/_captured-hellos.js, recorded by scripts/capture-clienthello.mjs from curl 8.21.0 /
// OpenSSL 3.6.3 and from Chromium. Until then the claim had no artifact behind it: the tests
// compared the builder against the constants below, which catches drift and cannot catch the
// constants being wrong about the client they name.
//
// Two things that check found, both now asserted rather than assumed:
//   * curl's TLS backend is part of its identity. macOS system curl (8.7.1, LibreSSL) sends SEVEN
//     extensions where the OpenSSL build sends twelve, so "curl" alone does not name a fingerprint.
//   * Chromium leads signature_algorithms with ML-DSA-44/65/87 (0x0904/5/6), which this package
//     cannot verify and therefore must not offer. The omission is correct and was undocumented.

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
  //
  // INITIAL_WINDOW_SIZE is 65536 and used to be 10485760, which was curl 8.7.1's value. curl changed
  // it between 8.7.1 and 8.21.0, and this profile's TLS half is captured from 8.21.0 — so the
  // package was presenting one curl's ClientHello above a different curl's SETTINGS. A split
  // identity inside a single named client, and one only a capture could find: both halves were
  // internally consistent and each was individually true of SOME curl. See test/tls/_captured-h2.js,
  // which holds both recordings side by side for exactly this reason.
  http2Settings: Object.freeze([[3, 100], [4, 65536], [2, 0]]),
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
    // Chromium's list, in Chromium's order, RESTRICTED to what this package can perform. It offers
    // sixteen; the eight left out are TLS 1.2 CBC, RSA key exchange and the 1.2 ChaCha20 suites,
    // none of which this package implements. Listing them would have been the exact dishonesty the
    // requires-check exists to prevent: in a 1.3 handshake they are ignored, but a 1.2 server can
    // select one and get a dead connection. 0x1303 is present because ChaCha20 is injectable and
    // this profile requires it.
    ciphers: Object.freeze([0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030]),
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
  // Captured in 1.6.2, and the answer was that there was nothing to change: Chromium emits `:path`
  // WITHOUT indexing and everything else incrementally, byte-identical in representation to curl.
  // 1.6.1 recorded this as an uncaptured gap and refused to guess at it; the guess would in fact
  // have been right, which is not a reason to have guessed. It is declared explicitly now so the
  // identity states its own value instead of inheriting one by accident.
  http2HpackIndexing: Object.freeze({ ':path': 'without' }),
  // Chromium sets PRIORITY on its request HEADERS (flags 0x25) and carries the five deprecated
  // priority bytes: `80 00 00 00 ff`, i.e. exclusive, dependency 0, weight byte 255. Captured, in
  // test/tls/_captured-h2.js. 1.6.2 found the difference and documented it; 1.6.5 emits it.
  //
  // RFC 9113 s5.3.2 deprecates the mechanism and this package still IGNORES every PRIORITY frame it
  // receives — sending it is a statement about identity, not a request to be prioritised, and those
  // are different things. curl sets no priority, so `profiles.curl` leaves this unset and the
  // default stays "do not send".
  http2HeadersPriority: Object.freeze({ exclusive: true, streamDependency: 0, weight: 255 }),
  //
  // The connection window immediately above was DEAD until 1.6.1 — declared here, copied by
  // nothing, passed by nothing, and read under a different name — so every connection using this
  // profile sent curl's 1000 MiB increment. Four places had to agree and no test checked that they
  // did. There is one now.
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

  // A profile may carry its own implementations — `tunnelfetch/profile/chrome` bundles the two
  // WASM primitives, and importing it is the opt-in. So a requirement is satisfied by either the
  // caller's options OR the profile itself; checking only the options made a self-sufficient
  // profile refuse itself.
  const supplied = (kind, what) =>
    Boolean(options[kind]?.[what] ?? p[kind]?.[what]);
  const missing = [];
  for (const need of p.requires ?? []) {
    const [kind, what] = need.split(':');
    if (kind === 'decoder' && !supplied('decoders', what)) missing.push(need);
    if (kind === 'cipher' && !supplied('ciphers', what)) missing.push(need);
    if (kind === 'group' && !supplied('groups', what)) missing.push(need);
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
        'connection rather than merely looking wrong. For the Chrome identity with its two WASM ' +
        "primitives already wired in, import { chrome } from 'tunnelfetch/profile/chrome'; " +
        'otherwise supply the missing pieces yourself through `decoders`, `ciphers` and `groups`.',
      { profile: p.name, missing },
    );
  }

  const out = { ...options };
  if (p.tls) out.tls = { ...p.tls, ...(options.tls ?? {}) };
  // Implementations the profile brings, with the caller's taking precedence.
  for (const kind of ['ciphers', 'groups', 'decoders']) {
    if (p[kind]) out[kind] = { ...p[kind], ...(options[kind] ?? {}) };
  }
  // Every h2 fingerprint field a profile can carry must be listed here. `http2ConnectionWindow`
  // was missing, which made it dead config: the chrome profile declared Chromium's ~15 MiB window
  // and every chrome connection sent curl's 1000 MiB one.
  for (const key of ['headerOrder', 'http2Settings', 'http2ConnectionWindow',
                     'http2PseudoHeaderOrder', 'http2HpackIndexing', 'http2HeadersPriority']) {
    if (options[key] === undefined && p[key] != null) out[key] = p[key];
  }
  // Profile headers are DEFAULTS: a request that sets its own User-Agent keeps it. They are folded
  // in per request rather than here, so this only records them.
  if (p.headers) out.profileHeaders = p.headers;
  return out;
}
