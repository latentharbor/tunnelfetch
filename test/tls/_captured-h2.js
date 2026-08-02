// What real clients send over HTTP/2, recorded once a TLS handshake actually completed.
//
// Captured by scripts/capture-h2-preface.mjs. Everything here — the SETTINGS flight, the connection
// WINDOW_UPDATE, the HEADERS flags and the HPACK representation of each field — exists only above a
// completed handshake, which is why the ClientHello capture could not reach it.
//
// Three recordings, because two of them are the same client at different versions and they DISAGREE:
// curl changed SETTINGS_INITIAL_WINDOW_SIZE between 8.7.1 and 8.21.0. This package quotes 8.21.0 for
// its TLS half and had 8.7.1's value for its h2 half, which is a split identity of exactly the kind
// the profile system exists to prevent — one that only a capture could find.

export const H2_CAPTURE_PROVENANCE = Object.freeze({
  capturedAt: "2026-08-02",
  curl871: "curl 8.7.1 / LibreSSL / nghttp2 1.69.0 (macOS system curl)",
  curl821: "curl 8.21.0 / OpenSSL 3.6.3 / nghttp2 1.69.0 (homebrew)",
  chrome: "Chromium (headless) from /Applications/Google Chrome.app",
});

/** SETTINGS as [id, value] pairs, in the order sent. Order is part of the fingerprint. */
export const CURL_871_SETTINGS = Object.freeze([[3,100],[4,10485760],[2,0]]);
export const CURL_821_SETTINGS = Object.freeze([[3,100],[4,65536],[2,0]]);
export const CHROME_SETTINGS  = Object.freeze([[1,65536],[2,0],[4,6291456],[6,262144]]);

/** The connection-level WINDOW_UPDATE increment that follows SETTINGS. */
export const CURL_CONN_WINDOW_INCREMENT = 1048510465;
export const CHROME_CONN_WINDOW_INCREMENT = 15663105;

/** HEADERS frame flags. Chromium sets PRIORITY (0x20); curl does not. */
export const CURL_HEADERS_FLAGS = 0x5;
export const CHROME_HEADERS_FLAGS = 0x25;

/** Per-field HPACK representation, in order, for GET /deep/path. This is what
 *  `http2HpackIndexing` names, and it had never been captured for either client. */
export const CURL_HPACK = Object.freeze([{"kind":"indexed","index":2},{"kind":"indexed","index":7},{"kind":"incremental","index":1},{"kind":"without","index":4},{"kind":"incremental","index":58},{"kind":"incremental","index":19}]);
export const CHROME_HPACK = Object.freeze([{"kind":"indexed","index":2},{"kind":"incremental","index":1},{"kind":"indexed","index":7},{"kind":"without","index":4},{"kind":"incremental","index":0},{"kind":"incremental","index":0},{"kind":"incremental","index":0},{"kind":"incremental","index":0},{"kind":"incremental","index":58},{"kind":"incremental","index":19},{"kind":"incremental","index":0},{"kind":"incremental","index":0},{"kind":"incremental","index":0},{"kind":"incremental","index":0},{"kind":"incremental","index":16},{"kind":"incremental","index":17},{"kind":"incremental","index":0}]);
