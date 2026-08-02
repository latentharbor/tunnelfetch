// A ClientHello recorded off the wire from a REAL client. Not written by hand, not derived from
// anything in src/ — captured by scripts/capture-clienthello.mjs, which parses it with its own
// parser for exactly that reason.
//
// This exists because every "captured off the wire" claim in this repository used to have no
// artifact behind it. The fingerprint tests asserted the builder against constants in src/, which
// catches drift and CANNOT catch the constants being wrong about the client they name. A recording
// is an independent witness: it comes from a program we did not write.
//
// Reproduce:
//
//   node scripts/capture-clienthello.mjs out.json -- \
//     /opt/homebrew/opt/curl/bin/curl -sk --http2 https://localhost:PORT/
//
// curl advertises its TLS backend in `curl --version`; a curl linked against LibreSSL or
// SecureTransport sends a COMPLETELY different hello (macOS system curl 8.7.1 sends seven
// extensions against this one's twelve), so the backend is part of the identity, not a footnote.

/** @type {{ client: string, capturedAt: string, command: string }} */
export const CURL_CAPTURE_PROVENANCE = Object.freeze({
  client: "curl 8.21.0 / OpenSSL 3.6.3 (aarch64-apple-darwin25.4.0)",
  capturedAt: "2026-08-02",
  command: "/opt/homebrew/opt/curl/bin/curl -sk --http2 https://localhost:PORT/",
});

/** The whole record, base64. 5-byte TLS record header included. */
export const CURL_CLIENT_HELLO_B64 =
  "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";

/** Extension types in WIRE ORDER, which is what JA3/JA4 hash. */
export const CURL_CAPTURED_EXTENSION_ORDER = Object.freeze([65281,0,11,10,16,22,23,49,13,43,45,51]);

/** Cipher suites in offer order. */
export const CURL_CAPTURED_CIPHERS = Object.freeze([4866,4867,4865,49196,49200,159,52393,52392,52394,49195,49199,158,49188,49192,107,49187,49191,103,49162,49172,57,49161,49171,51,157,156,61,60,53,47]);

export const CURL_CAPTURED_BYTES = () =>
  Uint8Array.from(atob(CURL_CLIENT_HELLO_B64), (c) => c.charCodeAt(0));

// ---------------------------------------------------------------------------------------------
// Chromium, recorded the same way. Headless, --ignore-certificate-errors, pointed at the capture
// socket; the ClientHello precedes any certificate decision, so nothing about it is affected.
//
// One hello is one SAMPLE, not the identity: Chromium shuffles its extension order per connection
// (see src/tls/grease.js), so the order below is what this run produced and must not be asserted
// as fixed. The cipher list, the groups, the signature algorithms and the GREASE placement are
// stable, and those are what the tests read.

export const CHROME_CAPTURE_PROVENANCE = Object.freeze({
  client: "Chromium (headless) from /Applications/Google Chrome.app",
  capturedAt: "2026-08-02",
  command: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --headless=new …",
});

export const CHROME_CLIENT_HELLO_B64 =
  "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";

/** Offer order, GREASE included — the leading GREASE is part of the fingerprint. */
export const CHROME_CAPTURED_CIPHERS = Object.freeze([14906,4865,4866,4867,49195,49199,49196,49200,52393,52392,49171,49172,156,157,47,53]);
/** supported_groups, GREASE included. */
export const CHROME_CAPTURED_GROUPS = Object.freeze([31354,4588,29,23,24]);
/** signature_algorithms, in offer order. */
export const CHROME_CAPTURED_SIG_SCHEMES = Object.freeze([2308,2309,2310,1027,2052,1025,1283,2053,1281,2054,1537]);
/** ONE shuffle sample. Do not assert as an order; it is here so the SET is checkable. */
export const CHROME_CAPTURED_EXTENSION_SAMPLE = Object.freeze([14906,18,65037,16,11,13,51,27,17613,35,23,5,43,10,65281,45,43690]);

export const CHROME_CAPTURED_BYTES = () =>
  Uint8Array.from(atob(CHROME_CLIENT_HELLO_B64), (c) => c.charCodeAt(0));
