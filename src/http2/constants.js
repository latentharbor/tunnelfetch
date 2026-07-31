// HTTP/2 wire constants (RFC 9113), and the deliberately narrow client posture on top of them.
//
// This is a client that opens streams and reads responses. It never receives a request, never
// serves a push, and never prioritises — so the constants for those exist only to NAME what we
// refuse when a peer sends them, not to act on them.
//
// The SETTINGS and window values below are not defaults chosen for taste. They are the exact
// values curl 8.7.1 / nghttp2 1.69.0 puts on the wire, captured over a real ALPN-negotiated h2
// handshake. That matters empirically, not aesthetically: the whole reason to implement h2 here
// is that some sites challenge HTTP/1.1 as a bot signal while letting curl's h2 through, and a
// naive h2 fingerprint can fail exactly where curl's succeeds. Matching the SETTINGS frame, the
// initial window sizes, the connection WINDOW_UPDATE, and the pseudo-header order removes the
// cheapest tells. See the capture note beside `preferredSettingsOrder`.

/** The 24-byte client connection preface (RFC 9113 s3.4). Sent before any frame. */
export const CONNECTION_PREFACE = Uint8Array.from(
  'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',
  (c) => c.charCodeAt(0),
);

/** Frame types (RFC 9113 s6). PRIORITY and PUSH_PROMISE are named to reject, not to honour. */
export const FRAME = {
  DATA: 0x0,
  HEADERS: 0x1,
  PRIORITY: 0x2,
  RST_STREAM: 0x3,
  SETTINGS: 0x4,
  PUSH_PROMISE: 0x5,
  PING: 0x6,
  GOAWAY: 0x7,
  WINDOW_UPDATE: 0x8,
  CONTINUATION: 0x9,
};

/** Reverse map for diagnostics: an unknown type still gets a number. */
export const FRAME_NAME = Object.fromEntries(Object.entries(FRAME).map(([k, v]) => [v, k]));

/** Frame flags (RFC 9113 s6). The same bit means different things per frame type. */
export const FLAG = {
  END_STREAM: 0x1, // DATA, HEADERS
  ACK: 0x1, // SETTINGS, PING (same bit, different frames)
  END_HEADERS: 0x4, // HEADERS, CONTINUATION, PUSH_PROMISE
  PADDED: 0x8, // DATA, HEADERS, PUSH_PROMISE
  PRIORITY: 0x20, // HEADERS
};

/** SETTINGS parameter identifiers (RFC 9113 s6.5.2). */
export const SETTINGS = {
  HEADER_TABLE_SIZE: 0x1,
  ENABLE_PUSH: 0x2,
  MAX_CONCURRENT_STREAMS: 0x3,
  INITIAL_WINDOW_SIZE: 0x4,
  MAX_FRAME_SIZE: 0x5,
  MAX_HEADER_LIST_SIZE: 0x6,
};

export const SETTINGS_NAME = Object.fromEntries(
  Object.entries(SETTINGS).map(([k, v]) => [v, k]),
);

/** Error codes (RFC 9113 s7). Sent in RST_STREAM and GOAWAY; also received in them. */
export const H2_ERROR = {
  NO_ERROR: 0x0,
  PROTOCOL_ERROR: 0x1,
  INTERNAL_ERROR: 0x2,
  FLOW_CONTROL_ERROR: 0x3,
  SETTINGS_TIMEOUT: 0x4,
  STREAM_CLOSED: 0x5,
  FRAME_SIZE_ERROR: 0x6,
  REFUSED_STREAM: 0x7,
  CANCEL: 0x8,
  COMPRESSION_ERROR: 0x9,
  CONNECT_ERROR: 0xa,
  ENHANCE_YOUR_CALM: 0xb,
  INADEQUATE_SECURITY: 0xc,
  HTTP_1_1_REQUIRED: 0xd,
};

export const H2_ERROR_NAME = Object.fromEntries(
  Object.entries(H2_ERROR).map(([k, v]) => [v, k]),
);

// --- protocol-fixed limits ---------------------------------------------------------------------

/** The default SETTINGS_MAX_FRAME_SIZE and its floor (RFC 9113 s6.5.2): 2^14. A peer may raise
 *  its own limit, but until it says so in SETTINGS we must not send a frame larger than this. */
export const DEFAULT_MAX_FRAME_SIZE = 16384;
/** The ceiling a peer may set MAX_FRAME_SIZE to: 2^24 - 1. Beyond it, SETTINGS is a PROTOCOL_ERROR. */
export const MAX_ALLOWED_FRAME_SIZE = 16777215;
/** The default per-stream/-connection flow-control window before any SETTINGS/WINDOW_UPDATE. */
export const DEFAULT_INITIAL_WINDOW = 65535;
/** The largest a flow-control window may reach; exceeding it is a FLOW_CONTROL_ERROR (s6.9.1). */
export const MAX_WINDOW = 2147483647; // 2^31 - 1

// --- our client posture (the curl fingerprint) -------------------------------------------------

/**
 * The SETTINGS we advertise, and the ORDER we advertise them in. Both are matched to curl
 * 8.7.1 / nghttp2 1.69.0 as captured on the wire:
 *
 *   SETTINGS: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=10485760, ENABLE_PUSH=0
 *   emitted in the id order 3, 4, 2 — and nothing else (no HEADER_TABLE_SIZE, no MAX_FRAME_SIZE,
 *   no MAX_HEADER_LIST_SIZE), so those stay at their protocol defaults exactly as curl leaves them.
 *
 * These are the values the SERVER sees and fingerprints on, so they are held fixed here rather
 * than exposed as knobs. The receive-side buffering they imply is bounded elsewhere (see the
 * flow-control note in connection.js): a large advertised window is a fingerprint choice, not a
 * promise to buffer that much before applying backpressure.
 */
export const CLIENT_INITIAL_WINDOW_SIZE = 10485760; // 10 MiB, curl's SETTINGS_INITIAL_WINDOW_SIZE
export const CLIENT_MAX_CONCURRENT_STREAMS = 100; // curl's SETTINGS_MAX_CONCURRENT_STREAMS

/** curl raises the CONNECTION receive window to exactly 1000 MiB with one WINDOW_UPDATE on
 *  stream 0 right after SETTINGS. The increment below is 1000 MiB - 65535, i.e. what takes the
 *  default 65535 window up to 1048576000. Sent in the same preface flight, same order as curl. */
export const CLIENT_CONNECTION_WINDOW = 1048576000; // 1000 MiB
export const CLIENT_CONNECTION_WINDOW_INCREMENT = CLIENT_CONNECTION_WINDOW - DEFAULT_INITIAL_WINDOW; // 1048510465

/**
 * The order pseudo-headers are emitted in a request HEADERS block. curl/nghttp2 sends
 * :method, :scheme, :authority, :path — captured, not guessed. h2 fingerprinters read this order
 * (the "m,s,a,p" tail of an Akamai-style h2 fingerprint), so it is fixed to match.
 */
export const PSEUDO_HEADER_ORDER = [':method', ':scheme', ':authority', ':path'];

/** ALPN identifiers. Offering both and following the server's pick is the whole ALPN contract;
 *  there is no reconnect-and-retry path if the server picks the other one. */
export const ALPN_H2 = 'h2';
export const ALPN_HTTP11 = 'http/1.1';
