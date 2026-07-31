/** The 24-byte client connection preface (RFC 9113 s3.4). Sent before any frame. */
export const CONNECTION_PREFACE: Uint8Array<ArrayBuffer>;
export namespace FRAME {
    let DATA: number;
    let HEADERS: number;
    let PRIORITY: number;
    let RST_STREAM: number;
    let SETTINGS: number;
    let PUSH_PROMISE: number;
    let PING: number;
    let GOAWAY: number;
    let WINDOW_UPDATE: number;
    let CONTINUATION: number;
}
/** Reverse map for diagnostics: an unknown type still gets a number. */
export const FRAME_NAME: {
    [k: string]: string;
};
export namespace FLAG {
    export let END_STREAM: number;
    export let ACK: number;
    export let END_HEADERS: number;
    export let PADDED: number;
    let PRIORITY_1: number;
    export { PRIORITY_1 as PRIORITY };
}
export namespace SETTINGS {
    let HEADER_TABLE_SIZE: number;
    let ENABLE_PUSH: number;
    let MAX_CONCURRENT_STREAMS: number;
    let INITIAL_WINDOW_SIZE: number;
    let MAX_FRAME_SIZE: number;
    let MAX_HEADER_LIST_SIZE: number;
}
export const SETTINGS_NAME: {
    [k: string]: string;
};
export namespace H2_ERROR {
    let NO_ERROR: number;
    let PROTOCOL_ERROR: number;
    let INTERNAL_ERROR: number;
    let FLOW_CONTROL_ERROR: number;
    let SETTINGS_TIMEOUT: number;
    let STREAM_CLOSED: number;
    let FRAME_SIZE_ERROR: number;
    let REFUSED_STREAM: number;
    let CANCEL: number;
    let COMPRESSION_ERROR: number;
    let CONNECT_ERROR: number;
    let ENHANCE_YOUR_CALM: number;
    let INADEQUATE_SECURITY: number;
    let HTTP_1_1_REQUIRED: number;
}
export const H2_ERROR_NAME: {
    [k: string]: string;
};
/** The default SETTINGS_MAX_FRAME_SIZE and its floor (RFC 9113 s6.5.2): 2^14. A peer may raise
 *  its own limit, but until it says so in SETTINGS we must not send a frame larger than this. */
export const DEFAULT_MAX_FRAME_SIZE: 16384;
/** The ceiling a peer may set MAX_FRAME_SIZE to: 2^24 - 1. Beyond it, SETTINGS is a PROTOCOL_ERROR. */
export const MAX_ALLOWED_FRAME_SIZE: 16777215;
/** The default per-stream/-connection flow-control window before any SETTINGS/WINDOW_UPDATE. */
export const DEFAULT_INITIAL_WINDOW: 65535;
/** The largest a flow-control window may reach; exceeding it is a FLOW_CONTROL_ERROR (s6.9.1). */
export const MAX_WINDOW: 2147483647;
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
export const CLIENT_INITIAL_WINDOW_SIZE: 10485760;
export const CLIENT_MAX_CONCURRENT_STREAMS: 100;
/** curl raises the CONNECTION receive window to exactly 1000 MiB with one WINDOW_UPDATE on
 *  stream 0 right after SETTINGS. The increment below is 1000 MiB - 65535, i.e. what takes the
 *  default 65535 window up to 1048576000. Sent in the same preface flight, same order as curl. */
export const CLIENT_CONNECTION_WINDOW: 1048576000;
export const CLIENT_CONNECTION_WINDOW_INCREMENT: number;
/**
 * The order pseudo-headers are emitted in a request HEADERS block. curl/nghttp2 sends
 * :method, :scheme, :authority, :path — captured, not guessed. h2 fingerprinters read this order
 * (the "m,s,a,p" tail of an Akamai-style h2 fingerprint), so it is fixed to match.
 */
export const PSEUDO_HEADER_ORDER: string[];
/** ALPN identifiers. Offering both and following the server's pick is the whole ALPN contract;
 *  there is no reconnect-and-retry path if the server picks the other one. */
export const ALPN_H2: "h2";
export const ALPN_HTTP11: "http/1.1";
