/**
 * One frame off the wire. `payload` aliases the reader's buffer and must not be retained.
 * @typedef {object} Frame
 * @property {number} type
 * @property {number} flags
 * @property {number} streamId
 * @property {Uint8Array} payload
 */
/**
 * Read exactly one frame. Enforces our advertised SETTINGS_MAX_FRAME_SIZE on receipt: a peer
 * that sends a larger frame commits a FRAME_SIZE_ERROR (RFC 9113 s4.2), and refusing at the
 * header — before reading the body — is what bounds how much a hostile peer can make us buffer.
 * Returns null only on a clean EOF exactly at a frame boundary.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {number} maxFrameSize the largest payload we will accept
 * @returns {Promise<Frame | null>}
 */
export function readFrame(reader: import("../util/bytes.js").ByteReader, maxFrameSize?: number): Promise<Frame | null>;
/**
 * Serialise one frame (header + payload) into a single buffer.
 * @param {number} type
 * @param {number} flags
 * @param {number} streamId
 * @param {Uint8Array} payload
 * @returns {Uint8Array}
 */
export function serializeFrame(type: number, flags: number, streamId: number, payload?: Uint8Array): Uint8Array;
/**
 * A SETTINGS frame. `entries` is an array of [id, value]; order is preserved because it is part
 * of the client fingerprint. An ACK carries no payload and sets the ACK flag.
 * @param {Array<[number, number]>} entries
 * @param {boolean} [ack]
 * @returns {Uint8Array}
 */
export function settingsFrame(entries: Array<[number, number]>, ack?: boolean): Uint8Array;
/** A WINDOW_UPDATE frame (RFC 9113 s6.9). streamId 0 is connection-level. */
export function windowUpdateFrame(streamId: any, increment: any): Uint8Array<ArrayBufferLike>;
/** A RST_STREAM frame (RFC 9113 s6.4). */
export function rstStreamFrame(streamId: any, errorCode: any): Uint8Array<ArrayBufferLike>;
/** A PING frame (RFC 9113 s6.7). The 8-byte opaque data is echoed on ACK. */
export function pingFrame(opaque: any, ack?: boolean): Uint8Array<ArrayBufferLike>;
/** A GOAWAY frame (RFC 9113 s6.8). */
export function goawayFrame(lastStreamId: any, errorCode: any, debug?: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBufferLike>;
/** A HEADERS frame carrying a full (already-fragmented-if-needed) block. No PADDED, no PRIORITY —
 *  a client that emits neither is exactly what curl does. */
export function headersFrame(streamId: any, block: any, { endStream, endHeaders }?: {
    endStream?: boolean | undefined;
    endHeaders?: boolean | undefined;
}): Uint8Array<ArrayBufferLike>;
/** A CONTINUATION frame (RFC 9113 s6.10), for a header block that overflows one frame. */
export function continuationFrame(streamId: any, block: any, endHeaders: any): Uint8Array<ArrayBufferLike>;
/** A DATA frame (RFC 9113 s6.1). No padding is ever emitted. */
export function dataFrame(streamId: any, data: any, endStream: any): Uint8Array<ArrayBufferLike>;
/**
 * Strip a DATA/HEADERS PADDED frame's pad length and padding, returning the meaningful slice.
 * The pad length byte and padding both count against flow control (the caller handles that);
 * this only removes them from the bytes handed onward. A pad length >= the remaining payload is
 * a PROTOCOL_ERROR (RFC 9113 s6.1).
 * @param {Uint8Array} payload
 * @returns {{ data: Uint8Array, padLength: number }}
 */
export function stripPadding(payload: Uint8Array): {
    data: Uint8Array;
    padLength: number;
};
/**
 * The header block fragment inside a HEADERS payload, after removing padding (PADDED) and the
 * priority fields (PRIORITY). Priority is deprecated (RFC 9113 s5.3.2) and its fields are
 * discarded, not acted on.
 * @param {Uint8Array} payload
 * @param {number} flags
 * @returns {Uint8Array}
 */
export function headersBlockFragment(payload: Uint8Array, flags: number): Uint8Array;
/**
 * Parse a SETTINGS payload into [id, value] pairs. Length must be a multiple of 6
 * (RFC 9113 s6.5); anything else is a FRAME_SIZE_ERROR.
 * @param {Uint8Array} payload
 * @returns {Array<[number, number]>}
 */
export function parseSettings(payload: Uint8Array): Array<[number, number]>;
/**
 * Parse a WINDOW_UPDATE payload. Must be exactly 4 bytes; a zero increment is a protocol error
 * (RFC 9113 s6.9), surfaced by the caller which knows the stream context.
 * @param {Uint8Array} payload
 * @returns {number} the 31-bit increment
 */
export function parseWindowUpdate(payload: Uint8Array): number;
/**
 * Parse a RST_STREAM payload (exactly 4 bytes: an error code).
 * @param {Uint8Array} payload
 * @returns {number}
 */
export function parseRstStream(payload: Uint8Array): number;
/**
 * Parse a GOAWAY payload (RFC 9113 s6.8): last-stream-id, error code, optional debug data.
 * @param {Uint8Array} payload
 * @returns {{ lastStreamId: number, errorCode: number, debug: Uint8Array }}
 */
export function parseGoaway(payload: Uint8Array): {
    lastStreamId: number;
    errorCode: number;
    debug: Uint8Array;
};
/** The fixed frame header size (RFC 9113 s4.1): 24-bit length, type, flags, 31-bit stream id. */
export const FRAME_HEADER_SIZE: 9;
/**
 * One frame off the wire. `payload` aliases the reader's buffer and must not be retained.
 */
export type Frame = {
    type: number;
    flags: number;
    streamId: number;
    payload: Uint8Array;
};
