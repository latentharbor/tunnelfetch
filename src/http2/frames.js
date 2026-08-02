// HTTP/2 frame layer (RFC 9113 s4, s6): the 9-octet header, and pure serialisers / parsers for
// the frame types a client sends and receives.
//
// This file knows nothing about streams, flow control, or state machines — it turns bytes into
// `{type, flags, streamId, payload}` and back, and validates only what framing itself dictates
// (a length the type forbids, padding longer than the frame). Everything semantic lives in
// connection.js. Splitting it this way is what lets the frame reader be run under all chunkings:
// it must produce identical frames whether the transport hands over one byte or the whole record.

import { Http2Error, codes } from '../errors.js';
import { UnexpectedEofError, readU16, readU32 } from '../util/bytes.js';
import { FRAME, FLAG, DEFAULT_MAX_FRAME_SIZE } from './constants.js';

/** The fixed frame header size (RFC 9113 s4.1): 24-bit length, type, flags, 31-bit stream id. */
export const FRAME_HEADER_SIZE = 9;

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
export async function readFrame(reader, maxFrameSize = DEFAULT_MAX_FRAME_SIZE) {
  let header;
  try {
    header = await reader.readExactly(FRAME_HEADER_SIZE, 'HTTP/2 frame header');
  } catch (e) {
    if (e instanceof UnexpectedEofError && e.detail?.got === 0) return null; // clean end
    throw e;
  }
  const length = (header[0] << 16) | (header[1] << 8) | header[2];
  const type = header[3];
  const flags = header[4];
  // The reserved high bit of the stream id is explicitly ignored (RFC 9113 s4.1), never checked.
  const streamId = readU32(header, 5) & 0x7fffffff;
  if (length > maxFrameSize) {
    throw new Http2Error(
      codes.HTTP2_FRAME_SIZE,
      `frame length ${length} exceeds SETTINGS_MAX_FRAME_SIZE ${maxFrameSize}`,
      { length, limit: maxFrameSize, type, streamId },
    );
  }
  const payload = length === 0 ? EMPTY : await reader.readExactly(length, 'HTTP/2 frame payload');
  return { type, flags, streamId, payload };
}

const EMPTY = new Uint8Array(0);

// ---------------------------------------------------------------------- serialisers

/** Write a frame header into the first 9 bytes of `out`, at offset `o`. */
function putHeader(out, o, length, type, flags, streamId) {
  out[o] = (length >>> 16) & 0xff;
  out[o + 1] = (length >>> 8) & 0xff;
  out[o + 2] = length & 0xff;
  out[o + 3] = type;
  out[o + 4] = flags;
  out[o + 5] = (streamId >>> 24) & 0x7f; // clear the reserved bit
  out[o + 6] = (streamId >>> 16) & 0xff;
  out[o + 7] = (streamId >>> 8) & 0xff;
  out[o + 8] = streamId & 0xff;
}

/**
 * Serialise one frame (header + payload) into a single buffer.
 * @param {number} type
 * @param {number} flags
 * @param {number} streamId
 * @param {Uint8Array} payload
 * @returns {Uint8Array}
 */
export function serializeFrame(type, flags, streamId, payload = EMPTY) {
  const out = new Uint8Array(FRAME_HEADER_SIZE + payload.length);
  putHeader(out, 0, payload.length, type, flags, streamId);
  out.set(payload, FRAME_HEADER_SIZE);
  return out;
}

/**
 * A SETTINGS frame. `entries` is an array of [id, value]; order is preserved because it is part
 * of the client fingerprint. An ACK carries no payload and sets the ACK flag.
 * @param {Array<[number, number]>} entries
 * @param {boolean} [ack]
 * @returns {Uint8Array}
 */
export function settingsFrame(entries, ack = false) {
  if (ack) return serializeFrame(FRAME.SETTINGS, FLAG.ACK, 0, EMPTY);
  const payload = new Uint8Array(entries.length * 6);
  let o = 0;
  for (const [id, value] of entries) {
    payload[o] = (id >>> 8) & 0xff;
    payload[o + 1] = id & 0xff;
    payload[o + 2] = (value >>> 24) & 0xff;
    payload[o + 3] = (value >>> 16) & 0xff;
    payload[o + 4] = (value >>> 8) & 0xff;
    payload[o + 5] = value & 0xff;
    o += 6;
  }
  return serializeFrame(FRAME.SETTINGS, 0, 0, payload);
}

/** A WINDOW_UPDATE frame (RFC 9113 s6.9). streamId 0 is connection-level. */
export function windowUpdateFrame(streamId, increment) {
  const payload = new Uint8Array(4);
  payload[0] = (increment >>> 24) & 0x7f;
  payload[1] = (increment >>> 16) & 0xff;
  payload[2] = (increment >>> 8) & 0xff;
  payload[3] = increment & 0xff;
  return serializeFrame(FRAME.WINDOW_UPDATE, 0, streamId, payload);
}

/** A RST_STREAM frame (RFC 9113 s6.4). */
export function rstStreamFrame(streamId, errorCode) {
  const payload = new Uint8Array(4);
  payload[0] = (errorCode >>> 24) & 0xff;
  payload[1] = (errorCode >>> 16) & 0xff;
  payload[2] = (errorCode >>> 8) & 0xff;
  payload[3] = errorCode & 0xff;
  return serializeFrame(FRAME.RST_STREAM, 0, streamId, payload);
}

/** A PING frame (RFC 9113 s6.7). The 8-byte opaque data is echoed on ACK. */
export function pingFrame(opaque, ack = false) {
  return serializeFrame(FRAME.PING, ack ? FLAG.ACK : 0, 0, opaque);
}

/** A GOAWAY frame (RFC 9113 s6.8). */
export function goawayFrame(lastStreamId, errorCode, debug = EMPTY) {
  const payload = new Uint8Array(8 + debug.length);
  payload[0] = (lastStreamId >>> 24) & 0x7f;
  payload[1] = (lastStreamId >>> 16) & 0xff;
  payload[2] = (lastStreamId >>> 8) & 0xff;
  payload[3] = lastStreamId & 0xff;
  payload[4] = (errorCode >>> 24) & 0xff;
  payload[5] = (errorCode >>> 16) & 0xff;
  payload[6] = (errorCode >>> 8) & 0xff;
  payload[7] = errorCode & 0xff;
  payload.set(debug, 8);
  return serializeFrame(FRAME.GOAWAY, 0, 0, payload);
}

/**
 * A HEADERS frame carrying a full (already-fragmented-if-needed) block. Never PADDED.
 *
 * PRIORITY is emitted only when `priority` is supplied, because whether a client sends it is part
 * of its identity: curl does not, Chromium does — flags 0x25 with `80 00 00 00 ff`, captured in
 * test/tls/_captured-h2.js. RFC 9113 s5.3.2 deprecates the mechanism and this package ignores
 * every PRIORITY frame it receives, but a frame-level fingerprinter reads whether the flag is set,
 * so refusing to emit it would make the Chromium identity wrong in a way nothing else could fix.
 *
 * The five bytes are exclusive (1 bit) + stream dependency (31) + weight (8). The weight is sent
 * as-is: RFC 7540 s6.3 defines the wire byte as weight-minus-one, so Chromium's 255 is a weight of
 * 256, and passing the byte through keeps this function free of an off-by-one nobody would see.
 *
 * @param {{ exclusive?: boolean, streamDependency?: number, weight: number } | null} [opts.priority]
 */
export function headersFrame(
  streamId,
  block,
  { endStream = false, endHeaders = true, priority = null } = {},
) {
  let flags = 0;
  if (endStream) flags |= FLAG.END_STREAM;
  if (endHeaders) flags |= FLAG.END_HEADERS;
  if (!priority) return serializeFrame(FRAME.HEADERS, flags, streamId, block);

  flags |= FLAG.PRIORITY;
  const dep = priority.streamDependency ?? 0;
  const head = new Uint8Array(5);
  head[0] = ((dep >>> 24) & 0x7f) | (priority.exclusive ? 0x80 : 0);
  head[1] = (dep >>> 16) & 0xff;
  head[2] = (dep >>> 8) & 0xff;
  head[3] = dep & 0xff;
  head[4] = priority.weight & 0xff;
  const payload = new Uint8Array(5 + block.length);
  payload.set(head, 0);
  payload.set(block, 5);
  return serializeFrame(FRAME.HEADERS, flags, streamId, payload);
}

/** A CONTINUATION frame (RFC 9113 s6.10), for a header block that overflows one frame. */
export function continuationFrame(streamId, block, endHeaders) {
  return serializeFrame(FRAME.CONTINUATION, endHeaders ? FLAG.END_HEADERS : 0, streamId, block);
}

/** A DATA frame (RFC 9113 s6.1). No padding is ever emitted. */
export function dataFrame(streamId, data, endStream) {
  return serializeFrame(FRAME.DATA, endStream ? FLAG.END_STREAM : 0, streamId, data);
}

// ---------------------------------------------------------------------- payload parsers

/**
 * Strip a DATA/HEADERS PADDED frame's pad length and padding, returning the meaningful slice.
 * The pad length byte and padding both count against flow control (the caller handles that);
 * this only removes them from the bytes handed onward. A pad length >= the remaining payload is
 * a PROTOCOL_ERROR (RFC 9113 s6.1).
 * @param {Uint8Array} payload
 * @returns {{ data: Uint8Array, padLength: number }}
 */
export function stripPadding(payload) {
  if (payload.length === 0) {
    throw new Http2Error(codes.HTTP2_PROTOCOL, 'PADDED frame has no pad length octet');
  }
  const padLength = payload[0];
  if (padLength >= payload.length) {
    throw new Http2Error(
      codes.HTTP2_PROTOCOL,
      `pad length ${padLength} is not smaller than the ${payload.length - 1} bytes that follow it`,
      { padLength, available: payload.length - 1 },
    );
  }
  return { data: payload.subarray(1, payload.length - padLength), padLength };
}

/**
 * The header block fragment inside a HEADERS payload, after removing padding (PADDED) and the
 * priority fields (PRIORITY). Priority is deprecated (RFC 9113 s5.3.2) and its fields are
 * discarded, not acted on.
 * @param {Uint8Array} payload
 * @param {number} flags
 * @returns {Uint8Array}
 */
export function headersBlockFragment(payload, flags) {
  let p = payload;
  if (flags & FLAG.PADDED) p = stripPadding(p).data;
  if (flags & FLAG.PRIORITY) {
    if (p.length < 5) {
      throw new Http2Error(codes.HTTP2_FRAME_SIZE, 'HEADERS PRIORITY block is shorter than 5 bytes');
    }
    p = p.subarray(5); // 4-byte stream dependency + 1-byte weight, both ignored
  }
  return p;
}

/**
 * Parse a SETTINGS payload into [id, value] pairs. Length must be a multiple of 6
 * (RFC 9113 s6.5); anything else is a FRAME_SIZE_ERROR.
 * @param {Uint8Array} payload
 * @returns {Array<[number, number]>}
 */
export function parseSettings(payload) {
  if (payload.length % 6 !== 0) {
    throw new Http2Error(
      codes.HTTP2_FRAME_SIZE,
      `SETTINGS payload of ${payload.length} bytes is not a multiple of 6`,
      { length: payload.length },
    );
  }
  const out = [];
  for (let o = 0; o < payload.length; o += 6) {
    out.push([readU16(payload, o), readU32(payload, o + 2)]);
  }
  return out;
}

/**
 * Parse a WINDOW_UPDATE payload. Must be exactly 4 bytes; a zero increment is a protocol error
 * (RFC 9113 s6.9), surfaced by the caller which knows the stream context.
 * @param {Uint8Array} payload
 * @returns {number} the 31-bit increment
 */
export function parseWindowUpdate(payload) {
  if (payload.length !== 4) {
    throw new Http2Error(
      codes.HTTP2_FRAME_SIZE,
      `WINDOW_UPDATE payload is ${payload.length} bytes, must be 4`,
      { length: payload.length },
    );
  }
  return readU32(payload, 0) & 0x7fffffff;
}

/**
 * Parse a RST_STREAM payload (exactly 4 bytes: an error code).
 * @param {Uint8Array} payload
 * @returns {number}
 */
export function parseRstStream(payload) {
  if (payload.length !== 4) {
    throw new Http2Error(
      codes.HTTP2_FRAME_SIZE,
      `RST_STREAM payload is ${payload.length} bytes, must be 4`,
      { length: payload.length },
    );
  }
  return readU32(payload, 0);
}

/**
 * Parse a GOAWAY payload (RFC 9113 s6.8): last-stream-id, error code, optional debug data.
 * @param {Uint8Array} payload
 * @returns {{ lastStreamId: number, errorCode: number, debug: Uint8Array }}
 */
export function parseGoaway(payload) {
  if (payload.length < 8) {
    throw new Http2Error(
      codes.HTTP2_FRAME_SIZE,
      `GOAWAY payload is ${payload.length} bytes, must be at least 8`,
      { length: payload.length },
    );
  }
  return {
    lastStreamId: readU32(payload, 0) & 0x7fffffff,
    errorCode: readU32(payload, 4),
    debug: payload.subarray(8),
  };
}
