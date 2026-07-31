/**
 * Every cap is fail-closed: the peer controls chunk sizes and counts, so each one bounds what
 * a hostile sender can make us buffer.
 * @typedef {object} ChunkedOptions
 * @property {number} [maxBytes] total payload cap, default unlimited
 * @property {number} [maxChunkSize] per-chunk cap, default 64 MiB
 * @property {number} [maxTrailerBytes] trailer-section cap, default 8192
 */
/**
 * Decode a chunked body from `reader`.
 *
 * Returns `{ stream, trailers }`:
 * - `stream`: ReadableStream<Uint8Array> of the decoded payload octets.
 * - `trailers`: Promise<Headers|null>. Resolves with the trailer fields once the terminal
 *   chunk and its trailing CRLF have been fully consumed — i.e. the reader is positioned
 *   exactly after the body, which is the signal a connection pool needs before reuse.
 *   Resolves null if the stream is cancelled before that point (position unknown, do not
 *   reuse). Rejects with the same error the stream errors with on a protocol violation.
 *
 * Reads only what the chunked grammar covers; any bytes after the terminal CRLF stay in
 * `reader` for the next message.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {ChunkedOptions} [opts]
 * @returns {{ stream: ReadableStream<Uint8Array>, trailers: Promise<Headers | null> }}
 */
export function decodeChunked(reader: import("../util/bytes.js").ByteReader, { maxBytes, maxChunkSize, maxTrailerBytes }?: ChunkedOptions): {
    stream: ReadableStream<Uint8Array>;
    trailers: Promise<Headers | null>;
};
/**
 * Every cap is fail-closed: the peer controls chunk sizes and counts, so each one bounds what
 * a hostile sender can make us buffer.
 */
export type ChunkedOptions = {
    /**
     * total payload cap, default unlimited
     */
    maxBytes?: number | undefined;
    /**
     * per-chunk cap, default 64 MiB
     */
    maxChunkSize?: number | undefined;
    /**
     * trailer-section cap, default 8192
     */
    maxTrailerBytes?: number | undefined;
};
