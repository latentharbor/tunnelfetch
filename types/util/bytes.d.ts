/**
 * @param {Uint8Array[]} parts
 * @param {number} [total] byte total, when the caller already counted; computed otherwise
 * @returns {Uint8Array}
 */
export function concat(parts: Uint8Array[], total?: number): Uint8Array;
/**
 * Boyer-Moore is not worth it for 1-4 byte needles over small buffers.
 * @param {Uint8Array} haystack
 * @param {Uint8Array} needle
 * @param {number} [from]
 * @returns {number} index of the first occurrence at or after `from`, or -1
 */
export function indexOf(haystack: Uint8Array, needle: Uint8Array, from?: number): number;
/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function equal(a: Uint8Array, b: Uint8Array): boolean;
/**
 * Comparison whose running time does not depend on where the first difference is.
 * JS cannot truly guarantee constant time (JIT tiering, GC), which is precisely why this package
 * refuses MAC-then-encrypt cipher suites. It is used only where a timing leak would be a
 * nice-to-have for an attacker rather than a decryption oracle: certificate pins and Finished
 * verification, where the compared value is already authenticated or public.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHex(bytes: Uint8Array): string;
/**
 * @param {string} hex whitespace and ':' separators tolerated
 * @returns {Uint8Array}
 */
export function fromHex(hex: string): Uint8Array;
/**
 * Latin-1 decode: HTTP header field values are opaque octets, not UTF-8.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function latin1(bytes: Uint8Array): string;
/**
 * Big-endian integer writers, the byte order of every protocol in this package.
 * @param {number} n
 * @returns {Uint8Array}
 */
export function u8(n: number): Uint8Array;
/** @param {number} n @returns {Uint8Array} */
export function u16(n: number): Uint8Array;
/** @param {number} n @returns {Uint8Array} */
export function u24(n: number): Uint8Array;
/** @param {number} n @returns {Uint8Array} */
export function u32(n: number): Uint8Array;
/** Raised when the peer stops sending in the middle of a structure we must read whole. */
export class UnexpectedEofError extends TunnelFetchError {
    /**
     * @param {number} wanted bytes the structure needed (-1 when scanning for a delimiter)
     * @param {number} got bytes actually buffered when the stream ended
     * @param {string} what the structure being read, named in the message
     */
    constructor(wanted: number, got: number, what: string);
}
/**
 * Buffered reader over a ReadableStream<Uint8Array>.
 *
 * Returned slices may alias the stream's own chunks (or, on the BYOB path, buffers this class
 * allocated and will never touch again); they are never written to by this class and must not
 * be retained beyond the caller's immediate use if memory matters.
 *
 * When the source is a byte stream — on the target runtime, a socket's readable is one — the
 * reader pulls with BYOB reads into large fresh views instead of taking the source's own
 * chunking. This is measured, not stylistic: the runtime delivers socket data in chunks of at
 * most 4096 bytes, ~1200 of them for a 4 MB body, and every chunk is a runtime/JS boundary
 * crossing; a BYOB read hands over everything the transport has buffered (up to the view size)
 * in one crossing, and resolves with a partial fill the instant anything at all is available,
 * so delivery latency is unchanged. Sources that are not byte streams (every in-process
 * ReadableStream in this package and its tests) take the default-reader path unchanged.
 */
export class ByteReader {
    /**
     * @param {ReadableStream<Uint8Array>} readable
     * @param {number} [pullBytes] size of each BYOB view pulled from the source. Tunable because it
     *   decides how many times a body crosses the runtime boundary on the way in, and that turned out
     *   to be the largest single cost in a large response — 42 ms of a 106 ms 4 MB request is socket
     *   reads and record decryption, of which the AEAD itself is under 2 ms.
     */
    constructor(readable: ReadableStream<Uint8Array>, pullBytes?: number);
    _pullBytes: number;
    /** @type {ReadableStreamBYOBReader | null} */
    _byob: ReadableStreamBYOBReader | null;
    _reader: ReadableStreamBYOBReader | ReadableStreamDefaultReader<Uint8Array<ArrayBufferLike>> | null;
    /** @type {Uint8Array[]} */
    _chunks: Uint8Array[];
    _head: number;
    _len: number;
    _eof: boolean;
    _done: boolean;
    get buffered(): number;
    get atEof(): boolean;
    /**
     * Push bytes back to the front. Used when a layer over-reads (e.g. proxy replies with data).
     * @param {Uint8Array} bytes
     */
    unshift(bytes: Uint8Array): void;
    /**
     * Pull one more chunk from the source. Returns false at EOF.
     * The BYOB view is freshly allocated per read and never reused: _take hands out subarrays of
     * buffered chunks, so recycling a view would rewrite bytes a parser already holds.
     * @returns {Promise<boolean>} annotated because the tail-recursive skip of empty chunks
     *   defeats return-type inference
     */
    _pull(): Promise<boolean>;
    /**
     * Take exactly n bytes from the buffer. Caller guarantees _len >= n.
     * @param {number} n
     * @returns {Uint8Array}
     */
    _take(n: number): Uint8Array;
    /**
     * Read exactly n bytes, or throw. This is the workhorse for length-prefixed formats
     * (TLS records, chunked bodies, SOCKS5 replies).
     * @param {number} n
     * @param {string} [what] described in the error if the stream ends early
     * @returns {Promise<Uint8Array>}
     */
    readExactly(n: number, what?: string): Promise<Uint8Array>;
    /**
     * Read at least 1 and at most n bytes. Returns null at clean EOF.
     * @param {number} [n]
     * @returns {Promise<Uint8Array | null>}
     */
    readSome(n?: number): Promise<Uint8Array | null>;
    /**
     * Read until `needle` is found, returning everything up to and including it.
     * Used for CRLF-delimited HTTP structures. Fails closed past `maxBytes` so a peer cannot
     * make us buffer without bound.
     * @param {Uint8Array} needle
     * @param {number} maxBytes
     * @param {string} [what]
     * @returns {Promise<Uint8Array>}
     */
    readUntil(needle: Uint8Array, maxBytes: number, what?: string): Promise<Uint8Array>;
    /**
     * Drain everything remaining, up to maxBytes.
     * @param {number} [maxBytes]
     * @returns {Promise<Uint8Array>}
     */
    readToEnd(maxBytes?: number): Promise<Uint8Array>;
    releaseLock(): void;
    /** @param {unknown} [reason] */
    cancel(reason?: unknown): Promise<void>;
}
/** Buffered writer over a WritableStream<Uint8Array>. */
export class ByteWriter {
    /** @param {WritableStream<Uint8Array>} writable */
    constructor(writable: WritableStream<Uint8Array>);
    _writer: WritableStreamDefaultWriter<Uint8Array<ArrayBufferLike>>;
    _done: boolean;
    /**
     * @param {Uint8Array} bytes
     * @returns {Promise<void>}
     */
    write(bytes: Uint8Array): Promise<void>;
    /**
     * Write several buffers as one, avoiding per-piece stream overhead.
     * @param {Uint8Array[]} parts
     * @returns {Promise<void>}
     */
    writeAll(parts: Uint8Array[]): Promise<void>;
    releaseLock(): void;
    close(): Promise<void>;
    /** @param {unknown} [reason] */
    abort(reason?: unknown): Promise<void>;
}
/** @type {(s: string) => Uint8Array} */
export const utf8: (s: string) => Uint8Array;
/** Big-endian integer readers over a byte view at offset `o`. */
/** @type {(b: Uint8Array, o?: number) => number} */
export const readU16: (b: Uint8Array, o?: number) => number;
/** @type {(b: Uint8Array, o?: number) => number} */
export const readU24: (b: Uint8Array, o?: number) => number;
/** @type {(b: Uint8Array, o?: number) => number} */
export const readU32: (b: Uint8Array, o?: number) => number;
import { TunnelFetchError } from '../errors.js';
