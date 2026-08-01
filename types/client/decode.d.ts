/**
 * The Accept-Encoding to send given the caller's extra decoders.
 *
 * Registering a decoder is what makes advertising its coding honest — the two must move together
 * or the client asks for bytes it cannot read. Order is registration order after the built-ins,
 * so a caller matching a browser can produce exactly `gzip, deflate, br, zstd`.
 *
 * @param {Record<string, BodyDecoder> | null | undefined} decoders
 * @returns {string}
 */
export function acceptEncodingFor(decoders: Record<string, BodyDecoder> | null | undefined): string;
/**
 * Undo the response's Content-Encoding.
 *
/**
 * A caller-supplied content decoder: raw coded bytes in, decoded bytes out. Streaming, so a body
 * is never fully buffered on this client's behalf.
 * @typedef {(stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>} BodyDecoder
 */
/**
 * @param {ReadableStream<Uint8Array>} stream the raw body
 * @param {string|null|undefined} contentEncoding the Content-Encoding header value; a
 *   comma-separated list names codings in the order the SERVER applied them, so decoding
 *   applies them in reverse.
 * @param {Record<string, BodyDecoder> | null} [decoders] caller-supplied codings
 * @returns {ReadableStream<Uint8Array>} decoded bytes
 */
export function decodeBody(stream: ReadableStream<Uint8Array>, contentEncoding: string | null | undefined, decoders?: Record<string, BodyDecoder> | null): ReadableStream<Uint8Array>;
/**
 * Extract the charset parameter from a Content-Type value, handling quoting and other
 * parameters: `text/html; boundary=x; charset="ISO-8859-4"` -> 'iso-8859-4'.
 * @param {string | null | undefined} contentType
 * @returns {string|null} lowercased charset label, or null when none is declared
 */
export function charsetFromContentType(contentType: string | null | undefined): string | null;
/**
 * Decide the charset for a response body.
 *
 * Precedence: BOM > Content-Type charset parameter > (text/html only) meta prescan > utf-8.
 * The BOM outranks even an explicit header because it describes the actual bytes, and servers
 * that recode content routinely forget to update the header; this is WHATWG "decode" order.
 * The utf-8 default matches Response.text() in fetch — for a client whose callers are code,
 * matching fetch is worth more than matching the legacy HTML default of windows-1252.
 *
 * @param {string|null|undefined} contentType
 * @param {Uint8Array} [bodyPrefix] the first bytes of the body (>= 1024 to satisfy the prescan)
 * @returns {string} a charset label for decodeText
 */
export function charsetFor(contentType: string | null | undefined, bodyPrefix?: Uint8Array): string;
/**
 * Decode bytes with a charset label.
 *
 * TextDecoder implements the WHATWG encoding registry, which is the alias table every browser
 * uses. Note one alias that looks like a bug and is not: `iso-8859-1` (and `latin1`, `ascii`)
 * maps to windows-1252, per WHATWG — the bytes 0x80-0x9F decode to the punctuation everyone
 * actually means, not C1 controls. A BOM matching the charset is stripped (TextDecoder default),
 * which is also what Response.text() does.
 *
 * Throws HttpError (HTTP_CHARSET) for a label outside the WHATWG encoding registry.
 *
 * @param {Uint8Array} bytes
 * @param {string} [charset]
 * @returns {string}
 */
export function decodeText(bytes: Uint8Array, charset?: string): string;
/**
 * What the request layer advertises with no extra decoders registered. The target runtime's
 * DecompressionStream supports ONLY gzip / deflate / deflate-raw (verified empirically);
 * advertising `br` or `zstd` would invite bytes we can never decode, turning every response
 * from a brotli-preferring CDN into garbage. Keep this list and decodeBody in lockstep.
 *
 * It is also exactly what curl sends, which matters because this client presents curl's TLS and
 * HTTP/2 fingerprints by default: a browser-shaped handshake paired with a curl-shaped
 * Accept-Encoding is a mismatch a bot detector can read straight off the wire.
 */
export const ACCEPT_ENCODING: "gzip, deflate";
/**
 * Undo the response's Content-Encoding.
 *
 * /**
 * A caller-supplied content decoder: raw coded bytes in, decoded bytes out. Streaming, so a body
 * is never fully buffered on this client's behalf.
 */
export type BodyDecoder = (stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>;
