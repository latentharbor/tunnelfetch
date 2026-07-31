/**
 * One skipped 1xx head. Kept because Early Hints (103) carry Link headers a caller may want;
 * everything else about a 1xx is noise by definition.
 * @typedef {object} InformationalHead
 * @property {'1.0' | '1.1'} httpVersion
 * @property {number} status
 * @property {string} statusText
 * @property {Headers} headers
 */
/**
 * The parsed response head. `setCookie` repeats the raw Set-Cookie values because the Headers
 * class folds duplicates with ", ", which destroys cookie dates — no jar can be built from the
 * folded form.
 * @typedef {object} ResponseHead
 * @property {'1.0' | '1.1'} httpVersion only versions the status-line grammar admits
 * @property {number} status
 * @property {string} statusText may be empty; `HTTP/1.1 200` is a legal status line
 * @property {Headers} headers
 * @property {string[]} setCookie one entry per Set-Cookie header, unfolded
 * @property {InformationalHead[]} informational 1xx heads skipped before the real response
 */
/**
 * @typedef {object} ReadHeadOptions
 * @property {number} [maxHeaderBytes] budget for the ENTIRE head phase, default 65536
 */
/**
 * Read the response head: status line and header fields, plus any preceding informational
 * (1xx) responses, which are legal noise before the real response (100 Continue, 103 Early
 * Hints). They are skipped — 1xx never has a body — and returned in `informational` so a
 * caller can surface Early Hints. 101 is fatal: this client never offers an upgrade, so a
 * peer switching protocols means the bytes that follow are not HTTP and cannot be framed.
 * Malformed heads throw HttpError; an oversized head throws LimitError.
 *
 * `maxHeaderBytes` bounds the ENTIRE head phase, informational heads included; a per-head
 * budget would let a peer stream 1xx responses forever.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {ReadHeadOptions} [opts]
 * @returns {Promise<ResponseHead>}
 */
export function readResponseHead(reader: import("../util/bytes.js").ByteReader, { maxHeaderBytes }?: ReadHeadOptions): Promise<ResponseHead>;
/**
 * How a response body is delimited. The four kinds are exhaustive: RFC 9112 §6.3 admits no
 * fifth, and everything ambiguous throws before a kind is chosen.
 * @typedef {'none' | 'content-length' | 'chunked' | 'until-close'} FramingKind
 */
/**
 * The framing decision. `length` is present exactly when `kind` is 'content-length'.
 * @typedef {object} Framing
 * @property {FramingKind} kind
 * @property {number} [length] declared byte count, content-length framing only
 * @property {boolean} keepAliveEligible whether the socket MAY be reused after the body ends
 *   as framed; see bodyFraming for why this is the load-bearing bit
 */
/**
 * Decide how the response body is delimited, per RFC 9112 §6.3, in its order. Ambiguous
 * framing (TE and CL together, disagreeing duplicate CLs, an undecodable transfer coding)
 * throws HttpError with HTTP_FRAMING_AMBIGUOUS — every one of those is a smuggling vector.
 *
 * `keepAliveEligible` is the load-bearing bit: it is true only when the body has a determinate
 * end (`none`, `content-length`, `chunked`). A connection pool must never reuse a socket after
 * an `until-close` body — with no marked end, "the body" is just "whatever arrived", and the
 * next request on that socket would read the previous response's tail as its own head. That is
 * the response-to-the-wrong-request bug, and this flag is the only thing standing between the
 * pool and it. (A 2xx CONNECT reply is also ineligible: the socket is a tunnel now, not HTTP.)
 *
 * @param {{ status: number, method?: string, headers: Headers }} res the head fields framing
 *   depends on; a full ResponseHead satisfies it
 * @returns {Framing}
 */
export function bodyFraming({ status, method, headers }: {
    status: number;
    method?: string;
    headers: Headers;
}): Framing;
/**
 * A response body stream plus the completion contract a connection pool needs. The two extra
 * properties are documented on readResponseBody, which is the only producer.
 * @typedef {ReadableStream<Uint8Array> & { completed: Promise<boolean>,
 *           trailers: Promise<Headers | null> }} BodyStream
 */
/**
 * @typedef {object} ReadBodyOptions
 * @property {number} [maxBytes] fail-closed cap on total payload bytes, default unlimited
 */
/**
 * Stream the response body according to `framing`.
 *
 * The returned ReadableStream<Uint8Array> carries two extra properties — the completion
 * contract a connection pool needs:
 *
 * - `completed`: Promise<boolean>. Resolves `true` only when the body ended exactly as framed
 *   (the reader is positioned at the first byte after the body). Resolves `false` if the
 *   consumer cancelled early (position unknown). Rejects with the stream's error on a protocol
 *   violation (truncation, over-limit). The pool must await `completed === true` AND require
 *   `framing.keepAliveEligible` before reusing the socket; anything else and the next request
 *   reads this response's tail. Note it settles as the body is CONSUMED — an unread stream
 *   settles nothing (except for bodies that are complete at creation: `none` and length 0).
 * - `trailers`: Promise<Headers|null>. Chunked trailers, or null for other framings / cancel.
 *
 * Bytes are streamed through, never buffered whole; `maxBytes` bounds the total.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {Framing} framing
 * @param {ReadBodyOptions} [opts]
 * @returns {BodyStream}
 */
export function readResponseBody(reader: import("../util/bytes.js").ByteReader, framing: Framing, { maxBytes }?: ReadBodyOptions): BodyStream;
/**
 * One skipped 1xx head. Kept because Early Hints (103) carry Link headers a caller may want;
 * everything else about a 1xx is noise by definition.
 */
export type InformationalHead = {
    httpVersion: "1.0" | "1.1";
    status: number;
    statusText: string;
    headers: Headers;
};
/**
 * The parsed response head. `setCookie` repeats the raw Set-Cookie values because the Headers
 * class folds duplicates with ", ", which destroys cookie dates — no jar can be built from the
 * folded form.
 */
export type ResponseHead = {
    /**
     * only versions the status-line grammar admits
     */
    httpVersion: "1.0" | "1.1";
    status: number;
    /**
     * may be empty; `HTTP/1.1 200` is a legal status line
     */
    statusText: string;
    headers: Headers;
    /**
     * one entry per Set-Cookie header, unfolded
     */
    setCookie: string[];
    /**
     * 1xx heads skipped before the real response
     */
    informational: InformationalHead[];
};
export type ReadHeadOptions = {
    /**
     * budget for the ENTIRE head phase, default 65536
     */
    maxHeaderBytes?: number | undefined;
};
/**
 * How a response body is delimited. The four kinds are exhaustive: RFC 9112 §6.3 admits no
 * fifth, and everything ambiguous throws before a kind is chosen.
 */
export type FramingKind = "none" | "content-length" | "chunked" | "until-close";
/**
 * The framing decision. `length` is present exactly when `kind` is 'content-length'.
 */
export type Framing = {
    kind: FramingKind;
    /**
     * declared byte count, content-length framing only
     */
    length?: number | undefined;
    /**
     * whether the socket MAY be reused after the body ends
     * as framed; see bodyFraming for why this is the load-bearing bit
     */
    keepAliveEligible: boolean;
};
/**
 * A response body stream plus the completion contract a connection pool needs. The two extra
 * properties are documented on readResponseBody, which is the only producer.
 */
export type BodyStream = ReadableStream<Uint8Array> & {
    completed: Promise<boolean>;
    trailers: Promise<Headers | null>;
};
export type ReadBodyOptions = {
    /**
     * fail-closed cap on total payload bytes, default unlimited
     */
    maxBytes?: number | undefined;
};
