/**
 * Build the ordered HPACK field list for a request, pseudo-headers first in curl's order
 * (:method, :scheme, :authority, :path). :path is emitted "without indexing" and the rest
 * "incremental", matching the captured curl encoding.
 *
 * @param {{ method: string, scheme: string, authority: string, path: string,
 *   headers: Array<[string, string]> }} req
 * @returns {import('./hpack.js').HpackField[]}
 */
export function buildRequestFields({ method, scheme, authority, path, headers }: {
    method: string;
    scheme: string;
    authority: string;
    path: string;
    headers: Array<[string, string]>;
}): import("./hpack.js").HpackField[];
/**
 * @typedef {ReadableStream<Uint8Array> & { completed: Promise<boolean>,
 *   trailers: Promise<Headers | null> }} BodyStream
 */
/**
 * @typedef {object} Http2ResponseHead
 * @property {number} status
 * @property {string} statusText always '' — HTTP/2 has no reason phrase
 * @property {Headers} headers
 * @property {string[]} setCookie one entry per set-cookie field, kept separate like the h1 path
 * @property {'2'} httpVersion
 * @property {BodyStream} body
 */
/**
 * Raised by request() when the connection cannot take the stream but the request PROVABLY was not
 * processed (going away, or refused). It mirrors h1's serverNeverSawIt: only a request the server
 * demonstrably never saw may be re-sent, so client.js can safely open a fresh connection and retry.
 */
export class Http2Retryable extends Http2Error {
}
/**
 * @typedef {object} Http2ConnectionOptions
 * @property {import('../transport.js').ConnectionInfo} [info] provenance attached to responses
 * @property {number} [initialWindowSize] our SETTINGS_INITIAL_WINDOW_SIZE (receive window per
 *   stream). Defaults to curl's 10 MiB; tests lower it to exercise flow control.
 * @property {number} [connectionWindow] the connection receive window we open with a WINDOW_UPDATE
 *   right after SETTINGS. Defaults to curl's 1000 MiB.
 * @property {number} [maxConcurrentStreams] our advertised SETTINGS_MAX_CONCURRENT_STREAMS.
 * @property {number} [maxHeaderTableSize] our advertised SETTINGS_HEADER_TABLE_SIZE.
 * @property {number} [maxHeaderListSize] self-protection cap on a decoded response header list.
 * @property {(err: Error | null) => void} [onClose] called once when the connection dies, so a
 *   registry can drop it.
 */
export class Http2Connection {
    /**
     * @param {import('../tls/connect.js').ByteDuplex | { readable: ReadableStream<Uint8Array>,
     *   writable: WritableStream<Uint8Array> }} duplex plaintext transport (a TLS session's
     *   plaintextDuplex, or a raw socket for cleartext h2 in tests)
     * @param {Http2ConnectionOptions} [opts]
     */
    constructor(duplex: import("../tls/connect.js").ByteDuplex | {
        readable: ReadableStream<Uint8Array>;
        writable: WritableStream<Uint8Array>;
    }, opts?: Http2ConnectionOptions);
    _reader: ByteReader;
    _writer: ByteWriter;
    _closeTransport: () => any;
    info: import("../transport.js").ConnectionInfo | null;
    _ourInitialWindow: number;
    _ourConnWindow: number;
    _ourMaxConcurrent: number;
    _ourHeaderTableSize: number;
    _peerInitialWindow: number;
    _peerMaxFrameSize: number;
    _peerMaxConcurrent: number;
    _peerHeaderTableSize: number;
    _connRecvWindow: number;
    _connConsumed: number;
    _connSendWindow: number;
    /** @type {Array<() => void>} wakers for senders blocked on the connection window */
    _connSendWaiters: Array<() => void>;
    _decoder: HpackDecoder;
    /** @type {Map<number, any>} live streams by id */
    _streams: Map<number, any>;
    _nextStreamId: number;
    _lastPeerStreamId: number;
    _continuation: {
        streamId: any;
        fragments: Uint8Array<ArrayBuffer>[];
        endStream: boolean;
    } | null;
    _expectFirstSettings: boolean;
    _fatal: any;
    _goaway: {
        lastStreamId: number;
        errorCode: number;
    } | null;
    _closed: boolean;
    _onClose: ((err: Error | null) => void) | null;
    _writeChain: Promise<void>;
    /** Whether a new request may be dispatched onto this connection right now. */
    canDispatch(): boolean;
    get activeStreams(): number;
    _sendPreface(): void;
    /** Serialise a wire write behind every previous one, so a header block is never split by another
     *  frame and the preface always leads. Mirrors the record layer's write discipline. */
    _write(bytes: any): Promise<void>;
    /**
     * Open a stream and send a request. Resolves once the response header block (the first non-1xx
     * HEADERS) has arrived; the body streams after.
     *
     * @param {object} req
     * @param {string} req.method
     * @param {string} req.scheme
     * @param {string} req.authority
     * @param {string} req.path
     * @param {Array<[string, string]>} req.headers already lowercased, connection-specific ones removed
     * @param {Uint8Array | null} [req.body] buffered whole by the caller, so send flow control is simple
     * @param {AbortSignal} [req.signal] aborting it RST_STREAMs the stream and rejects its promises;
     *   this is how a per-request deadline tears down exactly one stream without touching the others
     * @returns {Promise<Http2ResponseHead>}
     */
    request({ method, scheme, authority, path, headers, body, signal }: {
        method: string;
        scheme: string;
        authority: string;
        path: string;
        headers: Array<[string, string]>;
        body?: Uint8Array<ArrayBufferLike> | null | undefined;
        signal?: AbortSignal | undefined;
    }): Promise<Http2ResponseHead>;
    _createStream(id: any): {
        id: any;
        head: {
            promise: Promise<any>;
            resolve: undefined;
            reject: undefined;
            settled: boolean;
        };
        responseReceived: boolean;
        /** @type {Uint8Array[]} */
        recvQueue: Uint8Array[];
        recvEnded: boolean;
        /** @type {Error | null} */
        bodyError: Error | null;
        /** @type {(() => void) | null} */
        pullWaiter: (() => void) | null;
        completed: {
            promise: Promise<any>;
            resolve: undefined;
            reject: undefined;
            settled: boolean;
        };
        trailers: {
            promise: Promise<any>;
            resolve: undefined;
            reject: undefined;
            settled: boolean;
        };
        /** @type {Headers | null} */
        trailerFields: Headers | null;
        recvWindow: number;
        recvConsumed: number;
        sendWindow: number;
        /** @type {Array<() => void>} */
        sendWaiters: Array<() => void>;
        localEnded: boolean;
        cancelled: boolean;
        closed: boolean;
        rstSent: boolean;
    };
    /** Send a header block as HEADERS plus CONTINUATION frames if it overflows one frame. The whole
     *  run is one write, so no other frame can interleave it (RFC 9113 s6.10). */
    _sendHeaderBlock(streamId: any, block: any, endStream: any): void;
    /** Send a request body as DATA frames, respecting stream and connection send windows. */
    _sendBody(streamId: any, body: any, stream: any): Promise<void>;
    /** Block until either the stream or the connection send window grows (a WINDOW_UPDATE arrives). */
    _awaitSendWindow(stream: any): Promise<any>;
    _wakeSendWaiters(stream: any): void;
    _makeBodyStream(stream: any): ReadableStream<any> & {
        completed: any;
        trailers: any;
    };
    _wakePull(stream: any): void;
    /** Called as the CONSUMER drains `n` bytes: reopen the stream and connection receive windows,
     *  batched so a byte-at-a-time consumer does not produce a WINDOW_UPDATE storm. */
    _consumeStream(stream: any, n: any): void;
    _replenish(stream: any, n: any): void;
    _replenishConn(n: any): void;
    _readLoop(): Promise<void>;
    _dispatchFrame(frame: any): void;
    _onSettings(flags: any, streamId: any, payload: any): void;
    _onHeaders(flags: any, streamId: any, payload: any): void;
    _onContinuation(flags: any, payload: any): void;
    /** A full header block has been assembled: HPACK-decode it (connection-fatal on failure, since
     *  HPACK state is shared) and route it to the stream as a response head or as trailers. */
    _completeHeaderBlock(streamId: any, block: any, endStream: any): void;
    _deliverResponseHead(stream: any, pairs: any, endStream: any): void;
    _deliverTrailers(stream: any, pairs: any, endStream: any): void;
    _onData(flags: any, streamId: any, payload: any): void;
    _onWindowUpdate(streamId: any, payload: any): void;
    _onRstStream(streamId: any, payload: any): void;
    _onPing(flags: any, streamId: any, payload: any): void;
    _onGoaway(payload: any): void;
    /** Forget a stream: drop it from the table and wake anything blocked on it. */
    _removeStream(stream: any): void;
    /** Reject the caller's promises for a stream. Idempotent via the deferreds' settled flags. */
    _rejectStream(stream: any, err: any): void;
    /** Send RST_STREAM once, telling the peer to stop spending bandwidth on a stream we gave up on. */
    _sendRst(stream: any, errorCode: any): void;
    /** A stream finished cleanly once both halves ended: our request fully sent, END_STREAM received. */
    _maybeCloseStream(stream: any): void;
    /** A failure originating with the PEER (its RST_STREAM, its GOAWAY, a connection death): reject
     *  the caller, never RST back — RFC 9113 s5.4.2 forbids answering a reset with a reset. */
    _failStream(stream: any, err: any): void;
    /** A failure originating with US (malformed response, our timeout, flow-control overrun we caught):
     *  tell the peer with RST_STREAM, then reject the caller. */
    _resetStream(stream: any, errorCode: any, err: any): void;
    _die(err: any): void;
    /**
     * Graceful shutdown: GOAWAY(NO_ERROR), then close the transport. Any live stream is failed.
     *
     * The GOAWAY and the writer close are BEST-EFFORT and are not awaited: a peer that has stopped
     * reading applies backpressure that never clears, and awaiting a courtesy frame into a full
     * buffer would hang close() forever — the exact trap the record layer avoids with its grace
     * window. Only the transport close is awaited, because that is what actually releases the socket.
     */
    close(): Promise<void>;
    _settleResolve(d: any, value: any): void;
    _settleReject(d: any, err: any): void;
}
export type BodyStream = ReadableStream<Uint8Array> & {
    completed: Promise<boolean>;
    trailers: Promise<Headers | null>;
};
export type Http2ResponseHead = {
    status: number;
    /**
     * always '' — HTTP/2 has no reason phrase
     */
    statusText: string;
    headers: Headers;
    /**
     * one entry per set-cookie field, kept separate like the h1 path
     */
    setCookie: string[];
    httpVersion: "2";
    body: BodyStream;
};
export type Http2ConnectionOptions = {
    /**
     * provenance attached to responses
     */
    info?: import("../transport.js").ConnectionInfo | undefined;
    /**
     * our SETTINGS_INITIAL_WINDOW_SIZE (receive window per
     * stream). Defaults to curl's 10 MiB; tests lower it to exercise flow control.
     */
    initialWindowSize?: number | undefined;
    /**
     * the connection receive window we open with a WINDOW_UPDATE
     * right after SETTINGS. Defaults to curl's 1000 MiB.
     */
    connectionWindow?: number | undefined;
    /**
     * our advertised SETTINGS_MAX_CONCURRENT_STREAMS.
     */
    maxConcurrentStreams?: number | undefined;
    /**
     * our advertised SETTINGS_HEADER_TABLE_SIZE.
     */
    maxHeaderTableSize?: number | undefined;
    /**
     * self-protection cap on a decoded response header list.
     */
    maxHeaderListSize?: number | undefined;
    /**
     * called once when the connection dies, so a
     * registry can drop it.
     */
    onClose?: ((err: Error | null) => void) | undefined;
};
import { Http2Error } from '../errors.js';
import { ByteReader } from '../util/bytes.js';
import { ByteWriter } from '../util/bytes.js';
import { HpackDecoder } from './hpack.js';
