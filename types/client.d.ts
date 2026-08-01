/**
 * A standalone fetch bound to a configuration, matching httpx's module-level helpers. Creates and
 * closes a Client per call, so no connection is reused; use `new Client()` when reuse matters.
 *
 * @param {ClientOptions} [options]
 * @returns {FetchLike}
 */
export function createFetch(options?: ClientOptions): FetchLike;
/**
 * Replace `globalThis.fetch`, for libraries that only accept the global. Returns the undo.
 * Never called automatically, and never on import.
 *
 * @param {ClientOptions} [options]
 * @returns {() => void} uninstall; idempotent, and a no-op if someone else has since taken the global
 */
export function install(options?: ClientOptions): () => void;
/**
 * A `fetch`-shaped function. Deliberately the platform's own signature: being assignable to
 * `typeof fetch` is what lets an SDK accept this in place of the global without adapting.
 * @typedef {(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>} FetchLike
 */
/**
 * What a Response carries about the connection that produced it, under the non-standard
 * `tunnelfetch` property.
 * @typedef {object} ResponseDetail
 * @property {string} url
 * @property {boolean} proxied
 * @property {string | null} proxy the proxy actually used, credentials omitted
 * @property {import('./tls/connect.js').TlsSessionInfo | null} tls null for cleartext
 * @property {'1.0' | '1.1' | '2'} httpVersion '2' when ALPN negotiated HTTP/2
 * @property {'none' | 'content-length' | 'chunked' | 'until-close' | 'h2'} framing 'h2' when the
 *   body was delimited by an HTTP/2 END_STREAM rather than by any HTTP/1.1 framing rule
 */
/**
 * Limits on what a peer may make us buffer. Each is a fail-closed cap, not a hint.
 * @typedef {object} Limits
 * @property {number} [maxHeaderBytes] response head, default 65536
 * @property {number} [maxProxyReplyBytes] proxy CONNECT reply head, default 32768
 */
/**
 * @typedef {object} ClientOptions
 * @property {import('./proxy/index.js').ConnectFn} [connect] Socket factory. Required for any
 *   request the platform's own `fetch` cannot serve — which is every proxied request, and every
 *   request asking for a trust policy `fetch` cannot express.
 * @property {string | import('./proxy/index.js').ProxyConfig | null} [proxy] URL string or
 *   config object; `http:`, `https:`, `socks5:` and `socks5h:`.
 * @property {import('./trust/index.js').TrustConfig} [trust] certificate policy, httpx's
 *   `verify=`. Default `{ mode: 'system' }`.
 * @property {import('./tls/connect.js').TlsOptions} [tls] handshake knobs.
 * @property {import('./util/deadline.js').DeadlineOptions} [timeouts] connect / handshake /
 *   headers / idle / total, in ms. The idle gap is the control; total is a backstop.
 * @property {boolean} [cookies] enable a per-Client cookie jar.
 * @property {import('./client/cookies.js').CookieJar} [jar] supply a jar directly, e.g. to share
 *   one across Clients or to persist it.
 * @property {number} [maxRedirects] default 20.
 * @property {number} [maxBodyBytes] enforced from Content-Length before a byte is read.
 * @property {boolean} [decompress] gzip/deflate. Default true.
 * @property {Record<string, import('./client/decode.js').BodyDecoder>} [decoders] extra
 *   content-codings this client can read, e.g. `{ br: (s) => ... }`. Registering one is what
 *   makes advertising it honest, so each name is appended to Accept-Encoding — a client that
 *   asked for a coding it cannot decode would turn every such response into garbage. `br` and
 *   `zstd` are not built in because the runtime's DecompressionStream has neither and this
 *   package takes no dependencies; supply your own and the cost, and the supply chain, are
 *   yours and visible. Measured on the edge: WASM brotli decodes at about 2x native gzip, and
 *   the wire bytes it saves do not pay that back — see the README. The reason to turn it on is
 *   matching a browser's Accept-Encoding, not saving CPU.
 * @property {boolean} [keepAlive] default true.
 * @property {boolean} [http2] offer HTTP/2 via ALPN and speak it when the server selects it.
 *   Default true. The goal is ACCESS, not speed — some sites treat HTTP/1.1 as a bot signal — and
 *   on a CPU-billed runtime h2 costs MORE than h1 (HPACK is extra work). Set false to offer only
 *   `http/1.1`. There is no fallback-and-retry either way: the server's ALPN pick is followed.
 * @property {boolean} [forceTunnel] never delegate to the platform's fetch, even when it could
 *   serve the request. Mainly for exercising this stack against origins that do not need it.
 * @property {FetchLike} [nativeFetch] delegation target; defaults to `globalThis.fetch`.
 * @property {{ maxPerKey?: number, maxTotal?: number }} [pool] connection pool sizing.
 * @property {Limits} [limits]
 * @property {import('./tls/connect.js').TlsDeps} [deps] injectable randomness and key generation.
 * @property {AbortSignal} [signal] aborts every request this Client makes.
 * @property {number} [now] epoch ms override, for certificate validity in tests.
 */
export class Client {
    /**
     * @param {ClientOptions} [options]
     */
    constructor(options?: ClientOptions);
    options: Readonly<ClientOptions>;
    pool: ConnectionPool;
    /** @type {Map<string, import('./http2/connection.js').Http2Connection>} */
    _h2: Map<string, import("./http2/connection.js").Http2Connection>;
    /** @type {Set<import('./http2/connection.js').Http2Connection>} */
    _h2conns: Set<import("./http2/connection.js").Http2Connection>;
    jar: CookieJar | null;
    tickets: TicketStore;
    _closed: boolean;
    /** @type {Set<Promise<void>>} */
    _inflight: Set<Promise<void>>;
    /**
     * @param {RequestInfo | URL} input
     * @param {RequestInit} [init]
     * @returns {Promise<Response & { tunnelfetch?: ResponseDetail }>}
     */
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response & {
        tunnelfetch?: ResponseDetail;
    }>;
    /**
     * Resolve once every response body handed out by this Client has finished, one way or another —
     * read to the end, cancelled, or failed. Deliberately NOT folded into close(): close() is the
     * forceful teardown, and a teardown that waits on the streams it is tearing down would hang on
     * any body the caller abandoned. This is for callers that want the graceful order.
     *
     * Looping rather than a single Promise.all because a body settling can start another (a redirect
     * drains its predecessor), and a set sampled once would miss the successor.
     */
    idle(): Promise<void>;
    /** Release every pooled socket and shared HTTP/2 connection. A Client that is finished must be
     *  closed or sockets leak for the isolate's lifetime. */
    close(): Promise<void>;
}
/**
 * A `fetch`-shaped function. Deliberately the platform's own signature: being assignable to
 * `typeof fetch` is what lets an SDK accept this in place of the global without adapting.
 */
export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
/**
 * What a Response carries about the connection that produced it, under the non-standard
 * `tunnelfetch` property.
 */
export type ResponseDetail = {
    url: string;
    proxied: boolean;
    /**
     * the proxy actually used, credentials omitted
     */
    proxy: string | null;
    /**
     * null for cleartext
     */
    tls: import("./tls/connect.js").TlsSessionInfo | null;
    /**
     * '2' when ALPN negotiated HTTP/2
     */
    httpVersion: "1.0" | "1.1" | "2";
    /**
     * 'h2' when the
     * body was delimited by an HTTP/2 END_STREAM rather than by any HTTP/1.1 framing rule
     */
    framing: "none" | "content-length" | "chunked" | "until-close" | "h2";
};
/**
 * Limits on what a peer may make us buffer. Each is a fail-closed cap, not a hint.
 */
export type Limits = {
    /**
     * response head, default 65536
     */
    maxHeaderBytes?: number | undefined;
    /**
     * proxy CONNECT reply head, default 32768
     */
    maxProxyReplyBytes?: number | undefined;
};
export type ClientOptions = {
    /**
     * Socket factory. Required for any
     * request the platform's own `fetch` cannot serve — which is every proxied request, and every
     * request asking for a trust policy `fetch` cannot express.
     */
    connect?: import("./proxy/index.js").ConnectFn | undefined;
    /**
     * URL string or
     * config object; `http:`, `https:`, `socks5:` and `socks5h:`.
     */
    proxy?: string | import("./proxy/index.js").ProxyConfig | null | undefined;
    /**
     * certificate policy, httpx's
     * `verify=`. Default `{ mode: 'system' }`.
     */
    trust?: import("./trust/index.js").TrustConfig | undefined;
    /**
     * handshake knobs.
     */
    tls?: import("./tls/connect.js").TlsOptions | undefined;
    /**
     * connect / handshake /
     * headers / idle / total, in ms. The idle gap is the control; total is a backstop.
     */
    timeouts?: import("./util/deadline.js").DeadlineOptions | undefined;
    /**
     * enable a per-Client cookie jar.
     */
    cookies?: boolean | undefined;
    /**
     * supply a jar directly, e.g. to share
     * one across Clients or to persist it.
     */
    jar?: CookieJar | undefined;
    /**
     * default 20.
     */
    maxRedirects?: number | undefined;
    /**
     * enforced from Content-Length before a byte is read.
     */
    maxBodyBytes?: number | undefined;
    /**
     * gzip/deflate. Default true.
     */
    decompress?: boolean | undefined;
    /**
     * extra
     * content-codings this client can read, e.g. `{ br: (s) => ... }`. Registering one is what
     * makes advertising it honest, so each name is appended to Accept-Encoding — a client that
     * asked for a coding it cannot decode would turn every such response into garbage. `br` and
     * `zstd` are not built in because the runtime's DecompressionStream has neither and this
     * package takes no dependencies; supply your own and the cost, and the supply chain, are
     * yours and visible. Measured on the edge: WASM brotli decodes at about 2x native gzip, and
     * the wire bytes it saves do not pay that back — see the README. The reason to turn it on is
     * matching a browser's Accept-Encoding, not saving CPU.
     */
    decoders?: Record<string, import("./client/decode.js").BodyDecoder> | undefined;
    /**
     * default true.
     */
    keepAlive?: boolean | undefined;
    /**
     * offer HTTP/2 via ALPN and speak it when the server selects it.
     * Default true. The goal is ACCESS, not speed — some sites treat HTTP/1.1 as a bot signal — and
     * on a CPU-billed runtime h2 costs MORE than h1 (HPACK is extra work). Set false to offer only
     * `http/1.1`. There is no fallback-and-retry either way: the server's ALPN pick is followed.
     */
    http2?: boolean | undefined;
    /**
     * never delegate to the platform's fetch, even when it could
     * serve the request. Mainly for exercising this stack against origins that do not need it.
     */
    forceTunnel?: boolean | undefined;
    /**
     * delegation target; defaults to `globalThis.fetch`.
     */
    nativeFetch?: FetchLike | undefined;
    /**
     * connection pool sizing.
     */
    pool?: {
        maxPerKey?: number;
        maxTotal?: number;
    } | undefined;
    limits?: Limits | undefined;
    /**
     * injectable randomness and key generation.
     */
    deps?: import("./tls/connect.js").TlsDeps | undefined;
    /**
     * aborts every request this Client makes.
     */
    signal?: AbortSignal | undefined;
    /**
     * epoch ms override, for certificate validity in tests.
     */
    now?: number | undefined;
};
import { ConnectionPool } from './pool.js';
import { CookieJar } from './client/cookies.js';
import { TicketStore } from './tls/tickets.js';
import { utf8 } from './util/bytes.js';
export { CookieJar, ConnectionPool, utf8 };
