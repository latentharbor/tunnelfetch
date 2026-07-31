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
 * @property {'1.0' | '1.1'} httpVersion
 * @property {'none' | 'content-length' | 'chunked' | 'until-close'} framing
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
 * @property {boolean} [decompress] gzip/deflate. Default true. Never `br`; the runtime cannot
 *   decompress it, so it is never advertised either.
 * @property {boolean} [keepAlive] default true.
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
    options: {
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
         * gzip/deflate. Default true. Never `br`; the runtime cannot
         * decompress it, so it is never advertised either.
         */
        decompress?: boolean | undefined;
        /**
         * default true.
         */
        keepAlive?: boolean | undefined;
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
    pool: ConnectionPool;
    jar: CookieJar | null;
    _closed: boolean;
    /**
     * @param {RequestInfo | URL} input
     * @param {RequestInit} [init]
     * @returns {Promise<Response & { tunnelfetch?: ResponseDetail }>}
     */
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response & {
        tunnelfetch?: ResponseDetail;
    }>;
    /** Release every pooled socket. A Client that is finished must be closed or sockets leak. */
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
    httpVersion: "1.0" | "1.1";
    framing: "none" | "content-length" | "chunked" | "until-close";
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
     * gzip/deflate. Default true. Never `br`; the runtime cannot
     * decompress it, so it is never advertised either.
     */
    decompress?: boolean | undefined;
    /**
     * default true.
     */
    keepAlive?: boolean | undefined;
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
import { CookieJar } from './client/cookies.js';
import { ConnectionPool } from './pool.js';
import { utf8 } from './util/bytes.js';
export { CookieJar, ConnectionPool, utf8 };
