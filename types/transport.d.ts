/**
 * A request URL reduced to what the transport dials.
 * @typedef {object} TransportTarget
 * @property {URL} url
 * @property {string} hostname IPv6 unbracketed, as the socket API and SOCKS5 want it
 * @property {number} port explicit port, or the scheme default
 * @property {boolean} secure whether the scheme is https:
 */
/**
 * Split a request URL into what the transport needs. Throws ConfigError on any scheme other
 * than http: and https:.
 * @param {string | URL} input
 * @returns {TransportTarget}
 */
export function targetFromUrl(input: string | URL): TransportTarget;
/**
 * What a Response's `tunnelfetch` detail reports about the connection, before the HTTP layer
 * adds the per-response httpVersion and framing.
 * @typedef {object} ConnectionInfo
 * @property {string} url
 * @property {boolean} proxied
 * @property {string | null} proxy the proxy actually used, credentials omitted
 * @property {import('./tls/connect.js').TlsSessionInfo | null} tls null for cleartext
 */
/**
 * A live connection carrying application bytes: the duplex, its provenance, and the deadline
 * controller that governs it. This is what the pool stores and what sendAndReceive consumes.
 * @typedef {object} Connection
 * @property {ReadableStream<Uint8Array>} readable
 * @property {WritableStream<Uint8Array>} writable
 * @property {() => Promise<void> | void} close
 * @property {ConnectionInfo} info
 * @property {import('./trust/index.js').ParsedCertificate | null} [peerCertificate] TLS only;
 *   null when trust mode 'none' accepted a leaf it could not parse
 * @property {DeadlineController} deadlines
 * @property {boolean} ownsDeadlines whether this call created the controller (and must dispose
 *   it) rather than borrowing the caller's
 */
/**
 * @typedef {object} OpenConnectionOptions
 * @property {string | URL} url
 * @property {import('./proxy/index.js').ConnectFn} connect injected socket factory
 * @property {string | import('./proxy/index.js').ProxyConfig | null} [proxy]
 * @property {import('./trust/index.js').TrustConfig} [trust] the `verify=`-style knob, passed
 *   through to the trust layer
 * @property {DeadlineController} [deadlines] borrow the request's controller; omitting it makes
 *   this call own (and dispose) a fresh one
 * @property {import('./tls/connect.js').TlsOptions} [tls] handshake options
 * @property {import('./tls/connect.js').TlsDeps} [deps] injectable randomness/keygen for
 *   reproducible handshakes
 * @property {AbortSignal} [signal]
 * @property {{ maxProxyReplyBytes?: number }} [limits] cap on the proxy CONNECT reply head
 * @property {number} [now] epoch ms override for certificate validity
 */
/**
 * Open a connection carrying application bytes for `url`. Throws (ProxyError, TlsError,
 * CertificateError, TimeoutError, ConfigError) rather than resolving with a failure value.
 *
 * @param {OpenConnectionOptions} args
 * @returns {Promise<Connection>}
 */
export function openConnection({ url, connect, proxy, trust, deadlines, tls, deps, signal, limits, now, }: OpenConnectionOptions): Promise<Connection>;
/**
 * The delegation decision, with the disqualifying reason spelled out so a caller's error can
 * quote it. Discriminated on `ok` so `reason` is a string exactly when there is one.
 * @typedef {{ ok: true, reason: null } | { ok: false, reason: string }} NativeFetchVerdict
 */
/**
 * @typedef {object} NativeFetchQuery
 * @property {import('./proxy/index.js').ProxyConfig | string | null} [proxy]
 * @property {import('./trust/index.js').TrustConfig | null} [trust]
 * @property {import('./tls/connect.js').TlsOptions | null} [tls]
 * @property {boolean} [forceTunnel]
 */
/**
 * Can the platform's own fetch() satisfy this request in full?
 *
 * Delegating to the native implementation when it can is strictly better — it is faster, does not
 * burn metered CPU, speaks HTTP/2 and /3, and reaches origins our raw sockets are forbidden from
 * dialling. But delegation must be decided on CAPABILITY, not merely on "is there a proxy":
 * quietly satisfying a request that asked for a pinned certificate by handing it to an
 * implementation using a different trust store would answer a security question the caller did
 * not ask. So anything the native path cannot honour disqualifies it.
 *
 * @param {NativeFetchQuery} query
 * @returns {NativeFetchVerdict}
 */
export function nativeFetchCanServe({ proxy, trust, tls, forceTunnel }: NativeFetchQuery): NativeFetchVerdict;
/**
 * A request URL reduced to what the transport dials.
 */
export type TransportTarget = {
    url: URL;
    /**
     * IPv6 unbracketed, as the socket API and SOCKS5 want it
     */
    hostname: string;
    /**
     * explicit port, or the scheme default
     */
    port: number;
    /**
     * whether the scheme is https:
     */
    secure: boolean;
};
/**
 * What a Response's `tunnelfetch` detail reports about the connection, before the HTTP layer
 * adds the per-response httpVersion and framing.
 */
export type ConnectionInfo = {
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
};
/**
 * A live connection carrying application bytes: the duplex, its provenance, and the deadline
 * controller that governs it. This is what the pool stores and what sendAndReceive consumes.
 */
export type Connection = {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
    close: () => Promise<void> | void;
    info: ConnectionInfo;
    /**
     * TLS only;
     * null when trust mode 'none' accepted a leaf it could not parse
     */
    peerCertificate?: import("./trust/index.js").ParsedCertificate | null | undefined;
    deadlines: DeadlineController;
    /**
     * whether this call created the controller (and must dispose
     * it) rather than borrowing the caller's
     */
    ownsDeadlines: boolean;
};
export type OpenConnectionOptions = {
    url: string | URL;
    /**
     * injected socket factory
     */
    connect: import("./proxy/index.js").ConnectFn;
    proxy?: string | import("./proxy/index.js").ProxyConfig | null | undefined;
    /**
     * the `verify=`-style knob, passed
     * through to the trust layer
     */
    trust?: import("./trust/index.js").TrustConfig | undefined;
    /**
     * borrow the request's controller; omitting it makes
     * this call own (and dispose) a fresh one
     */
    deadlines?: DeadlineController | undefined;
    /**
     * handshake options
     */
    tls?: import("./tls/connect.js").TlsOptions | undefined;
    /**
     * injectable randomness/keygen for
     * reproducible handshakes
     */
    deps?: import("./tls/connect.js").TlsDeps | undefined;
    signal?: AbortSignal | undefined;
    /**
     * cap on the proxy CONNECT reply head
     */
    limits?: {
        maxProxyReplyBytes?: number;
    } | undefined;
    /**
     * epoch ms override for certificate validity
     */
    now?: number | undefined;
};
/**
 * The delegation decision, with the disqualifying reason spelled out so a caller's error can
 * quote it. Discriminated on `ok` so `reason` is a string exactly when there is one.
 */
export type NativeFetchVerdict = {
    ok: true;
    reason: null;
} | {
    ok: false;
    reason: string;
};
export type NativeFetchQuery = {
    proxy?: string | import("./proxy/index.js").ProxyConfig | null | undefined;
    trust?: import("./trust/index.js").TrustConfig | null | undefined;
    tls?: import("./tls/connect.js").TlsOptions | null | undefined;
    forceTunnel?: boolean | undefined;
};
import { DeadlineController } from './util/deadline.js';
