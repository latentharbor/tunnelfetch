/**
 * Everything that decides whether two requests may share a socket. Mirrors what openConnection
 * consumed to build the connection, because anything that influenced the connection must
 * influence the key.
 * @typedef {object} PoolKeyInput
 * @property {string} scheme the URL protocol, colon included ('http:' | 'https:')
 * @property {string} hostname
 * @property {number} port
 * @property {import('./proxy/index.js').ProxyConfig | null | undefined} proxy
 * @property {import('./trust/index.js').TrustConfig | null | undefined} trust
 * @property {import('./tls/connect.js').TlsOptions | null | undefined} tls
 */
/**
 * The trust configuration is part of the key. Two requests to the same origin under different
 * verification policies must not share a connection — the peer was validated under one policy and
 * silently reusing it satisfies the other policy without ever having checked it.
 *
 * @param {PoolKeyInput} input
 * @returns {string}
 */
export function poolKey({ scheme, hostname, port, proxy, trust, tls }: PoolKeyInput): string;
/**
 * What the pool stores: the connection object openConnection resolves to. The pool itself only
 * ever calls `close?.()`, but naming the real type keeps take() useful to a caller.
 * @typedef {import('./transport.js').Connection} PooledConnection
 */
/**
 * @typedef {object} PoolOptions
 * @property {number} [maxPerKey] idle connections kept per key, default 6
 * @property {number} [maxTotal] idle connections kept across all keys, default 24
 */
/**
 * Running counters, never reset. `discarded` includes connections refused at release time;
 * `evicted` counts victims pushed out by a newer release under a full pool.
 * @typedef {object} PoolStats
 * @property {number} hits
 * @property {number} misses
 * @property {number} released
 * @property {number} discarded
 * @property {number} evicted
 */
export class ConnectionPool {
    /**
     * @param {PoolOptions} [opts]
     */
    constructor({ maxPerKey, maxTotal }?: PoolOptions);
    /** @type {Map<string, Array<{conn: PooledConnection}>>} */
    _idle: Map<string, Array<{
        conn: PooledConnection;
    }>>;
    _total: number;
    _maxPerKey: number;
    _maxTotal: number;
    _closed: boolean;
    /** @type {PoolStats} */
    stats: PoolStats;
    get idleCount(): number;
    /**
     * Take an idle connection for `key`, or null. Most-recently-used first: it is likeliest live.
     * @param {string} key
     * @returns {PooledConnection | null}
     */
    take(key: string): PooledConnection | null;
    /**
     * Offer a connection back. Callers must have proven the body reached its declared end; this
     * method cannot verify that and deliberately does not pretend to — `eligible` is the caller's
     * assertion, and the one place it is computed is the HTTP framing layer.
     * Idle entries carry no age, deliberately. Ageing them out would only narrow the window in
     * which a peer reaps a socket we still believe in, never close it — the peer can hang up at any
     * instant, including the one after the check. What actually makes reuse safe is the recovery in
     * sendAndReceive(): a reused connection that ends without producing one response byte is proof
     * the request was never seen, and it is re-sent on a fresh connection. An age field would look
     * like a second line of defence while being neither necessary nor sufficient.
     *
     * @param {string} key
     * @param {PooledConnection} conn
     * @param {boolean} eligible
     * @returns {boolean} whether the connection was retained
     */
    release(key: string, conn: PooledConnection, eligible: boolean): boolean;
    /**
     * Close and forget one connection that must not be reused.
     * @param {PooledConnection} conn
     * @returns {Promise<void>}
     */
    discard(conn: PooledConnection): Promise<void>;
    /**
     * Close everything. A Client that is done must call this or sockets leak for the isolate.
     * @returns {Promise<void>}
     */
    closeAll(): Promise<void>;
    _assertOpen(): void;
}
/**
 * Everything that decides whether two requests may share a socket. Mirrors what openConnection
 * consumed to build the connection, because anything that influenced the connection must
 * influence the key.
 */
export type PoolKeyInput = {
    /**
     * the URL protocol, colon included ('http:' | 'https:')
     */
    scheme: string;
    hostname: string;
    port: number;
    proxy: import("./proxy/index.js").ProxyConfig | null | undefined;
    trust: import("./trust/index.js").TrustConfig | null | undefined;
    tls: import("./tls/connect.js").TlsOptions | null | undefined;
};
/**
 * What the pool stores: the connection object openConnection resolves to. The pool itself only
 * ever calls `close?.()`, but naming the real type keeps take() useful to a caller.
 */
export type PooledConnection = import("./transport.js").Connection;
export type PoolOptions = {
    /**
     * idle connections kept per key, default 6
     */
    maxPerKey?: number | undefined;
    /**
     * idle connections kept across all keys, default 24
     */
    maxTotal?: number | undefined;
};
/**
 * Running counters, never reset. `discarded` includes connections refused at release time;
 * `evicted` counts victims pushed out by a newer release under a full pool.
 */
export type PoolStats = {
    hits: number;
    misses: number;
    released: number;
    discarded: number;
    evicted: number;
};
