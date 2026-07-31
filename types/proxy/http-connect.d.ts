/**
 * Establish a CONNECT tunnel through an http/https proxy. Resolves with the tunnel duplex;
 * every refusal (non-2xx, 407 with or without credentials, malformed reply) throws a
 * ProxyError naming what the proxy answered.
 *
 * @param {HttpConnectOptions} args
 * @returns {Promise<ProxyTunnel>}
 */
export function openHttpConnect({ proxy, target, connect, signal, limits }: HttpConnectOptions): Promise<ProxyTunnel>;
/**
 * The tunnel a proxy module hands back: the byte duplex plus the underlying socket, kept so a
 * caller that must tear down the transport can reach past the wrapping streams.
 */
export type ProxyTunnel = import("./index.js").Duplex & {
    socket: import("./index.js").Duplex;
};
export type HttpConnectOptions = {
    /**
     * protocol 'http' or 'https'
     */
    proxy: import("./index.js").ProxyConfig;
    target: {
        hostname: string;
        port: number;
    };
    /**
     * injected socket factory
     */
    connect: import("./index.js").ConnectFn;
    signal?: AbortSignal | undefined;
    /**
     * CONNECT reply head cap, default 32768
     */
    limits?: {
        maxProxyReplyBytes?: number;
    } | undefined;
};
