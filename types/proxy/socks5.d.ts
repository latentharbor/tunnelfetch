/**
 * @typedef {object} Socks5Options
 * @property {import('./index.js').ProxyConfig} proxy credentials trigger RFC 1929 user/pass auth
 * @property {{ hostname: string, port: number }} target
 * @property {import('./index.js').ConnectFn} connect injected socket factory
 * @property {AbortSignal} [signal]
 */
/**
 * Establish a SOCKS5 tunnel. Resolves with the tunnel duplex; every refusal (no acceptable
 * auth method, rejected credentials, non-zero reply code, unframeable reply) throws a
 * ProxyError naming the exact wire value the proxy sent.
 *
 * @param {Socks5Options} args
 * @returns {Promise<import('./http-connect.js').ProxyTunnel>}
 */
export function openSocks5({ proxy, target, connect, signal }: Socks5Options): Promise<import("./http-connect.js").ProxyTunnel>;
/**
 * Encode DST.ADDR + DST.PORT. Prefers the domain form so the proxy resolves.
 * @param {{ hostname: string, port: number }} target
 * @returns {Uint8Array}
 */
export function encodeAddress(target: {
    hostname: string;
    port: number;
}): Uint8Array;
/**
 * Minimal IPv6 text parser: `::` compression and a trailing embedded IPv4 are both real.
 * Throws ConfigError on anything that does not expand to exactly 8 groups.
 * @param {string} text
 * @returns {Uint8Array} the 16 address bytes
 */
export function parseIpv6(text: string): Uint8Array;
export type Socks5Options = {
    /**
     * credentials trigger RFC 1929 user/pass auth
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
};
