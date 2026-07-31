/**
 * @typedef {object} DirectOptions
 * @property {{ hostname: string, port: number }} target
 * @property {import('./index.js').ConnectFn} connect injected socket factory
 * @property {AbortSignal} [signal]
 */
/**
 * Dial the target itself. Resolves with the raw socket duplex; a refused or failed dial throws
 * ProxyError (PROXY_UNREACHABLE) quoting the runtime's own message, which is the best
 * diagnostic a caller will get.
 *
 * @param {DirectOptions} args
 * @returns {Promise<import('./index.js').Duplex>}
 */
export function openDirect({ target, connect, signal }: DirectOptions): Promise<import("./index.js").Duplex>;
export type DirectOptions = {
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
