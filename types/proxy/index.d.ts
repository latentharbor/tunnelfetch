/**
 * Normalise a proxy spec. Accepts a URL string (`http://user:pass@host:8080`,
 * `socks5://host:1080`) or an object.
 *
 * `socks5h` is accepted as an alias of `socks5` because that is the spelling curl popularised for
 * "resolve names at the proxy" — which is the only mode this package implements, since the
 * runtime gives us no resolver and remote resolution is also what avoids leaking the target to
 * the local DNS path.
 *
 * @param {string | ProxyConfig | null | undefined} spec
 * @returns {ProxyConfig | null}
 */
export function parseProxy(spec: string | ProxyConfig | null | undefined): ProxyConfig | null;
/**
 * Open a byte tunnel to `target`, through `proxy` if given.
 *
 * @param {object} args
 * @param {ProxyConfig | string | null} [args.proxy] null/absent means a direct connection
 * @param {{hostname: string, port: number}} args.target
 * @param {ConnectFn} args.connect socket factory, injected
 * @param {AbortSignal} [args.signal]
 * @param {object} [args.limits]
 * @returns {Promise<Duplex & { proxied: boolean }>}
 */
export function openTunnel({ proxy, target, connect, signal, limits }: {
    proxy?: string | ProxyConfig | null | undefined;
    target: {
        hostname: string;
        port: number;
    };
    connect: ConnectFn;
    signal?: AbortSignal | undefined;
    limits?: object | undefined;
}): Promise<Duplex & {
    proxied: boolean;
}>;
/** Close a duplex without caring whether it was already gone. */
export function closeQuietly(duplex: any): Promise<void>;
export type Duplex = {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
    opened?: Promise<unknown>;
    close?: () => Promise<void>;
};
export type ConnectFn = (addr: {
    hostname: string;
    port: number;
}, opts?: {
    secureTransport?: "off" | "on" | "starttls";
    allowHalfOpen?: boolean;
}) => Duplex;
/**
 * `proxyConnection` sets the pre-standard `Proxy-Connection` header on a CONNECT request, or
 * omits it entirely when null. Default 'keep-alive'. The origin never sees this header; the
 * proxy does, so it belongs to whatever fingerprint the proxy is reading. Clients disagree —
 * some send keep-alive, some close, some nothing — and omitting is not the same as 'close'.
 */
export type ProxyConfig = {
    protocol: "http" | "https" | "socks5" | "socks5h";
    hostname: string;
    port: number;
    username?: string;
    password?: string;
    proxyConnection?: string | null;
};
import { openDirect } from './direct.js';
import { openHttpConnect } from './http-connect.js';
import { openSocks5 } from './socks5.js';
export { openDirect, openHttpConnect, openSocks5 };
