export { CookieJar } from "./client/cookies.js";
/**
 * A ready-made fetch with default options: no proxy, system trust, one connection per call.
 * Equivalent to httpx.get() versus httpx.Client() — reach for `new Client()` when connection
 * reuse or a cookie jar matters, which for anything crawl-shaped it does.
 *
 * A `connect` function must still be supplied per call (or via `createFetch`) for any request the
 * platform's own fetch cannot serve; see the README for why that is not defaulted.
 */
export const fetch: import("./client.js").FetchLike;
export { Client, createFetch, install } from "./client.js";
export { ConnectionPool, poolKey } from "./pool.js";
export { openConnection, targetFromUrl, nativeFetchCanServe } from "./transport.js";
export { openTunnel, parseProxy } from "./proxy/index.js";
export { verifyChain, rootStoreProvenance } from "./trust/index.js";
export { TunnelFetchError, ProxyError, HttpError, TlsError, TlsUnsupportedError, CertificateError, TimeoutError, LimitError, ConfigError, codes } from "./errors.js";
