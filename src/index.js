// tunnelfetch — a fetch-shaped HTTP client that can route through a proxy on runtimes that only
// expose raw TCP.
//
// Why this exists, in one paragraph: on Cloudflare Workers `fetch()` has no proxy option,
// `node:net`/`node:tls` are built on the same socket API and inherit its limits, and the socket
// API's own TLS verifies the certificate against the hostname passed to `connect()` — which,
// inside a CONNECT or SOCKS5 tunnel, is the proxy rather than the origin. It also exposes no peer
// certificate, so the check cannot be redone afterwards. Measured on the edge: a tunnelled
// `startTls()` fails closed, which is the right failure but leaves no route at all. The only
// remaining path is to speak TLS ourselves, which is what this package does.
//
// Nothing here installs itself. `install()` is explicit and returns its own undo.

export { Client, createFetch, install } from './client.js';
export { warmup } from './warmup.js';
export { ConnectionPool, poolKey } from './pool.js';
export { openConnection, targetFromUrl, nativeFetchCanServe } from './transport.js';
export { openTunnel, parseProxy } from './proxy/index.js';
export { CookieJar } from './client/cookies.js';
export { verifyChain, rootStoreProvenance } from './trust/index.js';

export {
  TunnelFetchError,
  ProxyError,
  HttpError,
  TlsError,
  TlsUnsupportedError,
  Http2Error,
  CertificateError,
  TimeoutError,
  LimitError,
  ConfigError,
  codes,
} from './errors.js';

import { createFetch } from './client.js';

/**
 * A ready-made fetch with default options: no proxy, system trust, one connection per call.
 * Equivalent to httpx.get() versus httpx.Client() — reach for `new Client()` when connection
 * reuse or a cookie jar matters, which for anything crawl-shaped it does.
 *
 * A `connect` function must still be supplied per call (or via `createFetch`) for any request the
 * platform's own fetch cannot serve; see the README for why that is not defaulted.
 */
export const fetch = createFetch();
export { profiles, curl, chrome, applyProfile } from './profiles.js';
