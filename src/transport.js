// Transport assembly: URL in, byte duplex out.
//
// This is where the proxy tunnel and the userland TLS stack are stacked, and where the decision
// about who verifies the peer is made. That decision is the reason this package exists, so it is
// stated once, here, rather than being implied by the call graph:
//
//   The platform's socket API will happily complete a TLS handshake for us, but the identity it
//   checks is the hostname handed to connect(). Inside a proxy tunnel that hostname is the PROXY,
//   so the platform verifies the wrong party — and it exposes no peer certificate, so we cannot
//   check the right one afterwards either. Every proxied https connection therefore runs the
//   userland handshake, with the trust decision made by this package.
//
// The socket factory is injected. Nothing in src/ imports a runtime-specific module, which keeps
// every layer testable over an in-memory pipe and keeps the package portable.

import { ConfigError, codes } from './errors.js';
import { openTunnel, parseProxy } from './proxy/index.js';
import { connectTls } from './tls/connect.js';
import { verifyChain } from './trust/index.js';
import { DeadlineController } from './util/deadline.js';

const DEFAULT_PORT = { 'http:': 80, 'https:': 443 };

/**
 * Split a request URL into what the transport needs.
 * @param {string | URL} input
 */
export function targetFromUrl(input) {
  const url = input instanceof URL ? input : new URL(String(input));
  const port = url.port ? Number(url.port) : DEFAULT_PORT[url.protocol];
  if (!port) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `unsupported URL scheme "${url.protocol}"; only http: and https: are supported`,
      { scheme: url.protocol },
    );
  }
  // URL keeps IPv6 hosts bracketed; the socket API and SOCKS5 both want the bare address.
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  return { url, hostname, port, secure: url.protocol === 'https:' };
}

/**
 * Open a connection carrying application bytes for `url`.
 *
 * @param {object} args
 * @param {string|URL} args.url
 * @param {import('./proxy/index.js').ConnectFn} args.connect injected socket factory
 * @param {string|object|null} [args.proxy]
 * @param {object} [args.trust] the `verify=`-style knob, passed through to the trust layer
 * @param {DeadlineController} [args.deadlines]
 * @param {object} [args.tls] handshake options (alpn, groups, ciphers, ...)
 * @param {object} [args.deps] injectable randomness/keygen for reproducible handshakes
 * @param {AbortSignal} [args.signal]
 */
export async function openConnection({
  url,
  connect,
  proxy = null,
  trust = { mode: 'system' },
  deadlines,
  tls = {},
  deps = {},
  signal,
  limits = {},
  now,
}) {
  const target = targetFromUrl(url);
  const proxyConfig = parseProxy(proxy);
  const owns = !deadlines;
  const dl = deadlines ?? new DeadlineController({}, { signal });

  try {
    dl.beginPhase('connect');
    const tunnel = await dl.race(
      openTunnel({
        proxy: proxyConfig,
        target: { hostname: target.hostname, port: target.port },
        connect,
        signal: dl.signal,
        limits,
      }),
    );
    dl.endPhase();

    if (!target.secure) {
      return {
        readable: tunnel.readable,
        writable: tunnel.writable,
        close: () => tunnel.close?.(),
        info: {
          url: target.url.href,
          proxied: tunnel.proxied,
          proxy: proxyConfig ? `${proxyConfig.protocol}://${proxyConfig.hostname}:${proxyConfig.port}` : null,
          tls: null,
        },
        deadlines: dl,
        ownsDeadlines: owns,
      };
    }

    dl.beginPhase('handshake');
    let session;
    try {
      session = await dl.race(
        // connectTls offers TLS 1.3 and 1.2 in one ClientHello and follows the server's pick on
        // this same connection. There is no reconnect-and-retry-lower path anywhere: a failure
        // at any version is a failure, because a retry loop is exactly the downgrade lever the
        // RFC 8446 protections exist to deny an attacker. `tls.versions` narrows the offer.
        connectTls({
          transport: tunnel,
          hostname: target.hostname,
          // Bound to this request's trust configuration, so a caller who asked for pinning gets
          // pinning on this connection and nothing else can quietly substitute a laxer policy.
          verifyPeer: (chain, hostname) => verifyChain({ chain, hostname, trust, now }),
          options: tls,
          deps,
        }),
      );
    } catch (err) {
      await safeClose(tunnel);
      throw err;
    }
    dl.endPhase();

    return {
      readable: session.readable,
      writable: session.writable,
      close: async () => {
        try {
          await session.close();
        } finally {
          await safeClose(tunnel);
        }
      },
      info: {
        url: target.url.href,
        proxied: tunnel.proxied,
        proxy: proxyConfig ? `${proxyConfig.protocol}://${proxyConfig.hostname}:${proxyConfig.port}` : null,
        tls: session.info,
      },
      peerCertificate: session.peer,
      deadlines: dl,
      ownsDeadlines: owns,
    };
  } catch (err) {
    if (owns) dl.dispose();
    throw err;
  }
}

async function safeClose(duplex) {
  try {
    await duplex?.close?.();
  } catch {
    /* already gone */
  }
}

/**
 * Can the platform's own fetch() satisfy this request in full?
 *
 * Delegating to the native implementation when it can is strictly better — it is faster, does not
 * burn metered CPU, speaks HTTP/2 and /3, and reaches origins our raw sockets are forbidden from
 * dialling. But delegation must be decided on CAPABILITY, not merely on "is there a proxy":
 * quietly satisfying a request that asked for a pinned certificate by handing it to an
 * implementation using a different trust store would answer a security question the caller did
 * not ask. So anything the native path cannot honour disqualifies it.
 */
export function nativeFetchCanServe({ proxy, trust, tls, forceTunnel }) {
  if (forceTunnel) return { ok: false, reason: 'forceTunnel was requested' };
  if (proxy) return { ok: false, reason: 'a proxy was configured and fetch() has no proxy option' };
  const mode = trust?.mode ?? 'system';
  if (mode !== 'system') {
    return {
      ok: false,
      reason: `trust mode "${mode}" cannot be expressed to the platform's fetch(), which exposes ` +
        'no certificate hooks',
    };
  }
  if (tls && Object.keys(tls).length > 0) {
    return { ok: false, reason: 'TLS options were supplied that fetch() cannot honour' };
  }
  return { ok: true, reason: null };
}
