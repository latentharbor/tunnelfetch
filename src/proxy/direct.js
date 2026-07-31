// No proxy: the socket is the tunnel.
//
// Worth stating plainly, because it shapes what this package is for: on the target runtime a
// direct connection cannot reach a large fraction of the public web at all — the platform refuses
// outbound TCP to its own address ranges, and a great many sites sit behind them. Direct mode is
// therefore useful for hosts that are demonstrably not behind the platform, and for exercising the
// TLS stack in tests; for everything else the proxy is not an optimisation, it is the only route.

import { ProxyError, codes } from '../errors.js';

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
export async function openDirect({ target, connect, signal }) {
  signal?.throwIfAborted?.();
  let socket;
  try {
    socket = connect({ hostname: target.hostname, port: target.port }, {
      secureTransport: 'off',
      allowHalfOpen: false,
    });
  } catch (cause) {
    throw new ProxyError(
      codes.PROXY_UNREACHABLE,
      `could not open a socket to ${target.hostname}:${target.port}: ${cause?.message ?? cause}`,
      { target: `${target.hostname}:${target.port}` },
    );
  }
  if (socket.opened) {
    try {
      await socket.opened;
    } catch (cause) {
      // A failed dial still leaves a socket object behind; not closing it leaks one per attempt,
      // which for a crawl retrying against an unreachable host adds up inside a single isolate.
      try {
        await socket.close?.();
      } catch {
        /* it never opened; close failing tells us nothing new */
      }
      // The runtime's refusal messages are the most useful diagnostic a caller will get here, so
      // they are quoted rather than replaced.
      throw new ProxyError(
        codes.PROXY_UNREACHABLE,
        `connection to ${target.hostname}:${target.port} failed: ${cause?.message ?? cause}`,
        { target: `${target.hostname}:${target.port}` },
      );
    }
  }
  return socket;
}
