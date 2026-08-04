// Proxy tunnels: turn "reach host:port" into a raw byte duplex, whatever sits in between.
//
// The whole point of this layer is that nothing above it can tell the difference. Once
// openTunnel resolves, the caller writes a TLS ClientHello or a plaintext HTTP request into an
// opaque pipe and the proxy protocol never surfaces again.
//
// The socket factory is injected rather than imported from the runtime. That is what makes every
// protocol path here testable byte-for-byte with an in-memory fake proxy and no network at all —
// and it is also why this package can run anywhere `{readable, writable}` can be produced.

import { ProxyError, ConfigError, codes } from '../errors.js';
import { openDirect } from './direct.js';
import { openHttpConnect } from './http-connect.js';
import { openSocks5 } from './socks5.js';

/**
 * @typedef {{ readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>,
 *             opened?: Promise<unknown>, close?: () => Promise<void> }} Duplex
 * @typedef {(addr: {hostname: string, port: number},
 *            opts?: {secureTransport?: 'off'|'on'|'starttls', allowHalfOpen?: boolean}) => Duplex} ConnectFn
 * @typedef {{ protocol: 'http'|'https'|'socks5'|'socks5h', hostname: string, port: number,
 *             username?: string, password?: string,
 *             proxyConnection?: string | null }} ProxyConfig
 *
 * `proxyConnection` sets the pre-standard `Proxy-Connection` header on a CONNECT request, or
 * omits it entirely when null. Default 'keep-alive'. The origin never sees this header; the
 * proxy does, so it belongs to whatever fingerprint the proxy is reading. Clients disagree —
 * some send keep-alive, some close, some nothing — and omitting is not the same as 'close'.
 */

const DEFAULT_PORTS = { http: 8080, https: 443, socks5: 1080, socks5h: 1080 };

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
export function parseProxy(spec) {
  if (spec == null || spec === '') return null;
  if (typeof spec === 'object') return normalise(spec);

  let url;
  try {
    url = new URL(spec);
  } catch {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `proxy "${spec}" is not a URL; expected scheme://[user:pass@]host[:port] with a scheme of ` +
        'http, https, socks5 or socks5h',
    );
  }
  const protocol = url.protocol.replace(/:$/, '').toLowerCase();
  return normalise({
    protocol,
    hostname: url.hostname.replace(/^\[|\]$/g, ''),
    // `url.port` is empty both when no port was written AND when the written port equals the
    // WHATWG default for the scheme — so `http://proxy:80` and `http://proxy` are indistinguishable
    // through the URL API, and falling back to our default would silently dial 8080 instead of 80.
    port: url.port ? Number(url.port) : explicitPort(spec),
    // Credentials in a URL are percent-encoded; a password containing `@` or `:` only survives
    // the round trip if it is decoded here.
    username: url.username ? decodePart(url.username, 'username', spec) : undefined,
    password: url.password ? decodePart(url.password, 'password', spec) : undefined,
  });
}

/** Read the port straight out of the authority, since the URL API hides scheme-default ports. */
function explicitPort(spec) {
  const sep = spec.indexOf('://');
  if (sep === -1) return undefined;
  const authority = spec.slice(sep + 3).split(/[/?#]/, 1)[0];
  const hostPart = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
  const m = /^(?:\[[^\]]*\]|[^:]*)(?::(\d+))?$/.exec(hostPart);
  return m && m[1] !== undefined ? Number(m[1]) : undefined;
}

function decodePart(value, what, spec) {
  try {
    return decodeURIComponent(value);
  } catch {
    // decodeURIComponent throws a bare URIError, which would escape the typed-error contract
    // every other malformed spec in this function honours.
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `proxy ${what} in "${spec}" contains a malformed percent-escape`,
      { what },
    );
  }
}

function normalise(cfg) {
  const protocol = String(cfg.protocol ?? '').toLowerCase().replace(/:$/, '');
  if (!(protocol in DEFAULT_PORTS)) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `proxy protocol "${protocol}" is not supported; use http, https, socks5 or socks5h`,
      { protocol },
    );
  }
  if (!cfg.hostname) {
    throw new ConfigError(codes.CONFIG_INVALID, 'proxy configuration has no hostname');
  }
  const port = cfg.port ?? DEFAULT_PORTS[protocol];
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ConfigError(codes.CONFIG_INVALID, `proxy port ${port} is out of range`, { port });
  }
  if ((cfg.password != null && cfg.password !== '') && !cfg.username) {
    throw new ConfigError(codes.CONFIG_INVALID, 'proxy password given without a username');
  }
  return Object.freeze({
    protocol: protocol === 'socks5h' ? 'socks5' : protocol,
    hostname: cfg.hostname,
    port,
    username: cfg.username || undefined,
    password: cfg.password || undefined,
    // Listed explicitly because this function REBUILDS the config rather than copying it, so a
    // field not named here is dropped without a word. That is how `http2ConnectionWindow` came to
    // be declared in a profile and read by nothing.
    proxyConnection: cfg.proxyConnection,
  });
}

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
export async function openTunnel({ proxy, target, connect, signal, limits = {} }) {
  if (typeof connect !== 'function') {
    throw new ConfigError(codes.CONFIG_INVALID, 'openTunnel requires a connect function');
  }
  validateTarget(target);
  const cfg = typeof proxy === 'string' || (proxy && !Object.isFrozen(proxy)) ? parseProxy(proxy) : proxy ?? null;

  if (!cfg) {
    // Read the duplex off the socket explicitly rather than spreading it. Object spread copies own
    // enumerable properties only, and on the target runtime a socket's `readable` and `writable`
    // are accessors on the prototype — so `{ ...socket }` yields an object with neither, and the
    // first read fails with "Cannot read properties of undefined (reading 'getReader')" from deep
    // inside the TLS layer. The proxy branches below are unaffected because they return plain
    // objects they built themselves; only this one handed a host object to the spread. The offline
    // suite cannot catch it either, since its fake sockets are plain objects with own properties.
    const socket = await openDirect({ target, connect, signal });
    return {
      readable: socket.readable,
      writable: socket.writable,
      opened: socket.opened,
      close: () => socket.close?.(),
      socket,
      proxied: false,
    };
  }
  if (cfg.protocol === 'http' || cfg.protocol === 'https') {
    return { ...(await openHttpConnect({ proxy: cfg, target, connect, signal, limits })), proxied: true };
  }
  if (cfg.protocol === 'socks5') {
    return { ...(await openSocks5({ proxy: cfg, target, connect, signal })), proxied: true };
  }
  /* c8 ignore next */
  throw new ConfigError(codes.CONFIG_INVALID, `unreachable proxy protocol ${cfg.protocol}`);
}

function validateTarget(target) {
  if (!target || typeof target.hostname !== 'string' || !target.hostname) {
    throw new ConfigError(codes.CONFIG_INVALID, 'tunnel target needs a hostname');
  }
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `tunnel target port ${target.port} is out of range`,
      { port: target.port },
    );
  }
  // A hostname carrying CR, LF or NUL would let a caller inject a second request line into the
  // CONNECT we are about to write. Reject at the boundary rather than escaping downstream.
  if (/[\0\r\n\s]/.test(target.hostname)) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      'tunnel target hostname contains whitespace or a control character',
      { hostname: target.hostname },
    );
  }
}

/** Close a duplex without caring whether it was already gone. */
export async function closeQuietly(duplex) {
  try {
    await duplex?.close?.();
  } catch {
    /* already closed or never opened */
  }
}

export { openDirect, openHttpConnect, openSocks5 };
