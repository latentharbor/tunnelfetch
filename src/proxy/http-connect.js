// HTTP CONNECT tunnelling (RFC 9110 s9.3.6; wire syntax RFC 9112).
//
// Two details here are not theory — they were measured against a live proxy while building this:
//
//   * The reply may be `HTTP/1.0 200 OK` even though we sent an HTTP/1.1 request. Matching on the
//     version or the reason phrase would break against real deployments; only the status code is
//     meaningful, and any 2xx opens the tunnel.
//   * The reply header block can be as short as 19 bytes and the server may put tunnel payload in
//     the SAME read as the terminating CRLFCRLF. Those bytes belong to the peer, not to us. Losing
//     them silently truncates the first TLS record, which surfaces much later as an inexplicable
//     handshake failure, so the reader that consumed the header block is handed on intact rather
//     than being discarded.

import { ProxyError, LimitError, codes } from '../errors.js';
import { ByteReader, ByteWriter, latin1, utf8 } from '../util/bytes.js';

const CRLFCRLF = utf8('\r\n\r\n');
const MAX_REPLY_HEADER = 32 * 1024;

/**
 * The tunnel a proxy module hands back: the byte duplex plus the underlying socket, kept so a
 * caller that must tear down the transport can reach past the wrapping streams.
 * @typedef {import('./index.js').Duplex & { socket: import('./index.js').Duplex }} ProxyTunnel
 */

/**
 * @typedef {object} HttpConnectOptions
 * @property {import('./index.js').ProxyConfig} proxy protocol 'http' or 'https'
 * @property {{ hostname: string, port: number }} target
 * @property {import('./index.js').ConnectFn} connect injected socket factory
 * @property {AbortSignal} [signal]
 * @property {{ maxProxyReplyBytes?: number }} [limits] CONNECT reply head cap, default 32768
 */

/** RFC 7617: credentials are UTF-8 before base64, and btoa only accepts code units below 256. */
function basicCredentials(username, password) {
  const raw = utf8(`${username}:${password ?? ''}`);
  return btoa(latin1(raw));
}

/** IPv6 literals must be bracketed in an authority, or the port cannot be told from the address. */
function authority(hostname, port) {
  return hostname.includes(':') ? `[${hostname}]:${port}` : `${hostname}:${port}`;
}

/**
 * Establish a CONNECT tunnel through an http/https proxy. Resolves with the tunnel duplex;
 * every refusal (non-2xx, 407 with or without credentials, malformed reply) throws a
 * ProxyError naming what the proxy answered.
 *
 * @param {HttpConnectOptions} args
 * @returns {Promise<ProxyTunnel>}
 */
export async function openHttpConnect({ proxy, target, connect, signal, limits = {} }) {
  signal?.throwIfAborted?.();
  const overTls = proxy.protocol === 'https';
  const where = `${proxy.hostname}:${proxy.port}`;

  let socket;
  try {
    socket = connect(
      { hostname: proxy.hostname, port: proxy.port },
      // For an https proxy the runtime does TLS to the proxy itself. That is the one hop where
      // the platform's certificate check asks the right question: the identity it verifies is the
      // hostname handed to connect(), which here IS the proxy. (It follows that an https proxy
      // addressed by bare IP will fail that check, since public certificates carry no IP SAN.)
      { secureTransport: overTls ? 'on' : 'starttls', allowHalfOpen: false },
    );
  } catch (cause) {
    throw new ProxyError(
      codes.PROXY_UNREACHABLE,
      `could not open a socket to proxy ${where}: ${cause?.message ?? cause}`,
      { proxy: where },
    );
  }

  let reader;
  let writer;
  try {
    if (socket.opened) await socket.opened;

    writer = new ByteWriter(socket.writable);
    await writer.write(utf8(buildConnectRequest(proxy, target)));
    writer.releaseLock();

    reader = new ByteReader(socket.readable);
    const max = limits.maxProxyReplyBytes ?? MAX_REPLY_HEADER;
    let block;
    try {
      block = await reader.readUntil(CRLFCRLF, max, 'proxy CONNECT reply');
    } catch (cause) {
      if (cause instanceof LimitError) throw cause;
      throw new ProxyError(
        codes.PROXY_PROTOCOL,
        `proxy ${where} closed or misbehaved before completing its CONNECT reply: ${cause?.message ?? cause}`,
        { proxy: where },
      );
    }
    const reply = parseReply(latin1(block), where);

    if (reply.status < 200 || reply.status > 299) {
      throw replyError(reply, proxy, target, where);
    }
    // Anything the proxy sent after the blank line is already tunnel payload. It stays buffered in
    // `reader`, which becomes the tunnel's read side, so it cannot be dropped.
    return tunnelFrom(socket, reader);
  } catch (err) {
    try {
      writer?.releaseLock();
      await reader?.cancel(err);
      await socket.close?.();
    } catch {
      /* the socket may already be unusable; the original error is what matters */
    }
    throw err;
  }
}

function buildConnectRequest(proxy, target) {
  const host = authority(target.hostname, target.port);
  const lines = [`CONNECT ${host} HTTP/1.1`, `Host: ${host}`];
  if (proxy.username) {
    lines.push(`Proxy-Authorization: Basic ${basicCredentials(proxy.username, proxy.password)}`);
  }
  // Some proxies still key off the pre-standard hop header; sending it is harmless and avoids a
  // class of proxy that closes the tunnel after one request without it.
  lines.push('Proxy-Connection: keep-alive');
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function parseReply(text, where) {
  const [statusLine, ...headerLines] = text.split('\r\n');
  const m = /^HTTP\/(\d)\.(\d) (\d{3})(?: (.*))?$/.exec(statusLine ?? '');
  if (!m) {
    throw new ProxyError(
      codes.PROXY_PROTOCOL,
      `proxy ${where} did not answer CONNECT with an HTTP status line (got ${JSON.stringify(
        (statusLine ?? '').slice(0, 80),
      )})`,
      { proxy: where, statusLine },
    );
  }
  const headers = new Map();
  for (const line of headerLines) {
    if (line === '') break;
    const i = line.indexOf(':');
    if (i <= 0) continue; // a malformed header in an otherwise valid reply is not worth failing on
    headers.set(line.slice(0, i).toLowerCase().trim(), line.slice(i + 1).trim());
  }
  return {
    httpVersion: `${m[1]}.${m[2]}`,
    status: Number(m[3]),
    reason: m[4] ?? '',
    headers,
    statusLine,
  };
}

function replyError(reply, proxy, target, where) {
  const to = authority(target.hostname, target.port);
  if (reply.status === 407) {
    const challenge = reply.headers.get('proxy-authenticate') ?? '(none sent)';
    // Naming the scheme the proxy asked for is the whole value of this error: "auth failed" does
    // not tell anyone whether they typed the password wrong or the proxy wants Digest/NTLM.
    return proxy.username
      ? new ProxyError(
          codes.PROXY_AUTH_FAILED,
          `proxy ${where} rejected the supplied credentials for user "${proxy.username}" ` +
            `(407 ${reply.reason}); it offers: ${challenge}`,
          { proxy: where, challenge, status: 407 },
        )
      : new ProxyError(
          codes.PROXY_AUTH_REQUIRED,
          `proxy ${where} requires authentication (407 ${reply.reason}); it offers: ${challenge}`,
          { proxy: where, challenge, status: 407 },
        );
  }
  return new ProxyError(
    codes.PROXY_CONNECT_REFUSED,
    `proxy ${where} refused CONNECT to ${to}: ${reply.status} ${reply.reason}`.trimEnd(),
    { proxy: where, target: to, status: reply.status, reason: reply.reason },
  );
}

/**
 * Wrap the still-buffered reader as the tunnel's readable so bytes that arrived alongside the
 * CONNECT reply are delivered first, in order.
 */
function tunnelFrom(socket, reader) {
  return {
    readable: new ReadableStream({
      async pull(controller) {
        const chunk = await reader.readSome();
        if (chunk === null) controller.close();
        else controller.enqueue(chunk);
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    }),
    writable: socket.writable,
    opened: socket.opened,
    close: () => socket.close?.(),
    socket,
  };
}
