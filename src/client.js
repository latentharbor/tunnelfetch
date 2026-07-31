// The fetch-shaped facade.
//
// The public surface is deliberately the platform's own: requests come in as `Request`, responses
// go out as `Response`. That is not decoration — the OpenAI and Anthropic SDKs, and most of the
// libraries anyone would want to route through a proxy, accept a custom `fetch` and nothing else.
// Being that function is the deliverable.
//
// Delegation to the platform's fetch is a capability decision, not a convenience one; see
// `nativeFetchCanServe` in transport.js for why. Nothing here ever installs itself: replacing a
// global at import time turns every unrelated failure in a process into a mystery about this
// package, so `install()` exists, is explicit, and hands back its own undo.

import { ConfigError, HttpError, TunnelFetchError, codes } from './errors.js';
import { ByteReader, ByteWriter, concat, utf8 } from './util/bytes.js';
import { serializeRequestHead } from './http1/request.js';
import { bodyFraming, readResponseBody, readResponseHead } from './http1/response.js';
import { ACCEPT_ENCODING, decodeBody } from './client/decode.js';
import { CookieJar } from './client/cookies.js';
import { DEFAULT_MAX_REDIRECTS, nextRequest, shouldRedirect } from './client/redirect.js';
import { ConnectionPool, poolKey } from './pool.js';
import { DeadlineController } from './util/deadline.js';
import { nativeFetchCanServe, openConnection, targetFromUrl } from './transport.js';
import { parseProxy } from './proxy/index.js';

/** Status codes whose Response may not carry a body, per the Response constructor. */
const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

export class Client {
  /**
   * @param {object} [options]
   * @param {import('./proxy/index.js').ConnectFn} [options.connect] socket factory; required for
   *   anything the platform's fetch cannot serve
   * @param {string|object|null} [options.proxy]
   * @param {object} [options.trust] httpx-style `verify=`: {mode:'system'|'anchors'|'pinned'|'none'|'custom'}
   * @param {object} [options.tls] handshake options
   * @param {object} [options.timeouts] connect/handshake/headers/idle/total, in ms
   * @param {boolean} [options.cookies] enable a per-Client cookie jar
   * @param {number} [options.maxRedirects]
   * @param {number} [options.maxBodyBytes]
   * @param {boolean} [options.forceTunnel] never delegate to the platform fetch
   * @param {typeof globalThis.fetch} [options.nativeFetch]
   */
  constructor(options = {}) {
    this.options = { ...options };
    this.pool = new ConnectionPool(options.pool);
    this.jar = options.cookies ? (options.jar ?? new CookieJar()) : (options.jar ?? null);
    this._closed = false;
    // Bound so a Client can be handed straight to an SDK expecting a bare function.
    this.fetch = this.fetch.bind(this);
  }

  async fetch(input, init) {
    if (this._closed) {
      throw new TunnelFetchError(codes.POOL_CLOSED, 'this Client has been closed');
    }
    return performFetch(this, input, init);
  }

  /** Release every pooled socket. A Client that is finished must be closed or sockets leak. */
  async close() {
    this._closed = true;
    await this.pool.closeAll();
  }
}

/**
 * A standalone fetch bound to a configuration, matching httpx's module-level helpers. Creates and
 * closes a Client per call, so no connection is reused; use `new Client()` when reuse matters.
 */
export function createFetch(options = {}) {
  return async function tunnelFetch(input, init) {
    const client = new Client(options);
    try {
      return await client.fetch(input, init);
    } finally {
      await client.close();
    }
  };
}

/**
 * Replace `globalThis.fetch`, for libraries that only accept the global. Returns the undo.
 * Never called automatically, and never on import.
 */
export function install(options = {}) {
  const previous = globalThis.fetch;
  const replacement = createFetch(options);
  globalThis.fetch = replacement;
  let undone = false;
  return function uninstall() {
    if (undone) return;
    undone = true;
    // Only restore if nobody replaced us in the meantime; clobbering a third party's global on
    // the way out would be the same mistake in reverse.
    if (globalThis.fetch === replacement) globalThis.fetch = previous;
  };
}

// ------------------------------------------------------------------ the request loop

async function performFetch(client, input, init) {
  const o = client.options;
  const request = new Request(input, init);
  const redirectMode = init?.redirect ?? request.redirect ?? 'follow';
  const maxRedirects = o.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  // Buffer the body once so a 307/308 can replay it. A stream body cannot be replayed, and
  // pretending otherwise by sending an empty body on the second hop would corrupt the request.
  let body = null;
  if (request.body) {
    body = new Uint8Array(await request.arrayBuffer());
  }

  let current = {
    url: new URL(request.url),
    method: request.method,
    headers: new Headers(request.headers),
    body,
  };
  const history = [];

  for (let hop = 0; ; hop++) {
    const response = await exchange(client, current, { hop });

    if (redirectMode !== 'follow' || !shouldRedirect(response.status, current.method)) {
      if (redirectMode === 'error' && shouldRedirect(response.status, current.method)) {
        throw new HttpError(
          codes.REDIRECT_SCHEME,
          `redirect mode is "error" but the server answered ${response.status}`,
          { status: response.status },
        );
      }
      return finish(response, current.url, history.length > 0);
    }

    const next = nextRequest(current, response, { maxRedirects, history });
    // The previous body must be drained (or discarded) before the socket can be reused, and the
    // caller will never read a redirect's body.
    await response.body?.cancel?.().catch(() => {});
    history.push({ method: current.method, url: current.url.href });
    current = next;
  }
}

function finish(response, url, redirected) {
  // `url` and `redirected` are read-only on Response, but every consumer expects them to reflect
  // where the body actually came from.
  Object.defineProperty(response, 'url', { value: url.href, configurable: true });
  Object.defineProperty(response, 'redirected', { value: redirected, configurable: true });
  return response;
}

// ------------------------------------------------------------------ one request/response

async function exchange(client, current, { hop }) {
  const o = client.options;
  const proxy = parseProxy(o.proxy ?? null);
  const trust = o.trust ?? { mode: 'system' };
  const tls = o.tls ?? {};

  const native = nativeFetchCanServe({ proxy, trust, tls, forceTunnel: o.forceTunnel });
  if (native.ok) {
    const fetchImpl = o.nativeFetch ?? globalThis.fetch;
    if (typeof fetchImpl === 'function') {
      return fetchImpl(current.url.href, {
        method: current.method,
        headers: current.headers,
        body: current.body ?? undefined,
        redirect: 'manual',
      });
    }
  } else if (typeof o.connect !== 'function') {
    throw new ConfigError(
      codes.CONFIG_UNSATISFIABLE,
      `this request cannot use the platform's fetch (${native.reason}) and no connect function ` +
        'was configured. Supply `connect`: the raw-TCP socket factory of the host runtime, ' +
        'which must return { readable, writable, opened?, close? }. The README names the exact ' +
        'import for each supported runtime.',
      { reason: native.reason },
    );
  }

  const target = targetFromUrl(current.url);
  const key = poolKey({
    scheme: current.url.protocol,
    hostname: target.hostname,
    port: target.port,
    proxy,
    trust,
    tls,
  });

  const deadlines = new DeadlineController(o.timeouts ?? {}, { signal: o.signal });
  let conn = client.pool.take(key);
  let reused = conn !== null;
  try {
    if (!conn) {
      conn = await openConnection({
        url: current.url,
        connect: o.connect,
        proxy,
        trust,
        tls,
        deps: o.deps,
        deadlines,
        limits: o.limits ?? {},
        now: o.now,
      });
    }
    return await sendAndReceive(client, conn, current, { key, deadlines, reused, hop });
  } catch (err) {
    deadlines.dispose();
    if (conn) await client.pool.discard(conn);
    throw err;
  }
}

async function sendAndReceive(client, conn, current, { key, deadlines, reused }) {
  const o = client.options;
  const target = targetFromUrl(current.url);
  const headers = buildHeaders(client, current, target);

  const head = serializeRequestHead({
    method: current.method,
    target: requestTarget(current.url),
    headers,
  });

  const writer = new ByteWriter(conn.writable);
  try {
    await writer.write(current.body ? concat([head, current.body]) : head);
  } finally {
    writer.releaseLock();
  }

  deadlines.beginPhase('headers');
  const reader = conn._reader ?? new ByteReader(conn.readable);
  conn._reader = reader; // one reader per connection, so a reused socket keeps its buffer

  let headInfo;
  try {
    headInfo = await deadlines.race(
      readResponseHead(reader, { maxHeaderBytes: o.limits?.maxHeaderBytes }),
    );
  } catch (err) {
    // A reused connection the server had already closed looks exactly like a truncated response.
    // Retrying once on a fresh connection is the standard remedy and is safe here because the
    // request has not been answered.
    if (reused) {
      await client.pool.discard(conn);
      deadlines.endPhase();
      const fresh = await openConnection({
        url: current.url,
        connect: o.connect,
        proxy: parseProxy(o.proxy ?? null),
        trust: o.trust ?? { mode: 'system' },
        tls: o.tls ?? {},
        deps: o.deps,
        deadlines,
        limits: o.limits ?? {},
        now: o.now,
      });
      return sendAndReceive(client, fresh, current, { key, deadlines, reused: false });
    }
    throw err;
  }
  deadlines.endPhase();

  const framing = bodyFraming({
    status: headInfo.status,
    method: current.method,
    headers: headInfo.headers,
  });

  if (client.jar && headInfo.setCookie?.length) {
    client.jar.setFromResponse(current.url, headInfo.setCookie);
  }

  const raw = readResponseBody(reader, framing, { maxBytes: o.maxBodyBytes ?? Infinity });

  // The connection goes back to the pool only when the body reaches the end its framing declared.
  // `completed` resolving false means the caller cancelled and the stream position is unknown.
  raw.completed.then(
    (ok) => {
      deadlines.dispose();
      client.pool.release(key, conn, ok && framing.keepAliveEligible && wantsKeepAlive(headInfo));
    },
    () => {
      deadlines.dispose();
      void client.pool.discard(conn);
    },
  );

  deadlines.beginIdle();
  const decoded = decodeResponseBody(raw, headInfo.headers, deadlines, o);
  return buildResponse(headInfo, decoded, framing, conn);
}

function wantsKeepAlive(headInfo) {
  const connection = (headInfo.headers.get('connection') ?? '').toLowerCase();
  if (connection.split(',').some((t) => t.trim() === 'close')) return false;
  // HTTP/1.0 defaults to close unless it explicitly asks to stay open.
  if (headInfo.httpVersion === '1.0') {
    return connection.split(',').some((t) => t.trim() === 'keep-alive');
  }
  return true;
}

function decodeResponseBody(raw, headers, deadlines, options) {
  if (options.decompress === false) return raw;
  const encoding = headers.get('content-encoding');
  if (!encoding) return raw;
  return decodeBody(raw, encoding);
}

function buildResponse(headInfo, body, framing, conn) {
  const headers = new Headers();
  for (const [k, v] of headInfo.headers) {
    if (k === 'set-cookie') continue;
    headers.append(k, v);
  }
  for (const c of headInfo.setCookie ?? []) headers.append('set-cookie', c);
  if (headers.has('content-encoding')) {
    // The bytes handed to the caller are decoded, so a byte count describing the encoded form
    // would be a lie. Content-Encoding stays as information about what was on the wire.
    headers.delete('content-length');
  }

  const useNullBody = NULL_BODY_STATUS.has(headInfo.status) || framing.kind === 'none';
  const response = new Response(useNullBody ? null : body, {
    status: headInfo.status,
    statusText: headInfo.statusText,
    headers,
  });
  Object.defineProperty(response, 'tunnelfetch', {
    value: Object.freeze({ ...conn.info, httpVersion: headInfo.httpVersion, framing: framing.kind }),
    configurable: true,
  });
  return response;
}

function requestTarget(url) {
  return `${url.pathname}${url.search}`;
}

function buildHeaders(client, current, target) {
  const headers = new Headers(current.headers);
  // Host is derived from the URL and never carried across a redirect; the default port is omitted
  // because a server matching virtual hosts on the literal Host value expects it that way.
  const defaultPort = current.url.protocol === 'https:' ? 443 : 80;
  const hostValue =
    target.port === defaultPort ? current.url.hostname : `${current.url.hostname}:${target.port}`;

  if (!headers.has('accept')) headers.set('accept', '*/*');
  if (!headers.has('accept-encoding') && client.options.decompress !== false) {
    // Never advertise br or zstd: the runtime has no DecompressionStream for either, so the
    // reward for asking would be a body we cannot decode.
    headers.set('accept-encoding', ACCEPT_ENCODING);
  }
  if (client.jar) {
    const cookie = client.jar.headerFor(current.url);
    if (cookie) {
      const existing = headers.get('cookie');
      headers.set('cookie', existing ? `${existing}; ${cookie}` : cookie);
    }
  }
  headers.set('connection', client.options.keepAlive === false ? 'close' : 'keep-alive');

  // Content-Length must describe exactly what we are about to write.
  if (current.body) headers.set('content-length', String(current.body.byteLength));
  else if (['POST', 'PUT', 'PATCH'].includes(current.method)) headers.set('content-length', '0');

  const ordered = [['host', hostValue]];
  for (const [k, v] of headers) {
    if (k === 'host') continue;
    ordered.push([k, v]);
  }
  return ordered;
}

export { CookieJar, ConnectionPool, utf8 };
