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
import { ByteReader, ByteWriter, UnexpectedEofError, concat, utf8 } from './util/bytes.js';
import { serializeRequestHead } from './http1/request.js';
import { bodyFraming, readResponseBody, readResponseHead } from './http1/response.js';
import { ACCEPT_ENCODING, decodeBody } from './client/decode.js';
import { CookieJar } from './client/cookies.js';
import { DEFAULT_MAX_REDIRECTS, nextRequest, shouldRedirect } from './client/redirect.js';
import { ConnectionPool, poolKey } from './pool.js';
import { DeadlineController, withIdleDeadline } from './util/deadline.js';
import { nativeFetchCanServe, openConnection, targetFromUrl } from './transport.js';
import { parseProxy } from './proxy/index.js';

/** Status codes whose Response may not carry a body, per the Response constructor. */
const NULL_BODY_STATUS = new Set([101, 204, 205, 304]);

/**
 * A `fetch`-shaped function. Deliberately the platform's own signature: being assignable to
 * `typeof fetch` is what lets an SDK accept this in place of the global without adapting.
 * @typedef {(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>} FetchLike
 */

/**
 * What a Response carries about the connection that produced it, under the non-standard
 * `tunnelfetch` property.
 * @typedef {object} ResponseDetail
 * @property {string} url
 * @property {boolean} proxied
 * @property {string | null} proxy the proxy actually used, credentials omitted
 * @property {import('./tls/connect.js').TlsSessionInfo | null} tls null for cleartext
 * @property {'1.0' | '1.1'} httpVersion
 * @property {'none' | 'content-length' | 'chunked' | 'until-close'} framing
 */

/**
 * Limits on what a peer may make us buffer. Each is a fail-closed cap, not a hint.
 * @typedef {object} Limits
 * @property {number} [maxHeaderBytes] response head, default 65536
 * @property {number} [maxProxyReplyBytes] proxy CONNECT reply head, default 32768
 */

/**
 * @typedef {object} ClientOptions
 * @property {import('./proxy/index.js').ConnectFn} [connect] Socket factory. Required for any
 *   request the platform's own `fetch` cannot serve — which is every proxied request, and every
 *   request asking for a trust policy `fetch` cannot express.
 * @property {string | import('./proxy/index.js').ProxyConfig | null} [proxy] URL string or
 *   config object; `http:`, `https:`, `socks5:` and `socks5h:`.
 * @property {import('./trust/index.js').TrustConfig} [trust] certificate policy, httpx's
 *   `verify=`. Default `{ mode: 'system' }`.
 * @property {import('./tls/connect.js').TlsOptions} [tls] handshake knobs.
 * @property {import('./util/deadline.js').DeadlineOptions} [timeouts] connect / handshake /
 *   headers / idle / total, in ms. The idle gap is the control; total is a backstop.
 * @property {boolean} [cookies] enable a per-Client cookie jar.
 * @property {import('./client/cookies.js').CookieJar} [jar] supply a jar directly, e.g. to share
 *   one across Clients or to persist it.
 * @property {number} [maxRedirects] default 20.
 * @property {number} [maxBodyBytes] enforced from Content-Length before a byte is read.
 * @property {boolean} [decompress] gzip/deflate. Default true. Never `br`; the runtime cannot
 *   decompress it, so it is never advertised either.
 * @property {boolean} [keepAlive] default true.
 * @property {boolean} [forceTunnel] never delegate to the platform's fetch, even when it could
 *   serve the request. Mainly for exercising this stack against origins that do not need it.
 * @property {FetchLike} [nativeFetch] delegation target; defaults to `globalThis.fetch`.
 * @property {{ maxPerKey?: number, maxTotal?: number }} [pool] connection pool sizing.
 * @property {Limits} [limits]
 * @property {import('./tls/connect.js').TlsDeps} [deps] injectable randomness and key generation.
 * @property {AbortSignal} [signal] aborts every request this Client makes.
 * @property {number} [now] epoch ms override, for certificate validity in tests.
 */

export class Client {
  /**
   * @param {ClientOptions} [options]
   */
  constructor(options = {}) {
    this.options = { ...options };
    this.pool = new ConnectionPool(options.pool);
    this.jar = options.cookies ? (options.jar ?? new CookieJar()) : (options.jar ?? null);
    this._closed = false;
    // Bound so a Client can be handed straight to an SDK expecting a bare function.
    this.fetch = this.fetch.bind(this);
  }

  /**
   * @param {RequestInfo | URL} input
   * @param {RequestInit} [init]
   * @returns {Promise<Response & { tunnelfetch?: ResponseDetail }>}
   */
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
 *
 * @param {ClientOptions} [options]
 * @returns {FetchLike}
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
 *
 * @param {ClientOptions} [options]
 * @returns {() => void} uninstall; idempotent, and a no-op if someone else has since taken the global
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

    // nextRequest owns `history`: it appends this hop's key (for loop detection) and reads the
    // array's length as the hop budget. Pushing here as well would count every hop twice and halve
    // the effective maxRedirects — the `redirected` flag below reads the same array and stays
    // correct because nextRequest appends exactly one entry per redirect followed.
    const next = nextRequest(current, response, { maxRedirects, history });
    // The previous body must be drained (or discarded) before the socket can be reused, and the
    // caller will never read a redirect's body.
    await response.body?.cancel?.().catch(() => {});
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

/**
 * Does this failure prove the peer never saw the request? Only then may it be re-sent.
 *
 * The single provable case is a connection that ended having produced no response byte at all,
 * which is exactly what an idle keep-alive socket the peer had already closed looks like. It
 * surfaces two ways depending on how the peer hung up: a clean close_notify drains the record
 * layer and the head reader hits EOF with nothing buffered, while a bare TCP close makes the
 * record layer refuse the truncation itself. Both report `got: 0`.
 *
 * Everything else must fall through and be reported, a timeout above all: a request that timed out
 * may be executing on the server at this moment, so re-sending it would apply a non-idempotent
 * operation twice — precisely the ambiguous state this package refuses to continue in. Partial
 * bytes disqualify too, because a peer that had begun answering had the request.
 *
 * @param {unknown} err
 * @returns {boolean}
 */
function serverNeverSawIt(err) {
  if (err instanceof UnexpectedEofError) return err.detail?.got === 0;
  return err instanceof TunnelFetchError && err.code === codes.TLS_TRUNCATED && err.detail?.got === 0;
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
    // A reused connection the server had already reaped looks exactly like a truncated response,
    // and re-sending on a fresh connection is the standard remedy. It is only safe, though, when
    // the failure proves the server never saw the request — see serverNeverSawIt().
    if (reused && serverNeverSawIt(err)) {
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

  // The idle deadline wraps the RAW body, before any content decoding. Wrapping the decoded
  // stream instead would judge liveness by decompressed output, and a decompressor legitimately
  // consumes input for a while before producing any — so a healthy stream would look stalled.
  // What "still alive" means is bytes arriving from the peer, which is exactly this stream.
  deadlines.beginIdle();
  const guarded = framing.kind === 'none' ? raw : withIdleDeadline(raw, deadlines);
  const decoded = decodeResponseBody(guarded, headInfo.headers, o);
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

function decodeResponseBody(body, headers, options) {
  if (options.decompress === false) return body;
  const encoding = headers.get('content-encoding');
  if (!encoding) return body;
  return decodeBody(body, encoding);
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

  // Framing is the client's to declare, never the caller's. The body is always buffered whole by
  // performFetch, so every request this client sends is Content-Length-framed and never chunked.
  // A caller-supplied Transfer-Encoding is therefore always a lie (we do not chunk the body), and
  // a caller-supplied Content-Length is at best redundant and at worst a smuggling vector: emitting
  // Content-Length AND Transfer-Encoding together is the exact ambiguity bodyFraming() refuses on
  // the response side (RFC 9112 §6.1: a sender MUST NOT send Content-Length with Transfer-Encoding),
  // and a Content-Length that does not match the bytes written (e.g. one left on a bodyless GET)
  // desynchronises the very next message. Drop both, then state the one truth.
  headers.delete('transfer-encoding');
  if (current.body) headers.set('content-length', String(current.body.byteLength));
  else if (['POST', 'PUT', 'PATCH'].includes(current.method)) headers.set('content-length', '0');
  else headers.delete('content-length');

  const ordered = [['host', hostValue]];
  for (const [k, v] of headers) {
    if (k === 'host') continue;
    ordered.push([k, v]);
  }
  return ordered;
}

export { CookieJar, ConnectionPool, utf8 };
