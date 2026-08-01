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
import { acceptEncodingFor, decodeBody } from './client/decode.js';
import { CookieJar } from './client/cookies.js';
import { DEFAULT_MAX_REDIRECTS, nextRequest, shouldRedirect } from './client/redirect.js';
import { ConnectionPool, poolKey } from './pool.js';
import { TicketStore } from './tls/tickets.js';
import { DeadlineController, withIdleDeadline } from './util/deadline.js';
import { nativeFetchCanServe, openConnection, targetFromUrl } from './transport.js';
import { parseProxy } from './proxy/index.js';
import { Http2Connection, Http2Retryable } from './http2/connection.js';
import { ALPN_H2, ALPN_HTTP11 } from './http2/constants.js';

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
 * @property {'1.0' | '1.1' | '2'} httpVersion '2' when ALPN negotiated HTTP/2
 * @property {'none' | 'content-length' | 'chunked' | 'until-close' | 'h2'} framing 'h2' when the
 *   body was delimited by an HTTP/2 END_STREAM rather than by any HTTP/1.1 framing rule
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
 * @property {boolean} [decompress] gzip/deflate. Default true.
 * @property {Record<string, import('./client/decode.js').BodyDecoder>} [decoders] extra
 *   content-codings this client can read, e.g. `{ br: (s) => ... }`. Registering one is what
 *   makes advertising it honest, so each name is appended to Accept-Encoding — a client that
 *   asked for a coding it cannot decode would turn every such response into garbage. `br` and
 *   `zstd` are not built in because the runtime's DecompressionStream has neither and this
 *   package takes no dependencies; supply your own and the cost, and the supply chain, are
 *   yours and visible. Measured on the edge: WASM brotli decodes at about 2x native gzip, and
 *   the wire bytes it saves do not pay that back — see the README. The reason to turn it on is
 *   matching a browser's Accept-Encoding, not saving CPU.
 * @property {boolean} [keepAlive] default true.
 * @property {boolean} [http2] offer HTTP/2 via ALPN and speak it when the server selects it.
 *   Default true. The goal is ACCESS, not speed — some sites treat HTTP/1.1 as a bot signal — and
 *   on a CPU-billed runtime h2 costs MORE than h1 (HPACK is extra work). Set false to offer only
 *   `http/1.1`. There is no fallback-and-retry either way: the server's ALPN pick is followed.
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
    this.options = snapshotOptions(options);
    this.pool = new ConnectionPool(options.pool);
    // HTTP/2 connections are NOT pooled the way h1 is: one connection multiplexes many concurrent
    // streams, so it is not checked out per request. It lives here, keyed exactly like the h1 pool,
    // and is shared until it goes away. See http2/connection.js for why the exclusive-checkout
    // model does not apply. `Map<poolKey, Http2Connection>`.
    /** @type {Map<string, import('./http2/connection.js').Http2Connection>} */
    this._h2 = new Map();
    // Every live h2 connection, keyed map or not. The map holds the one CURRENTLY dispatchable
    // connection per key; if two first-requests to a new key race, the loser is orphaned from the
    // map but is still open and serving its stream, so it must be tracked here or close() would
    // leak it. Entries remove themselves on death.
    /** @type {Set<import('./http2/connection.js').Http2Connection>} */
    this._h2conns = new Set();
    this.jar = options.cookies ? (options.jar ?? new CookieJar()) : (options.jar ?? null);
    // TLS 1.3 session tickets, per-Client for the same reason the pool is: a ticket is a
    // credential bound to a trust configuration, and it is stored and looked up under the SAME
    // key the pool uses, so a ticket can never resume a session for a request whose scheme,
    // host, port, proxy, trust policy or TLS options differ from the connection that earned it.
    // `options.now` (the test override for certificate validity) drives ticket ages too — the
    // two are the same clock question.
    this.tickets = new TicketStore(
      typeof options.now === 'number' ? { now: () => options.now } : {},
    );
    this._closed = false;
    // Response bodies that have not finished arriving. `fetch` resolves at the response HEAD, so a
    // caller holding a Response may still be streaming over a connection this Client owns — and on
    // HTTP/2 that connection is SHARED and torn down by close(), not checked out of the pool the
    // way an h1 socket is. Anything that decides when a Client is done needs to see these.
    /** @type {Set<Promise<void>>} */
    this._inflight = new Set();
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

  /**
   * Resolve once every response body handed out by this Client has finished, one way or another —
   * read to the end, cancelled, or failed. Deliberately NOT folded into close(): close() is the
   * forceful teardown, and a teardown that waits on the streams it is tearing down would hang on
   * any body the caller abandoned. This is for callers that want the graceful order.
   *
   * Looping rather than a single Promise.all because a body settling can start another (a redirect
   * drains its predecessor), and a set sampled once would miss the successor.
   */
  async idle() {
    while (this._inflight.size) await Promise.all([...this._inflight]);
  }

  /** Release every pooled socket and shared HTTP/2 connection. A Client that is finished must be
   *  closed or sockets leak for the isolate's lifetime. */
  async close() {
    this._closed = true;
    this.tickets.clear(); // tickets are credentials; a closed Client keeps none
    const h2 = [...this._h2conns]; // the set, not the map: it also holds race-orphaned connections
    this._h2.clear();
    this._h2conns.clear();
    await Promise.all([this.pool.closeAll(), ...h2.map((c) => c.close().catch(() => {}))]);
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
    let response;
    try {
      response = await client.fetch(input, init);
    } catch (err) {
      await client.close();
      throw err;
    }
    // NOT `finally { await client.close() }`. `fetch` resolves when the response HEAD arrives and
    // the body is still on the wire, so closing here tore down the connection out from under the
    // caller — invisibly on HTTP/1.1, where the socket is checked out of the pool and closeAll()
    // could not reach it, but fatally on HTTP/2, where the connection is shared and close() ends
    // every stream on it. `res.text()` then failed with HTTP2_PROTOCOL.
    //
    // Not awaited, or this would deadlock: the body only drains when the caller reads it, and the
    // caller cannot read a Response that has not been returned yet.
    //
    // A caller who neither reads nor cancels the body would leave the Client open — the same leak
    // as forgetting to close one — except that the idle deadline aborts a stalled body, which
    // settles the completion and fires this anyway.
    void client.idle().then(() => client.close().catch(() => {}));
    return response;
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

  // 1. An existing shared HTTP/2 connection for this key multiplexes this request as a new stream.
  const shared = client._h2.get(key);
  if (shared && shared.canDispatch()) {
    const deadlines = new DeadlineController(o.timeouts ?? {}, { signal: o.signal });
    try {
      return await sendAndReceiveH2(client, shared, current, { deadlines });
    } catch (err) {
      deadlines.dispose();
      // A provably-unprocessed stream (GOAWAY past it, REFUSED_STREAM) is the h2 analogue of h1's
      // "server never saw it": safe to re-send on a fresh connection. Anything else propagates.
      if (!(err instanceof Http2Retryable)) throw err;
    }
  }

  // 2. A pooled HTTP/1.1 connection, taken exclusively for this one request.
  const pooled = client.pool.take(key);
  if (pooled) {
    const deadlines = new DeadlineController(o.timeouts ?? {}, { signal: o.signal });
    try {
      return await sendAndReceive(client, pooled, current, { key, deadlines, reused: true, hop });
    } catch (err) {
      deadlines.dispose();
      await client.pool.discard(pooled);
      throw err;
    }
  }

  // 3. A fresh connection. Its negotiated ALPN — not a guess, not a retry — decides h2 or h1.
  return openFreshAndSend(client, current, { hop, key, proxy, trust, tls });
}

/**
 * Open a new connection for `key` and dispatch the request over whichever protocol ALPN selected.
 * There is no reconnect-and-retry-lower anywhere: the server picked, and we speak that.
 */
async function openFreshAndSend(client, current, { hop, key, proxy, trust, tls }) {
  const o = client.options;
  const deadlines = new DeadlineController(o.timeouts ?? {}, { signal: o.signal });
  // Offer h2 unless the caller disabled it or pinned their own ALPN list. Newest first: ALPN is a
  // client preference list and the server chooses from it.
  const alpn = tls.alpn ?? (o.http2 === false ? [ALPN_HTTP11] : [ALPN_H2, ALPN_HTTP11]);
  let conn;
  let isH2 = false;
  try {
    conn = await openConnection({
      url: current.url,
      connect: o.connect,
      proxy,
      trust,
      tls,
      alpn,
      resumption: resumptionFor(client, key),
      deps: o.deps,
      deadlines,
      limits: o.limits ?? {},
      now: o.now,
    });
    if (conn.info.tls?.alpnProtocol === ALPN_H2) {
      isH2 = true;
      const h2 = registerHttp2(client, key, conn);
      return await sendAndReceiveH2(client, h2, current, { deadlines });
    }
    return await sendAndReceive(client, conn, current, { key, deadlines, reused: false, hop });
  } catch (err) {
    deadlines.dispose();
    // An h2 connection owns its own duplex and deregisters itself on death (registerHttp2's
    // onClose); a stream-level failure leaves it healthy and registered for reuse, so it must not
    // be discarded here. Only the h1 socket is the pool's to throw away.
    if (conn && !isH2) await client.pool.discard(conn);
    throw err;
  }
}

/**
 * Session-resumption wiring for one connection attempt: the freshest usable ticket stored under
 * this pool key (consumed now, single-use), and the capture callback that files new tickets
 * under the same key. That the offer and the capture share the connection's own pool key is the
 * entire safety argument — a ticket can only ever be replayed to the exact
 * scheme/host/port/proxy/trust/tls tuple that earned it.
 *
 * One policy carve-out: under `revocation: 'require-staple'` resumption is disabled outright
 * (nothing stored, nothing offered). That caller demanded a stapled revocation proof on every
 * connection, and a resumed handshake carries no certificate and therefore no staple — resuming
 * would silently skip the exact check that was made mandatory. Costs one full handshake per
 * connection, which is precisely what that trust posture asks for.
 *
 * @param {Client} client
 * @param {string} key
 * @returns {{ offer: object | null, onTicket: (t: object) => void } | undefined}
 */
function resumptionFor(client, key) {
  const trust = client.options.trust ?? { mode: 'system' };
  if (trust.revocation === 'require-staple') return undefined;
  // Keyed by the FULL pool key, which already folds scheme, host, port, proxy, trust policy and
  // TLS options — for exactly the reason the pool does it. A ticket is a credential: one obtained
  // under a pinned or custom trust policy must never resume a connection for a caller who asked
  // for something else, and keying by origin alone is precisely how that happens.
  return {
    offer: client.tickets.take(key),
    onTicket: (t) => {
      if (!client._closed) client.tickets.put(key, t);
    },
  };
}

/** Wrap a freshly negotiated h2 connection, register it for reuse, and arrange its own removal. */
function registerHttp2(client, key, conn) {
  const h2 = new Http2Connection(
    { readable: conn.readable, writable: conn.writable, close: conn.close },
    {
      info: conn.info,
      onClose: () => {
        client._h2conns.delete(h2);
        // Only drop the keyed entry if it is still this connection; a newer one may have replaced it.
        if (client._h2.get(key) === h2) client._h2.delete(key);
      },
    },
  );
  client._h2conns.add(h2);
  client._h2.set(key, h2);
  return h2;
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
/**
 * Take a private, frozen copy of the security-relevant configuration.
 *
 * `{ ...options }` is a SHALLOW copy, so `client.options.trust` stayed the caller's own object: a
 * caller could flip `revocation` or swap `pins` after construction and the next request would run
 * under the new policy over a pool of connections verified under the old one. The pool key covers
 * every field the verifier reads (see trustFingerprint), but a key computed from a mutable object
 * is only as stable as the object.
 *
 * `proxy` is deliberately NOT frozen: openTunnel treats a frozen proxy as already normalised and
 * skips parseProxy, so freezing a raw object here would bypass its validation entirely. Proxy
 * identity is part of the pool key on its own, so a changed proxy gets a different key regardless.
 *
 * @param {ClientOptions} options
 * @returns {Readonly<ClientOptions>}
 */
function snapshotOptions(options) {
  const o = { ...options };
  if (o.trust && typeof o.trust === 'object') {
    const t = { ...o.trust };
    if (Array.isArray(t.pins)) t.pins = Object.freeze([...t.pins]);
    if (Array.isArray(t.anchors)) t.anchors = Object.freeze([...t.anchors]);
    o.trust = Object.freeze(t);
  }
  if (o.tls && typeof o.tls === 'object') o.tls = Object.freeze({ ...o.tls });
  if (o.timeouts && typeof o.timeouts === 'object') o.timeouts = Object.freeze({ ...o.timeouts });
  return Object.freeze(o);
}

/**
 * Remember a body until it settles. Never rejects: a failed body is still a finished one, and this
 * set exists to answer "is anything still arriving", not "did it go well".
 */
function trackBody(client, completed) {
  const settled = completed.then(
    () => {},
    () => {},
  );
  client._inflight.add(settled);
  settled.then(() => client._inflight.delete(settled));
}

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
        resumption: resumptionFor(client, key),
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
  trackBody(client, raw.completed);
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

// ------------------------------------------------------------------ one request/response over h2

/**
 * The HTTP/2 counterpart of sendAndReceive. The connection is shared, so nothing here checks it
 * out or returns it — the stream id keeps this response's bytes separate from every other stream's.
 * The two load-bearing invariants from the h1 path are preserved deliberately: the idle deadline
 * wraps the RAW body before any content decoding, and the completion of the body disposes the
 * per-request deadline (it just never releases a connection, because the connection is not ours to
 * release).
 */
async function sendAndReceiveH2(client, h2, current, { deadlines }) {
  const o = client.options;
  const target = targetFromUrl(current.url);
  const { authority, headers } = buildH2Request(client, current, target);

  deadlines.beginPhase('headers');
  let head;
  try {
    head = await deadlines.race(
      h2.request({
        method: current.method,
        scheme: current.url.protocol === 'https:' ? 'https' : 'http',
        authority,
        path: requestTarget(current.url) || '/',
        headers,
        body: current.body ?? null,
        // The deadline's signal reaches into the connection so a headers/idle timeout resets
        // exactly this one stream (RST_STREAM), never the shared connection or its other streams.
        signal: deadlines.signal,
      }),
    );
  } finally {
    deadlines.endPhase();
  }

  if (client.jar && head.setCookie?.length) {
    client.jar.setFromResponse(current.url, head.setCookie);
  }

  const raw = head.body;
  // Dispose the per-request deadline once the body is done, however it ends. Unlike h1 there is no
  // pool.release: the connection stays shared and alive for the next stream.
  trackBody(client, raw.completed);
  raw.completed.then(
    () => deadlines.dispose(),
    () => deadlines.dispose(),
  );

  // Same invariant as h1: the idle deadline wraps the RAW body, before content decoding, so
  // liveness is judged by bytes arriving from the peer rather than by decompressed output.
  deadlines.beginIdle();
  const guarded = withIdleDeadline(raw, deadlines);
  const decoded = decodeResponseBody(guarded, head.headers, o);
  const framing = { kind: 'h2', keepAliveEligible: false };
  return buildResponse(head, decoded, framing, h2);
}

/**
 * Build the HTTP/2 request: the :authority value, and the ordered regular header fields with the
 * pseudo-headers and every connection-specific field removed (RFC 9113 s8.2.2). Framing is the
 * client's to declare here just as in h1 — Transfer-Encoding has no meaning in h2 and is dropped,
 * and Content-Length is set for a body so it matches what curl sends.
 */
function buildH2Request(client, current, target) {
  const o = client.options;
  const headers = new Headers(current.headers);
  const defaultPort = current.url.protocol === 'https:' ? 443 : 80;
  const authority =
    target.port === defaultPort ? current.url.hostname : `${current.url.hostname}:${target.port}`;

  if (!headers.has('accept')) headers.set('accept', '*/*');
  if (!headers.has('accept-encoding') && o.decompress !== false) {
    headers.set('accept-encoding', acceptEncodingFor(o.decoders));
  }
  if (client.jar) {
    const cookie = client.jar.headerFor(current.url);
    if (cookie) {
      const existing = headers.get('cookie');
      headers.set('cookie', existing ? `${existing}; ${cookie}` : cookie);
    }
  }
  // Connection-specific header fields are forbidden in HTTP/2 and are the sender's to strip.
  for (const name of ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'host']) {
    headers.delete(name);
  }
  if (current.body) headers.set('content-length', String(current.body.byteLength));
  else if (['POST', 'PUT', 'PATCH'].includes(current.method)) headers.set('content-length', '0');
  else headers.delete('content-length');

  // Headers iterates lowercased (RFC 9113 s8.2.1 requires lowercase names on the wire) — which is
  // also why h1 loses caller order; h2 is no different here. Pseudo-header ORDER, the part a
  // fingerprinter reads, is fixed in http2/connection.js buildRequestFields, not here.
  const out = [];
  for (const [k, v] of headers) out.push([k, v]);
  return { authority, headers: out };
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
  return decodeBody(body, encoding, options.decoders ?? null);
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
    headers.set('accept-encoding', acceptEncodingFor(client.options.decoders));
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
