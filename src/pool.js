// Connection pool for HTTP/1.1 keep-alive.
//
// Scope, stated up front because it is unusual: on the target runtime a socket cannot outlive the
// request that created it — I/O objects do not cross request contexts — so this pool is
// per-Client and deliberately not a global. The win it exists for is the crawl-shaped workload:
// one invocation fetching thirty pages from one host pays one TLS handshake instead of thirty,
// and a userland handshake is the single most expensive thing this package does.
//
// The rule that makes reuse safe, and the one that is worth getting paranoid about:
//
//   A connection returns to the pool ONLY after its response body has been read to the exact end
//   the framing declared. Not "the caller stopped reading", not "it looked finished" — the body's
//   own completion signal. Handing back a socket with unread bytes on it means the next request
//   reads the tail of the previous response and attributes it to the wrong request, which is the
//   worst class of bug an HTTP client can have: it corrupts data silently, under load, and only
//   sometimes.
//
// The second rule follows from the first: a body framed by connection close has no determinate
// end, so such a connection is never eligible, whatever else is true of it.

import { TunnelFetchError, codes } from './errors.js';

/**
 * The trust configuration is part of the key. Two requests to the same origin under different
 * verification policies must not share a connection — the peer was validated under one policy and
 * silently reusing it satisfies the other policy without ever having checked it.
 */
export function poolKey({ scheme, hostname, port, proxy, trust, tls }) {
  const proxyPart = proxy
    ? `${proxy.protocol}://${proxy.username ? `${proxy.username}@` : ''}${proxy.hostname}:${proxy.port}`
    : 'direct';
  const trustPart = trustFingerprint(trust);
  const tlsPart = tls && Object.keys(tls).length ? JSON.stringify(sortedEntries(tls)) : '-';
  return `${scheme}//${hostname}:${port}|${proxyPart}|${trustPart}|${tlsPart}`;
}

function trustFingerprint(trust) {
  const mode = trust?.mode ?? 'system';
  if (mode === 'system') return 'system';
  if (mode === 'none') return 'none';
  if (mode === 'custom') {
    // Two different callbacks are two different policies and we cannot compare functions, so a
    // custom policy never shares a connection. Correct, and cheap: custom trust is rare.
    return `custom:${customCounter(trust.verify)}`;
  }
  if (mode === 'pinned') return `pinned:${[...(trust.pins ?? [])].sort().join(',')}`;
  if (mode === 'anchors') return `anchors:${(trust.anchors ?? []).length}:${anchorDigest(trust.anchors)}`;
  return `unknown:${mode}`;
}

const customIds = new WeakMap();
let customSeq = 0;
function customCounter(fn) {
  if (typeof fn !== 'function') return 'invalid';
  let id = customIds.get(fn);
  if (id === undefined) {
    id = ++customSeq;
    customIds.set(fn, id);
  }
  return id;
}

const anchorDigests = new WeakMap();

/**
 * Order-sensitive digest of anchor material.
 *
 * Every byte is hashed. An earlier version sampled every 97th byte to save work and two anchor
 * sets of equal length that differed only in the middle produced the same key — which would have
 * let a connection validated against one anchor set serve a request that asked for a different
 * one. Cheap-and-approximate is the wrong trade when the output decides whether two security
 * policies are the same policy. The result is memoised per array, so the cost is paid once.
 */
function anchorDigest(anchors = []) {
  const cached = typeof anchors === 'object' ? anchorDigests.get(anchors) : undefined;
  if (cached !== undefined) return cached;

  let h = 0x811c9dc5;
  const mix = (byte) => {
    h = Math.imul(h ^ byte, 0x01000193) >>> 0;
  };
  for (const a of anchors) {
    const isText = typeof a === 'string';
    const len = isText ? a.length : (a?.byteLength ?? 0);
    // Length is folded in separately so concatenation cannot forge an equal digest.
    mix(len & 0xff);
    mix((len >>> 8) & 0xff);
    mix((len >>> 16) & 0xff);
    if (isText) for (let i = 0; i < len; i++) mix(a.charCodeAt(i) & 0xff);
    else for (let i = 0; i < len; i++) mix(a[i]);
    mix(0xff); // separator, so ['ab','c'] and ['a','bc'] differ
  }
  const out = h.toString(16);
  if (typeof anchors === 'object') anchorDigests.set(anchors, out);
  return out;
}

const sortedEntries = (o) => Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1));

export class ConnectionPool {
  /**
   * @param {{ maxPerKey?: number, maxTotal?: number }} [opts]
   */
  constructor({ maxPerKey = 6, maxTotal = 24 } = {}) {
    /** @type {Map<string, Array<{conn: any, since: number}>>} */
    this._idle = new Map();
    this._total = 0;
    this._maxPerKey = maxPerKey;
    this._maxTotal = maxTotal;
    this._closed = false;
    this.stats = { hits: 0, misses: 0, released: 0, discarded: 0, evicted: 0 };
  }

  get idleCount() {
    return this._total;
  }

  /** Take an idle connection for `key`, or null. Most-recently-used first: it is likeliest live. */
  take(key) {
    this._assertOpen();
    const list = this._idle.get(key);
    if (!list || list.length === 0) {
      this.stats.misses++;
      return null;
    }
    const entry = list.pop();
    if (list.length === 0) this._idle.delete(key);
    this._total--;
    this.stats.hits++;
    return entry.conn;
  }

  /**
   * Offer a connection back. Callers must have proven the body reached its declared end; this
   * method cannot verify that and deliberately does not pretend to — `eligible` is the caller's
   * assertion, and the one place it is computed is the HTTP framing layer.
   * @returns {boolean} whether the connection was retained
   */
  release(key, conn, eligible, now = 0) {
    if (this._closed || !eligible) {
      this.stats.discarded++;
      void discard(conn);
      return false;
    }
    const list = this._idle.get(key) ?? [];
    if (list.length >= this._maxPerKey || this._total >= this._maxTotal) {
      // Drop the oldest rather than refusing the newest: the newest is the one just proven alive.
      const victim = list.shift() ?? null;
      if (victim) {
        this._total--;
        this.stats.evicted++;
        void discard(victim.conn);
      } else {
        this.stats.discarded++;
        void discard(conn);
        return false;
      }
    }
    list.push({ conn, since: now });
    this._idle.set(key, list);
    this._total++;
    this.stats.released++;
    return true;
  }

  /** Close and forget one connection that must not be reused. */
  discard(conn) {
    this.stats.discarded++;
    return discard(conn);
  }

  /** Close everything. A Client that is done must call this or sockets leak for the isolate. */
  async closeAll() {
    this._closed = true;
    const all = [];
    for (const list of this._idle.values()) for (const e of list) all.push(e.conn);
    this._idle.clear();
    this._total = 0;
    await Promise.all(all.map(discard));
  }

  _assertOpen() {
    if (this._closed) {
      throw new TunnelFetchError(codes.POOL_CLOSED, 'the connection pool has been closed');
    }
  }
}

async function discard(conn) {
  try {
    await conn?.close?.();
  } catch {
    /* a connection being discarded is already suspect; its close failing changes nothing */
  }
}
