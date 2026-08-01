// Request header order and case — the part of a fingerprint that needs no TLS inspection at all.
//
// The platform's `Headers` is the wrong wire representation and always was: it iterates
// lexicographically sorted and lowercased. So a request built through it goes out as
// `accept, accept-encoding, connection, host, referer, user-agent` whatever the caller wrote —
// alphabetical order, with `user-agent` last, which no real client does. curl sends:
//
//   Host, User-Agent, Accept, Accept-Encoding, <the caller's headers, in order>,
//   Content-Length, Content-Type
//
// captured off the wire from curl 8.21.0. Note where the framing headers go: last, AFTER the
// caller's. That is why the default order below carries a `'*'` marker rather than being a plain
// ranking — "everything else" belongs in the middle, not at the end.
//
// Case matters too, and only on HTTP/1.1: real clients send `Host:` and `X-Custom:`, not `host:`
// and `x-custom:`. HTTP/2 is the opposite — RFC 9113 s8.2.1 REQUIRES lowercase field names, and a
// server must treat an uppercase one as malformed. So this preserves the case it was given and the
// h2 path lowercases at the last moment, which is the only place that is correct.

import { HttpError, codes } from '../errors.js';

/**
 * Default request header order, from curl 8.21.0 on the wire. `'*'` is where headers not named
 * here go, in the order they were given — which is where curl puts the caller's own.
 */
export const CURL_HEADER_ORDER = Object.freeze([
  'host',
  'user-agent',
  'accept',
  'accept-encoding',
  '*',
  // curl sends no Connection on HTTP/1.1 (keep-alive is the default and it stays silent), so
  // there is no reference position for it. Grouped with the other connection-and-framing headers
  // at the end, which is where curl puts the ones it does send.
  'connection',
  'content-length',
  'content-type',
]);

/**
 * An ordered, case-preserving header list.
 *
 * Deliberately not a `Headers` subclass and deliberately not backed by one: the whole point is to
 * be the thing `Headers` is not. Lookup and mutation are case-insensitive, as HTTP requires;
 * iteration returns names exactly as they were written, in the order they arrived.
 */
export class OrderedHeaders {
  /** @param {Headers | Iterable<[string, string]> | Record<string, string> | null} [init] */
  constructor(init = null) {
    /** @type {Array<[string, string]>} name as written, value */
    this._list = [];
    if (init == null) return;
    const pairs =
      typeof (/** @type {any} */ (init)[Symbol.iterator]) === 'function'
        ? /** @type {Iterable<[string, string]>} */ (init)
        : Object.entries(init);
    for (const [name, value] of pairs) this.append(name, value);
  }

  _indexOf(name) {
    const lower = String(name).toLowerCase();
    return this._list.findIndex(([n]) => n.toLowerCase() === lower);
  }

  has(name) {
    return this._indexOf(name) !== -1;
  }

  /** Comma-joined when a field appears more than once, matching `Headers.get`. */
  get(name) {
    const lower = String(name).toLowerCase();
    const hits = this._list.filter(([n]) => n.toLowerCase() === lower).map(([, v]) => v);
    return hits.length ? hits.join(', ') : null;
  }

  /**
   * Replace IN PLACE when the field is already present, so setting a value does not move a header
   * to the end and silently reorder the request. A caller who wrote `User-Agent` first and then
   * had it overwritten should still see it first.
   */
  set(name, value) {
    const at = this._indexOf(name);
    if (at === -1) {
      this.append(name, value);
      return;
    }
    this._list[at] = [this._list[at][0], String(value)];
    // A repeated field collapses to the first position, as `Headers.set` collapses to one value.
    const lower = String(name).toLowerCase();
    this._list = this._list.filter(([n], i) => i === at || n.toLowerCase() !== lower);
  }

  append(name, value) {
    const n = String(name);
    if (n === '') throw new HttpError(codes.HTTP_HEADER, 'header name must not be empty', { name });
    this._list.push([n, String(value)]);
  }

  delete(name) {
    const lower = String(name).toLowerCase();
    this._list = this._list.filter(([n]) => n.toLowerCase() !== lower);
  }

  /**
   * Put the fields into `order`, which names lowercased header names and may contain `'*'` to mark
   * where everything unnamed goes. Fields keep their relative order within each group, so a
   * caller's own sequence survives.
   *
   * @param {readonly string[]} order
   */
  reorder(order) {
    const star = order.indexOf('*');
    const rank = new Map();
    order.forEach((name, i) => {
      if (name !== '*') rank.set(name, i);
    });
    // With no '*', unnamed fields go last — the same rule the TLS extension order uses.
    const fallback = star === -1 ? order.length : star;
    this._list = this._list
      .map((entry, i) => ({ entry, i, r: rank.get(entry[0].toLowerCase()) ?? fallback }))
      .sort((a, b) => a.r - b.r || a.i - b.i)
      .map((x) => x.entry);
  }

  /** @returns {Array<[string, string]>} names as written, in order */
  entries() {
    return this._list.map(([n, v]) => [n, v]);
  }

  /** Lowercased names, for HTTP/2 where RFC 9113 s8.2.1 requires them. */
  lowercased() {
    return this._list.map(([n, v]) => [n.toLowerCase(), v]);
  }

  [Symbol.iterator]() {
    return this.entries()[Symbol.iterator]();
  }
}

/**
 * Read the caller's header names in the order and case they wrote them, BEFORE anything hands them
 * to `Request`, which is where both are lost.
 *
 * Recovers what is recoverable and no more: an array of pairs or a plain object still carries the
 * caller's order, a `Headers` or a `Request` does not — those were normalised before this package
 * ever saw them, and there is nothing here to reconstruct.
 *
 * @param {RequestInfo | URL} input
 * @param {RequestInit} [init]
 * @returns {Array<[string, string]> | null} null when the caller's order was already gone
 */
export function callerHeaderOrder(input, init) {
  const raw = init?.headers ?? (input instanceof Request ? null : undefined);
  if (raw == null) return null;
  if (typeof Headers !== 'undefined' && raw instanceof Headers) return null;
  if (Array.isArray(raw)) return raw.map(([n, v]) => [String(n), String(v)]);
  if (typeof raw === 'object') return Object.entries(raw).map(([n, v]) => [n, String(v)]);
  return null;
}
