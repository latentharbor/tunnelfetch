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
export function callerHeaderOrder(input: RequestInfo | URL, init?: RequestInit): Array<[string, string]> | null;
/**
 * Default request header order, from curl 8.21.0 on the wire. `'*'` is where headers not named
 * here go, in the order they were given — which is where curl puts the caller's own.
 */
export const CURL_HEADER_ORDER: readonly string[];
/**
 * An ordered, case-preserving header list.
 *
 * Deliberately not a `Headers` subclass and deliberately not backed by one: the whole point is to
 * be the thing `Headers` is not. Lookup and mutation are case-insensitive, as HTTP requires;
 * iteration returns names exactly as they were written, in the order they arrived.
 */
export class OrderedHeaders {
    /** @param {Headers | Iterable<[string, string]> | Record<string, string> | null} [init] */
    constructor(init?: Headers | Iterable<[string, string]> | Record<string, string> | null);
    /** @type {Array<[string, string]>} name as written, value */
    _list: Array<[string, string]>;
    _indexOf(name: any): number;
    has(name: any): boolean;
    /** Comma-joined when a field appears more than once, matching `Headers.get`. */
    get(name: any): string | null;
    /**
     * Replace IN PLACE when the field is already present, so setting a value does not move a header
     * to the end and silently reorder the request. A caller who wrote `User-Agent` first and then
     * had it overwritten should still see it first.
     */
    set(name: any, value: any): void;
    append(name: any, value: any): void;
    delete(name: any): void;
    /**
     * Put the fields into `order`, which names lowercased header names and may contain `'*'` to mark
     * where everything unnamed goes. Fields keep their relative order within each group, so a
     * caller's own sequence survives.
     *
     * @param {readonly string[]} order
     */
    reorder(order: readonly string[]): void;
    /** @returns {Array<[string, string]>} names as written, in order */
    entries(): Array<[string, string]>;
    /** Lowercased names, for HTTP/2 where RFC 9113 s8.2.1 requires them. */
    lowercased(): string[][];
    [Symbol.iterator](): ArrayIterator<[string, string]>;
}
