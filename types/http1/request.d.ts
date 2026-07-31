/**
 * A request head as this serialiser consumes it. Nothing optional is invented: what is absent
 * here is absent on the wire.
 * @typedef {object} RequestHead
 * @property {string} method RFC 9110 token, sent verbatim (no case-folding)
 * @property {string} target request-target, already encoded: origin-form (`/path?q`),
 *   absolute-form, authority-form (CONNECT) or `*`
 * @property {Headers | Iterable<[string, string]>} [headers]
 * @property {'1.0' | '1.1'} [httpVersion] default '1.1'
 */
/**
 * Serialise a request head: request line, header fields, terminating blank line.
 * Throws HttpError on any input the RFC 9110 grammar rejects — notably CR/LF in a value,
 * which is header injection, never something to sanitise.
 *
 * `headers` may be a WHATWG Headers instance or any iterable of [name, value] pairs.
 * Pair iterables are written in caller order, unsorted — order can matter to real servers.
 * Note that a Headers instance has already lost the caller's order by spec (it iterates
 * lowercased and sorted); we serialise its iteration order as-is.
 *
 * @param {RequestHead} req
 * @returns {Uint8Array}
 */
export function serializeRequestHead({ method, target, headers, httpVersion }: RequestHead): Uint8Array;
/**
 * A request head as this serialiser consumes it. Nothing optional is invented: what is absent
 * here is absent on the wire.
 */
export type RequestHead = {
    /**
     * RFC 9110 token, sent verbatim (no case-folding)
     */
    method: string;
    /**
     * request-target, already encoded: origin-form (`/path?q`),
     * absolute-form, authority-form (CONNECT) or `*`
     */
    target: string;
    headers?: Headers | Iterable<[string, string]> | undefined;
    /**
     * default '1.1'
     */
    httpVersion?: "1.0" | "1.1" | undefined;
};
