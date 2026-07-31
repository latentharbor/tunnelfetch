/**
 * @param {number} status
 * @param {string} [method] accepted for API symmetry; the status alone decides, because even a
 *   combination we will rewrite (303 + POST) is still a redirect — it just mutates the method.
 * @returns {boolean}
 */
export function shouldRedirect(status: number, method?: string): boolean;
/**
 * Resolve a Location header against the current URL, enforcing the scheme allow-list.
 * Throws HttpError for a missing/unparseable Location or a non-http(s) scheme.
 * @param {URL} currentUrl
 * @param {string|null|undefined} location
 * @returns {URL}
 */
export function resolveLocation(currentUrl: URL, location: string | null | undefined): URL;
/**
 * A request as the redirect engine consumes it. Bodies stay in whatever form the caller holds
 * them; this layer only decides whether they survive the hop, never reads them.
 * @typedef {Uint8Array | string | ReadableStream<Uint8Array> | null} RedirectBody
 * @typedef {object} RedirectableRequest
 * @property {string} method
 * @property {string | URL} url
 * @property {Headers | Record<string, string>} [headers]
 * @property {RedirectBody} [body]
 */
/**
 * The follow-up request. `url` and `headers` are always normalised instances; `body` is the
 * caller's own value passed through, or null when the method rewrite dropped it.
 * @typedef {object} NextRequest
 * @property {string} method
 * @property {URL} url
 * @property {Headers} headers credential and body-describing headers already stripped per the
 *   rules above
 * @property {RedirectBody} body
 */
/**
 * @typedef {object} NextRequestOptions
 * @property {number} [maxRedirects] default 20
 * @property {string[]} [history] pass the SAME array across every hop of one logical fetch; it
 *   is both the loop detector and the hop counter
 */
/**
 * Compute the follow-up request for a redirect response. Throws rather than returning a
 * failure: LimitError past `maxRedirects`, HttpError for loops and bad Locations, ConfigError
 * for a non-redirect status or an unreplayable stream body on 307/308.
 *
 * @param {RedirectableRequest} current
 * @param {{ status: number, headers: Headers|Record<string,string> }} response
 * @param {NextRequestOptions} [options]
 * @returns {NextRequest}
 */
export function nextRequest(current: RedirectableRequest, response: {
    status: number;
    headers: Headers | Record<string, string>;
}, options?: NextRequestOptions): NextRequest;
export const DEFAULT_MAX_REDIRECTS: 20;
/**
 * A request as the redirect engine consumes it. Bodies stay in whatever form the caller holds
 * them; this layer only decides whether they survive the hop, never reads them.
 */
export type RedirectBody = Uint8Array | string | ReadableStream<Uint8Array> | null;
/**
 * A request as the redirect engine consumes it. Bodies stay in whatever form the caller holds
 * them; this layer only decides whether they survive the hop, never reads them.
 */
export type RedirectableRequest = {
    method: string;
    url: string | URL;
    headers?: Headers | Record<string, string> | undefined;
    body?: RedirectBody | undefined;
};
/**
 * The follow-up request. `url` and `headers` are always normalised instances; `body` is the
 * caller's own value passed through, or null when the method rewrite dropped it.
 */
export type NextRequest = {
    method: string;
    url: URL;
    /**
     * credential and body-describing headers already stripped per the
     * rules above
     */
    headers: Headers;
    body: RedirectBody;
};
export type NextRequestOptions = {
    /**
     * default 20
     */
    maxRedirects?: number | undefined;
    /**
     * pass the SAME array across every hop of one logical fetch; it
     * is both the loop detector and the hop counter
     */
    history?: string[] | undefined;
};
