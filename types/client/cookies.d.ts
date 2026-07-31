/**
 * Parse a cookie date per RFC 6265 s5.1.1 — NOT Date.parse. Date.parse accepts formats the
 * RFC rejects, rejects formats the RFC accepts (two-digit years, odd delimiters), and differs
 * between engines; cookies from 1990s-era servers still use every shape the RFC grandfathers.
 *
 * The algorithm: split into tokens on "delimiters", then find — in any order, first match per
 * category wins — a time (hh:mm:ss), a day (1-2 digits), a month (3-letter name), and a year
 * (2-4 digits). Each token may carry trailing non-digit junk after the match.
 *
 * @param {string} s
 * @returns {number|null} epoch milliseconds UTC, or null if the string is not a cookie date.
 */
export function parseCookieDate(s: string): number | null;
/**
 * RFC 6265 s5.1.4: the default path is the request path up to (not including) its last '/'.
 * @param {string} requestPath
 * @returns {string}
 */
export function defaultPath(requestPath: string): string;
/**
 * RFC 6265 s5.1.4 path-match.
 * @param {string} requestPath
 * @param {string} cookiePath
 * @returns {boolean}
 */
export function pathMatches(requestPath: string, cookiePath: string): boolean;
/**
 * RFC 6265 s5.1.3 domain-match: exact, or host ends with '.' + domain.
 * @param {string} host
 * @param {string} cookieDomain
 * @returns {boolean}
 */
export function domainMatches(host: string, cookieDomain: string): boolean;
/**
 * A stored cookie, as entries() exposes it. Records are live jar state, not copies.
 * @typedef {object} Cookie
 * @property {string} name
 * @property {string} value quotes already stripped
 * @property {string} domain lowercased; the Domain attribute, or the request host
 * @property {boolean} hostOnly true when no Domain attribute applied — exact-host match only
 * @property {string} path
 * @property {boolean} secure
 * @property {boolean} httpOnly
 * @property {string | null} sameSite lowercased attribute value, stored verbatim — servers send
 *   values outside strict/lax/none and this jar does not enforce SameSite anyway
 * @property {number} expiry epoch ms; Infinity for a session cookie
 * @property {number} creation epoch ms from the injected clock, kept across overwrites (s5.3)
 * @property {number} seq creation-order tiebreak for the frozen-clock runtime
 */
/**
 * @typedef {object} CookieJarOptions
 * @property {() => number} [now] injectable clock returning epoch ms. On the target runtime
 *   Date.now() freezes for a whole execution slice, so expiry must be testable via this knob.
 * @property {number} [maxCookies] global cap, default 3000
 * @property {number} [maxPerDomain] per-domain cap, default 50
 */
export class CookieJar {
    /**
     * @param {CookieJarOptions} [options]
     *   The caps exist because this jar lives inside a long-lived Worker isolate: an unbounded
     *   jar fed by a hostile or merely enthusiastic server is a slow memory leak, so overflow
     *   evicts the oldest cookies instead of growing.
     */
    constructor({ now, maxCookies, maxPerDomain }?: CookieJarOptions);
    _now: () => number;
    _maxCookies: number;
    _maxPerDomain: number;
    /** @type {Map<string, Cookie>} key "domain|path|name" -> cookie record */
    _cookies: Map<string, Cookie>;
    _rejected: number;
    /** Count of Set-Cookie values ignored per RFC rules — the observability hook. */
    get rejected(): number;
    get size(): number;
    /**
     * Ingest the Set-Cookie values of one response. Never throws on a bad cookie — rejection is
     * silent per RFC 6265, counted in `rejected`.
     * @param {string|URL} url the request URL the response belongs to
     * @param {string[]} setCookieValues one array entry per Set-Cookie header
     * @returns {void}
     */
    setFromResponse(url: string | URL, setCookieValues: string[]): void;
    /**
     * @param {string} host
     * @param {boolean} requestSecure
     * @param {string} requestPath
     * @param {string} setCookie
     * @returns {boolean} stored or deliberately deleted (true) vs ignored (false)
     */
    _setOne(host: string, requestSecure: boolean, requestPath: string, setCookie: string): boolean;
    /**
     * Evict expired cookies first, then the oldest by creation, per-domain then globally.
     * @param {string} domain
     */
    _enforceCaps(domain: string): void;
    /**
     * The Cookie header value for a request, or null if no cookie matches.
     * @param {string|URL} url
     * @returns {string | null}
     */
    headerFor(url: string | URL): string | null;
    /**
     * Everything currently stored, for tests and debugging. Records are live; do not mutate.
     * @returns {Cookie[]}
     */
    entries(): Cookie[];
}
/**
 * A stored cookie, as entries() exposes it. Records are live jar state, not copies.
 */
export type Cookie = {
    name: string;
    /**
     * quotes already stripped
     */
    value: string;
    /**
     * lowercased; the Domain attribute, or the request host
     */
    domain: string;
    /**
     * true when no Domain attribute applied — exact-host match only
     */
    hostOnly: boolean;
    path: string;
    secure: boolean;
    httpOnly: boolean;
    /**
     * lowercased attribute value, stored verbatim — servers send
     * values outside strict/lax/none and this jar does not enforce SameSite anyway
     */
    sameSite: string | null;
    /**
     * epoch ms; Infinity for a session cookie
     */
    expiry: number;
    /**
     * epoch ms from the injected clock, kept across overwrites (s5.3)
     */
    creation: number;
    /**
     * creation-order tiebreak for the frozen-clock runtime
     */
    seq: number;
};
export type CookieJarOptions = {
    /**
     * injectable clock returning epoch ms. On the target runtime
     * Date.now() freezes for a whole execution slice, so expiry must be testable via this knob.
     */
    now?: (() => number) | undefined;
    /**
     * global cap, default 3000
     */
    maxCookies?: number | undefined;
    /**
     * per-domain cap, default 50
     */
    maxPerDomain?: number | undefined;
};
