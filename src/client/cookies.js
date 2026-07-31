// RFC 6265 cookie jar, DOM-free.
//
// Two discipline points shape this file:
//
// 1. Rejection is silent BY SPECIFICATION. RFC 6265 says a UA that dislikes a Set-Cookie
//    (domain mismatch, Secure over http, bare-TLD domain) ignores it and moves on — erroring
//    would let any response header abort the fetch. Silent is not invisible, though: every
//    ignored cookie increments `jar.rejected`, because "why is my session cookie missing"
//    is otherwise undebuggable.
//
// 2. The clock is injected. On the target runtime Date.now() is frozen during synchronous
//    execution and only advances across I/O, so expiry logic that calls Date.now() directly
//    is untestable there and subtly wrong in production. Everything time-shaped goes through
//    `this._now()`.

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
export function parseCookieDate(s) {
  // Delimiter set per the RFC: %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E.
  const tokens = s.split(/[\x09\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+/).filter((t) => t !== '');
  const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  let time = null;
  let day = null;
  let month = null;
  let year = null;
  for (const tok of tokens) {
    // Order of checks mirrors the RFC: time, day, month, year; a token is consumed by the
    // first category it matches AND that is still unset.
    if (time === null) {
      const m = /^(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\D.*)?$/.exec(tok);
      if (m) {
        time = [Number(m[1]), Number(m[2]), Number(m[3])];
        continue;
      }
    }
    if (day === null) {
      const m = /^(\d{1,2})(?:\D.*)?$/.exec(tok);
      if (m) {
        day = Number(m[1]);
        continue;
      }
    }
    if (month === null) {
      const idx = MONTHS.indexOf(tok.slice(0, 3).toLowerCase());
      if (idx >= 0) {
        month = idx;
        continue;
      }
    }
    if (year === null) {
      const m = /^(\d{2,4})(?:\D.*)?$/.exec(tok);
      if (m) {
        year = Number(m[1]);
        continue;
      }
    }
  }
  if (time === null || day === null || month === null || year === null) return null;
  // Two-digit pivot: 70-99 are 19xx, 00-69 are 20xx. Three-digit years are not a thing the
  // RFC recognises; a "year" of 100-1600 falls to the <1601 floor below.
  if (year >= 70 && year <= 99) year += 1900;
  else if (year >= 0 && year <= 69) year += 2000;
  const [hh, mm, ss] = time;
  if (day < 1 || day > 31 || year < 1601 || hh > 23 || mm > 59 || ss > 59) return null;
  const ms = Date.UTC(year, month, day, hh, mm, ss);
  // Date.UTC rolls over out-of-range days (Feb 31 -> Mar 3); the RFC treats those as simply
  // "some date", and rollover is what every UA ships, so we accept the rolled value.
  return ms;
}

/**
 * RFC 6265 s5.1.4: the default path is the request path up to (not including) its last '/'.
 * @param {string} requestPath
 * @returns {string}
 */
export function defaultPath(requestPath) {
  if (!requestPath || requestPath[0] !== '/') return '/';
  const cut = requestPath.lastIndexOf('/');
  return cut === 0 ? '/' : requestPath.slice(0, cut);
}

/**
 * RFC 6265 s5.1.4 path-match.
 * @param {string} requestPath
 * @param {string} cookiePath
 * @returns {boolean}
 */
export function pathMatches(requestPath, cookiePath) {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  // Prefix match counts only when the boundary is a '/', so /foo does not match /foobar.
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

/**
 * RFC 6265 s5.1.3 domain-match: exact, or host ends with '.' + domain.
 * @param {string} host
 * @param {string} cookieDomain
 * @returns {boolean}
 */
export function domainMatches(host, cookieDomain) {
  if (host === cookieDomain) return true;
  return host.endsWith('.' + cookieDomain);
}

/** Very loose IPv4/IPv6 literal check — a suffix "domain match" on an IP makes no sense. */
const looksLikeIp = (host) =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':') || /^\[.*\]$/.test(host);

let seqCounter = 0; // creation-order tiebreak; the injected clock may legally stand still

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
  constructor({ now = () => Date.now(), maxCookies = 3000, maxPerDomain = 50 } = {}) {
    this._now = now;
    this._maxCookies = maxCookies;
    this._maxPerDomain = maxPerDomain;
    /** @type {Map<string, Cookie>} key "domain|path|name" -> cookie record */
    this._cookies = new Map();
    this._rejected = 0;
  }

  /** Count of Set-Cookie values ignored per RFC rules — the observability hook. */
  get rejected() {
    return this._rejected;
  }

  get size() {
    return this._cookies.size;
  }

  /**
   * Ingest the Set-Cookie values of one response. Never throws on a bad cookie — rejection is
   * silent per RFC 6265, counted in `rejected`.
   * @param {string|URL} url the request URL the response belongs to
   * @param {string[]} setCookieValues one array entry per Set-Cookie header
   * @returns {void}
   */
  setFromResponse(url, setCookieValues) {
    const u = url instanceof URL ? url : new URL(url);
    const host = u.hostname.toLowerCase();
    const secure = u.protocol === 'https:';
    for (const value of setCookieValues) {
      if (!this._setOne(host, secure, u.pathname, value)) this._rejected++;
    }
  }

  /**
   * @param {string} host
   * @param {boolean} requestSecure
   * @param {string} requestPath
   * @param {string} setCookie
   * @returns {boolean} stored or deliberately deleted (true) vs ignored (false)
   */
  _setOne(host, requestSecure, requestPath, setCookie) {
    if (typeof setCookie !== 'string') return false;
    const semi = setCookie.indexOf(';');
    const pair = semi === -1 ? setCookie : setCookie.slice(0, semi);
    // RFC 6265 s5.2: no '=' in the name-value pair means ignore the whole thing.
    const eq = pair.indexOf('=');
    if (eq === -1) return false;
    const name = pair.slice(0, eq).trim();
    let value = pair.slice(eq + 1).trim();
    if (name === '') return false;
    // Control characters in name or value are a smuggling vector, not a cookie.
    if (/[\x00-\x1f\x7f]/.test(name) || /[\x00-\x1f\x7f]/.test(value)) return false;
    if (/[\s;,]/.test(name)) return false;
    // A quoted value is stored with its quotes stripped, matching what UAs send back.
    if (value.length >= 2 && value[0] === '"' && value.at(-1) === '"') value = value.slice(1, -1);

    // ---- attributes: names case-insensitive, LAST occurrence of each wins, unknown ignored.
    let maxAge = null; // seconds, may be <= 0
    let expires = null; // epoch ms
    let domainAttr = null;
    let pathAttr = null;
    let secure = false;
    let httpOnly = false;
    let sameSite = null;
    if (semi !== -1) {
      for (const rawAttr of setCookie.slice(semi + 1).split(';')) {
        const aeq = rawAttr.indexOf('=');
        const aname = (aeq === -1 ? rawAttr : rawAttr.slice(0, aeq)).trim().toLowerCase();
        const avalue = aeq === -1 ? '' : rawAttr.slice(aeq + 1).trim();
        switch (aname) {
          case 'expires': {
            const t = parseCookieDate(avalue);
            // An unparseable date means "ignore this attribute", never "reject the cookie":
            // the RFC's error recovery is per-attribute.
            if (t !== null) expires = t;
            break;
          }
          case 'max-age': {
            // s5.2.2: first char must be a digit or '-', remainder digits; anything else
            // means ignore the attribute (Max-Age=forever is not an error, it is noise).
            if (/^-?\d+$/.test(avalue)) maxAge = Number(avalue);
            break;
          }
          case 'domain': {
            if (avalue !== '') domainAttr = avalue.replace(/^\./, '').toLowerCase();
            break;
          }
          case 'path': {
            pathAttr = avalue;
            break;
          }
          case 'secure':
            secure = true;
            break;
          case 'httponly':
            httpOnly = true;
            break;
          case 'samesite':
            sameSite = avalue.toLowerCase();
            break;
          default:
            // Unknown attributes are explicitly ignored (s5.2 last paragraph).
            break;
        }
      }
    }

    // Secure cookies may only be SET over https, not just sent over it — otherwise an http
    // man-in-the-middle can plant a cookie the application later trusts as Secure.
    if (secure && !requestSecure) return false;

    // ---- cookie name prefixes (RFC 6265bis s5.4; storage model s5.7 steps 20-21)
    //
    // A "__Secure-"/"__Host-" name is the server's claim that the cookie was set with specific
    // attributes, and the receiving server trusts the NAME as proof of them. A Set-Cookie that
    // breaks its own name's claim is therefore refused whole — storing it "repaired" would
    // manufacture exactly the proof the server must not get.
    //
    // Matching is case-INSENSITIVE (s5.4 "UAs MUST match cookie name prefixes
    // case-insensitively"): servers routinely compare names case-insensitively, so a
    // "__SeCuRe-" lookalike must face the same rules as the honest spelling or it can
    // impersonate the protected cookie. The regexes carry no 'u' flag on purpose: without it,
    // /i folding can never map a non-ASCII character onto an ASCII one, making the match
    // exactly ASCII-case-insensitive.
    //
    // The mimicry rule for nameless cookies (s5.7 step 22) needs no code: pairs with no '='
    // or an empty name were refused above, so a value can never pose as a prefixed name.
    if (/^__secure-/i.test(name)) {
      // Step 20 requires only the Secure attribute here; being set over a secure channel is
      // the check directly above. Together: https and Secure, or nothing.
      if (!secure) return false;
    } else if (/^__host-/i.test(name)) {
      // Step 21: Secure, host-only, Path=/. Two clauses are deliberately stricter than the
      // storage-model letter, matching the server-facing contract (s4.1.3.2: "a Secure
      // attribute, a Path attribute with a value of /, and no Domain attribute"):
      //  - the Domain attribute must be ABSENT, not merely resolve to host-only (the no-dot
      //    and IP-literal branches below keep Domain=<host> host-only, but the name promised
      //    no Domain at all);
      //  - the Path attribute's value must literally be "/", not an invalid value that the
      //    default-path fallback would quietly repair to "/".
      // Both refuse strictly more than s5.7 asks, never less — fail closed.
      if (!secure || domainAttr !== null || pathAttr !== '/') return false;
    }

    // ---- domain validation
    let domain = host;
    let hostOnly = true;
    if (domainAttr !== null) {
      // Public-suffix guard, minimal version: a domain with no dot is a bare TLD ("com",
      // "org", "internal"), and accepting it would let one site set cookies for every site
      // under that TLD. A real public-suffix list (which would also catch "co.uk") is out of
      // scope here and deliberately NOT approximated further — a half-faked PSL is worse than
      // a documented gap, because it changes behaviour silently as the fake grows. The one
      // legitimate no-dot case, Domain=localhost on localhost, is exact-equal to the host and
      // handled by treating it as host-only, which is what the PSL algorithm prescribes.
      if (!domainAttr.includes('.')) {
        if (domainAttr !== host) return false;
        // fall through with hostOnly = true, domain = host
      } else if (looksLikeIp(host)) {
        // A Domain attribute on an IP-literal request only makes sense as an exact match.
        if (domainAttr !== host) return false;
      } else {
        if (!domainMatches(host, domainAttr)) return false;
        domain = domainAttr;
        hostOnly = false;
      }
    }

    const path = pathAttr && pathAttr[0] === '/' ? pathAttr : defaultPath(requestPath);

    // ---- expiry: Max-Age wins over Expires when both are present (s5.3 step 3).
    const now = this._now();
    let expiry = Infinity; // session cookie: lives as long as the jar
    if (maxAge !== null) {
      // Max-Age <= 0 means "expire immediately", i.e. delete any existing cookie.
      expiry = maxAge <= 0 ? -Infinity : now + maxAge * 1000;
    } else if (expires !== null) {
      expiry = expires;
    }

    const key = `${domain}|${path}|${name}`;
    const existing = this._cookies.get(key);
    if (expiry <= now) {
      // Setting an already-expired cookie is the standard deletion idiom.
      this._cookies.delete(key);
      return true;
    }
    const record = {
      name,
      value,
      domain,
      hostOnly,
      path,
      secure,
      httpOnly,
      sameSite,
      expiry,
      // Overwriting keeps the ORIGINAL creation time (s5.3 step 11.3) so the s5.4 sort order
      // is stable across refreshes of the same cookie.
      creation: existing ? existing.creation : now,
      seq: existing ? existing.seq : seqCounter++,
    };
    // Map insertion order would put an overwrite at the end; delete-then-set keeps eviction
    // scanning simple while `seq` preserves true creation order.
    this._cookies.delete(key);
    this._cookies.set(key, record);
    this._enforceCaps(domain);
    return true;
  }

  /**
   * Evict expired cookies first, then the oldest by creation, per-domain then globally.
   * @param {string} domain
   */
  _enforceCaps(domain) {
    const now = this._now();
    for (const [k, c] of this._cookies) if (c.expiry <= now) this._cookies.delete(k);

    const inDomain = [...this._cookies.values()].filter((c) => c.domain === domain);
    if (inDomain.length > this._maxPerDomain) {
      inDomain.sort((a, b) => a.creation - b.creation || a.seq - b.seq);
      for (const c of inDomain.slice(0, inDomain.length - this._maxPerDomain)) {
        this._cookies.delete(`${c.domain}|${c.path}|${c.name}`);
      }
    }
    if (this._cookies.size > this._maxCookies) {
      const all = [...this._cookies.values()].sort(
        (a, b) => a.creation - b.creation || a.seq - b.seq,
      );
      for (const c of all.slice(0, all.length - this._maxCookies)) {
        this._cookies.delete(`${c.domain}|${c.path}|${c.name}`);
      }
    }
  }

  /**
   * The Cookie header value for a request, or null if no cookie matches.
   * @param {string|URL} url
   * @returns {string | null}
   */
  headerFor(url) {
    const u = url instanceof URL ? url : new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const host = u.hostname.toLowerCase();
    const requestPath = u.pathname || '/';
    const secureChannel = u.protocol === 'https:';
    const now = this._now();
    const matched = [];
    for (const [key, c] of this._cookies) {
      if (c.expiry <= now) {
        this._cookies.delete(key); // lazy expiry sweep; the injected clock decides "now"
        continue;
      }
      if (c.hostOnly ? host !== c.domain : !domainMatches(host, c.domain)) continue;
      if (!pathMatches(requestPath, c.path)) continue;
      if (c.secure && !secureChannel) continue;
      matched.push(c);
    }
    if (matched.length === 0) return null;
    // s5.4: longer paths first, then earlier creation first. The seq tiebreak matters because
    // the frozen-clock runtime hands out identical creation timestamps within one task.
    matched.sort(
      (a, b) => b.path.length - a.path.length || a.creation - b.creation || a.seq - b.seq,
    );
    return matched.map((c) => `${c.name}=${c.value}`).join('; ');
  }

  /**
   * Everything currently stored, for tests and debugging. Records are live; do not mutate.
   * @returns {Cookie[]}
   */
  entries() {
    return [...this._cookies.values()];
  }
}
