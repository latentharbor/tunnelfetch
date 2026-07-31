// Redirect policy: which statuses redirect, how the method and body survive the hop, and —
// the part that actually matters — which headers must NOT survive it.
//
// The security invariant: `Authorization`, `Cookie` and `Proxy-Authorization` never cross an
// origin boundary. A server you trusted enough to send credentials to can redirect you anywhere,
// and forwarding the header to that "anywhere" hands your bearer token to a third party. Every
// mainstream client has shipped this bug at least once (CVE-2018-1000007 in curl, CVE-2022-0155
// in follow-redirects); the stripping logic below is written to be auditable line by line.

import { HttpError, LimitError, ConfigError, codes } from '../errors.js';

/** Statuses that trigger a redirect for our purposes. 300 has no defined Location semantics,
 * 304 is a cache signal, 305/306 are deprecated/reserved — none of them redirect. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export const DEFAULT_MAX_REDIRECTS = 20;

/**
 * @param {number} status
 * @param {string} [method] accepted for API symmetry; the status alone decides, because even a
 *   combination we will rewrite (303 + POST) is still a redirect — it just mutates the method.
 */
export function shouldRedirect(status, method) { // eslint-disable-line no-unused-vars
  return REDIRECT_STATUSES.has(status);
}

/**
 * Method rewriting per RFC 9110 s15.4, tempered by reality:
 *
 * - 301/302: the RFC says the method SHOULD be preserved, but every browser and every mainstream
 *   client (curl, undici, Go net/http) rewrites POST -> GET and drops the body, and has for
 *   twenty years. Servers are written against that behaviour, so preserving POST here would be
 *   "correct" and non-interoperable. We match the herd. Methods other than POST are preserved.
 * - 303: "see other" — ANY method except HEAD becomes GET and the body is dropped. HEAD stays
 *   HEAD because a GET would fetch a body the caller never asked for.
 * - 307/308: method and body are preserved by definition; that is the whole point of these codes.
 */
function rewriteMethod(status, method) {
  const m = method.toUpperCase();
  if (status === 303) return m === 'HEAD' ? 'HEAD' : 'GET';
  if ((status === 301 || status === 302) && m === 'POST') return 'GET';
  return m;
}

/** Default ports so that http://a and http://a:80 compare as the same origin. */
const DEFAULT_PORT = { 'http:': '80', 'https:': '443' };
const effectivePort = (url) => url.port || DEFAULT_PORT[url.protocol] || '';

/**
 * Percent-encode bytes above 0x7F in a Location value.
 *
 * Header values are opaque octets which our HTTP layer decodes as latin-1, so a code unit in
 * 0x80..0xFF stands for exactly one raw wire byte. We percent-encode that byte AS ITSELF rather
 * than letting the URL parser re-encode it as UTF-8, because a server that sent byte 0xE9 meant
 * byte 0xE9 (typically a latin-1 filename); %C3%A9 would name a different resource. Code units
 * above 0xFF cannot have come off the wire at all, so they are rejected — fail closed rather
 * than guess an encoding for a value we were never sent.
 */
function encodeLocationOctets(location) {
  let out = '';
  for (let i = 0; i < location.length; i++) {
    const cu = location.charCodeAt(i);
    if (cu <= 0x7f) out += location[i];
    else if (cu <= 0xff) out += '%' + cu.toString(16).toUpperCase().padStart(2, '0');
    else {
      throw new HttpError(
        codes.REDIRECT_INVALID_LOCATION,
        `Location contains code unit U+${cu.toString(16).toUpperCase().padStart(4, '0')}, ` +
          'which cannot appear in a header value decoded from the wire',
        { location },
      );
    }
  }
  return out;
}

/**
 * Resolve a Location header against the current URL, enforcing the scheme allow-list.
 * @param {URL} currentUrl
 * @param {string|null|undefined} location
 */
export function resolveLocation(currentUrl, location) {
  if (location === null || location === undefined || location.trim() === '') {
    throw new HttpError(
      codes.REDIRECT_INVALID_LOCATION,
      'redirect response has no usable Location header',
      { location: location ?? null },
    );
  }
  const trimmed = location.trim();
  const encoded = encodeLocationOctets(trimmed);
  let next;
  try {
    next = new URL(encoded, currentUrl);
  } catch {
    throw new HttpError(codes.REDIRECT_INVALID_LOCATION, `Location "${trimmed}" does not parse`, {
      location: trimmed,
    });
  }
  // Allow-list, not block-list: file:, data:, javascript:, blob:, ftp: and anything invented
  // later are all equally unable to be fetched by this client and equally useful to an attacker.
  if (next.protocol !== 'http:' && next.protocol !== 'https:') {
    throw new HttpError(
      codes.REDIRECT_SCHEME,
      `redirect to unsupported scheme "${next.protocol.slice(0, -1)}" refused (${trimmed})`,
      { scheme: next.protocol.slice(0, -1), location: trimmed },
    );
  }
  // WHATWG fetch: if the Location has no fragment, the original URL's fragment is carried over.
  // "No fragment" means no '#' in the raw value — a trailing bare '#' is an explicit empty
  // fragment and must NOT inherit. URL resolution never inherits the base fragment on its own.
  if (!trimmed.includes('#') && currentUrl.hash) next.hash = currentUrl.hash;
  return next;
}

/** Headers that describe the body being dropped alongside a method rewrite to GET. */
const BODY_HEADERS = ['content-length', 'content-type', 'content-encoding', 'transfer-encoding'];

/** Credentials that must never cross an origin boundary. */
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'proxy-authorization'];

/**
 * Compute the follow-up request for a redirect response.
 *
 * @param {{ method: string, url: string|URL, headers?: Headers|Record<string,string>,
 *           body?: Uint8Array|string|ReadableStream|null }} current
 * @param {{ status: number, headers: Headers|Record<string,string> }} response
 * @param {{ maxRedirects?: number, history?: string[] }} [options] pass the SAME `history` array
 *   across every hop of one logical fetch; it is both the loop detector and the hop counter.
 * @returns {{ method: string, url: URL, headers: Headers, body: any }}
 */
export function nextRequest(current, response, options = {}) {
  const { maxRedirects = DEFAULT_MAX_REDIRECTS, history = [] } = options;
  const status = response.status;
  if (!shouldRedirect(status)) {
    throw new ConfigError(codes.CONFIG_INVALID, `status ${status} is not a redirect`, { status });
  }

  // Hop budget first: `history` gains one entry per hop taken, so its length at entry is the
  // number of redirects already followed. Checked before any parsing so a hostile chain of
  // malformed Locations still costs at most maxRedirects rounds.
  if (history.length >= maxRedirects) {
    throw new LimitError(
      codes.LIMIT_REDIRECTS,
      `stopped after ${history.length} redirects (limit ${maxRedirects})`,
      { limit: maxRedirects },
    );
  }

  const currentUrl = current.url instanceof URL ? current.url : new URL(current.url);
  const currentHeaders = new Headers(current.headers ?? {});
  const responseHeaders = new Headers(response.headers ?? {});

  const nextUrl = resolveLocation(currentUrl, responseHeaders.get('location'));
  const method = rewriteMethod(status, current.method ?? 'GET');
  const methodRewritten = method !== (current.method ?? 'GET').toUpperCase();

  // Loop detection keyed on (method, url): GET /a and POST /a are different requests, and a
  // 303 chain legitimately revisits a URL once with the rewritten method. The fragment is not
  // part of the key — the wire request is identical with or without it.
  const keyOf = (m, u) => {
    const bare = new URL(u);
    bare.hash = '';
    return `${m} ${bare.href}`;
  };
  history.push(keyOf((current.method ?? 'GET').toUpperCase(), currentUrl));
  const nextKey = keyOf(method, nextUrl);
  if (history.includes(nextKey)) {
    throw new HttpError(codes.REDIRECT_LOOP, `redirect loop: already visited ${nextKey}`, {
      key: nextKey,
      hops: history.length,
    });
  }

  // ---- header stripping: the security-critical section ----------------------------------
  //
  // "Same origin" is scheme AND host AND port, with default ports normalised so http://a and
  // http://a:80 agree. The three checks are computed separately (not via URL.origin string
  // comparison) so that each one is individually visible to an auditor, and so a change in any
  // single component demonstrably trips the strip. This single rule already subsumes the
  // special cases the spec calls out — a host-only change, and an https->http downgrade on the
  // same host, both differ in at least one component and therefore strip.
  const headers = new Headers(currentHeaders);
  const schemeChanged = nextUrl.protocol !== currentUrl.protocol;
  const hostChanged = nextUrl.hostname !== currentUrl.hostname;
  const portChanged = effectivePort(nextUrl) !== effectivePort(currentUrl);
  if (schemeChanged || hostChanged || portChanged) {
    for (const h of CREDENTIAL_HEADERS) headers.delete(h);
  }

  // Host is derived from the target URL by the request serialiser; a carried-over Host would
  // silently re-route a cross-origin hop at the HTTP layer (request smuggling adjacent).
  headers.delete('host');

  let body = current.body ?? null;
  if (methodRewritten) {
    // The body is gone, so every header describing it must go too, or the next server sees a
    // Content-Length for bytes that never arrive and stalls or smuggles.
    body = null;
    for (const h of BODY_HEADERS) headers.delete(h);
  } else if (status === 307 || status === 308) {
    // 307/308 must replay the body verbatim. A ReadableStream that has already been consumed
    // cannot be replayed, and silently sending an empty body would corrupt the request (an
    // upload that "succeeds" with zero bytes). Distinct, detectable failure instead: callers
    // that want 307-following with a stream body must buffer it or supply a fresh stream.
    if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream) {
      throw new ConfigError(
        codes.CONFIG_INVALID,
        `${status} redirect requires replaying the request body, but the body is a stream ` +
          'that cannot be replayed; buffer the body to follow this redirect',
        { reason: 'body-not-replayable', status },
      );
    }
  }

  return { method, url: nextUrl, headers, body };
}
