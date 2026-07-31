// Redirect semantics. The credential-stripping block is the one that matters: a miss there
// is not a bug but a leak of the caller's Authorization header to an arbitrary third party.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  shouldRedirect,
  nextRequest,
  resolveLocation,
  DEFAULT_MAX_REDIRECTS,
} from '../../src/client/redirect.js';
import { rejectsWithCode } from '../_harness.js';

const BODY = new Uint8Array([1, 2, 3]);

/** Build a minimal current-request object. */
function req(overrides = {}) {
  return {
    method: 'GET',
    url: 'https://origin.example/start',
    headers: {},
    body: null,
    ...overrides,
  };
}

/** Build a redirect response. */
function res(status, location, extra = {}) {
  const headers = { ...extra };
  if (location !== undefined) headers.location = location;
  return { status, headers };
}

test('shouldRedirect: only 301/302/303/307/308', () => {
  for (const s of [301, 302, 303, 307, 308]) assert.equal(shouldRedirect(s, 'GET'), true, `${s}`);
  for (const s of [200, 204, 300, 304, 305, 306, 400, 404, 500]) {
    assert.equal(shouldRedirect(s, 'GET'), false, `${s}`);
  }
});

test('method and body rewriting: full status x method matrix', () => {
  // [status, method, expectedMethod, bodySurvives]
  // 301/302 rewrite ONLY POST (browser-compatible reading of RFC 9110 s15.4);
  // 303 rewrites everything except HEAD; 307/308 rewrite nothing.
  const table = [
    [301, 'GET', 'GET', true], [301, 'POST', 'GET', false], [301, 'PUT', 'PUT', true],
    [301, 'HEAD', 'HEAD', true], [301, 'DELETE', 'DELETE', true],
    [302, 'GET', 'GET', true], [302, 'POST', 'GET', false], [302, 'PUT', 'PUT', true],
    [302, 'HEAD', 'HEAD', true], [302, 'DELETE', 'DELETE', true],
    [303, 'GET', 'GET', true], [303, 'POST', 'GET', false], [303, 'PUT', 'GET', false],
    [303, 'HEAD', 'HEAD', true], [303, 'DELETE', 'GET', false],
    [307, 'GET', 'GET', true], [307, 'POST', 'POST', true], [307, 'PUT', 'PUT', true],
    [307, 'HEAD', 'HEAD', true], [307, 'DELETE', 'DELETE', true],
    [308, 'GET', 'GET', true], [308, 'POST', 'POST', true], [308, 'PUT', 'PUT', true],
    [308, 'HEAD', 'HEAD', true], [308, 'DELETE', 'DELETE', true],
  ];
  for (const [status, method, expectedMethod, bodySurvives] of table) {
    const next = nextRequest(
      req({ method, body: BODY }),
      res(status, '/next'),
      { history: [] },
    );
    const label = `${status} ${method}`;
    assert.equal(next.method, expectedMethod, label);
    if (bodySurvives) assert.equal(next.body, BODY, `${label}: body should survive`);
    else assert.equal(next.body, null, `${label}: body should be dropped`);
  }
});

test('rewriting to GET drops the body-describing headers', () => {
  const headers = {
    'content-length': '3',
    'content-type': 'application/json',
    'content-encoding': 'gzip',
    'transfer-encoding': 'chunked',
    'x-keep-me': 'yes',
  };
  const next = nextRequest(req({ method: 'POST', headers, body: BODY }), res(303, '/other'));
  for (const h of ['content-length', 'content-type', 'content-encoding', 'transfer-encoding']) {
    assert.equal(next.headers.has(h), false, `${h} must be dropped with the body`);
  }
  assert.equal(next.headers.get('x-keep-me'), 'yes');
});

test('307 preserves the body-describing headers along with the body', () => {
  const next = nextRequest(
    req({ method: 'POST', headers: { 'content-type': 'application/json' }, body: BODY }),
    res(307, '/other'),
  );
  assert.equal(next.headers.get('content-type'), 'application/json');
  assert.equal(next.body, BODY);
});

// ---------------------------------------------------------------- credential stripping

const CREDS = {
  authorization: 'Bearer sekrit',
  cookie: 'session=abc',
  'proxy-authorization': 'Basic cHg=',
};

test('credentials are STRIPPED on a cross-host redirect', () => {
  const next = nextRequest(
    req({ url: 'https://origin.example/a', headers: CREDS }),
    res(302, 'https://evil.example/b'),
  );
  assert.equal(next.headers.has('authorization'), false);
  assert.equal(next.headers.has('cookie'), false);
  assert.equal(next.headers.has('proxy-authorization'), false);
});

test('credentials are STRIPPED on a cross-scheme (https->http) redirect to the same host', () => {
  const next = nextRequest(
    req({ url: 'https://origin.example/a', headers: CREDS }),
    res(302, 'http://origin.example/b'),
  );
  assert.equal(next.headers.has('authorization'), false, 'downgrade must strip Authorization');
  assert.equal(next.headers.has('cookie'), false, 'downgrade must strip Cookie');
  assert.equal(next.headers.has('proxy-authorization'), false);
});

test('credentials are STRIPPED on a cross-port redirect, same scheme and host', () => {
  const next = nextRequest(
    req({ url: 'https://origin.example/a', headers: CREDS }),
    res(302, 'https://origin.example:8443/b'),
  );
  assert.equal(next.headers.has('authorization'), false);
  assert.equal(next.headers.has('cookie'), false);
  assert.equal(next.headers.has('proxy-authorization'), false);
});

test('credentials are STRIPPED on a subdomain hop even with scheme and port unchanged', () => {
  // "Same site" is not "same origin"; api.origin.example is a different host and gets nothing.
  const next = nextRequest(
    req({ url: 'https://origin.example/a', headers: CREDS }),
    res(302, 'https://api.origin.example/a'),
  );
  assert.equal(next.headers.has('authorization'), false);
  assert.equal(next.headers.has('cookie'), false);
});

test('credentials SURVIVE a same-origin path-only redirect', () => {
  const next = nextRequest(
    req({ url: 'https://origin.example/a', headers: { ...CREDS, 'x-custom': 'v' } }),
    res(302, '/b?x=1'),
  );
  assert.equal(next.headers.get('authorization'), 'Bearer sekrit');
  assert.equal(next.headers.get('cookie'), 'session=abc');
  assert.equal(next.headers.get('proxy-authorization'), 'Basic cHg=');
  assert.equal(next.headers.get('x-custom'), 'v');
});

test('default ports normalise: http://h -> http://h:80 is same-origin, credentials survive', () => {
  const next = nextRequest(
    req({ url: 'http://origin.example/a', headers: CREDS }),
    res(302, 'http://origin.example:80/b'),
  );
  assert.equal(next.headers.get('authorization'), 'Bearer sekrit');
  assert.equal(next.headers.get('cookie'), 'session=abc');
});

test('an http->https upgrade on the same host still strips (scheme changed)', () => {
  // Conservative by design: the origin changed, so the credential does not follow. The caller
  // can re-attach credentials it considers safe for the upgraded origin.
  const next = nextRequest(
    req({ url: 'http://origin.example/a', headers: CREDS }),
    res(302, 'https://origin.example/a'),
  );
  assert.equal(next.headers.has('authorization'), false);
});

test('Host is never carried over, same-origin or not', () => {
  for (const location of ['/same-origin', 'https://other.example/x']) {
    const next = nextRequest(
      req({ url: 'https://origin.example/a', headers: { host: 'origin.example' } }),
      res(302, location),
    );
    assert.equal(next.headers.has('host'), false, `Host must be dropped for ${location}`);
  }
});

// ---------------------------------------------------------------- Location resolution

test('relative, absolute-path, absolute and protocol-relative Locations resolve', () => {
  const base = new URL('https://origin.example/dir/page?q=1');
  assert.equal(resolveLocation(base, 'other').href, 'https://origin.example/dir/other');
  assert.equal(resolveLocation(base, '/rooted').href, 'https://origin.example/rooted');
  assert.equal(resolveLocation(base, '../up').href, 'https://origin.example/up');
  assert.equal(resolveLocation(base, 'https://x.example/abs').href, 'https://x.example/abs');
  // Protocol-relative inherits the CURRENT scheme.
  assert.equal(resolveLocation(base, '//cdn.example/a').href, 'https://cdn.example/a');
  const httpBase = new URL('http://origin.example/');
  assert.equal(resolveLocation(httpBase, '//cdn.example/a').href, 'http://cdn.example/a');
});

test('fragment: original fragment is preserved when the Location has none', () => {
  const base = new URL('https://origin.example/page#section');
  assert.equal(resolveLocation(base, '/moved').hash, '#section');
  // A Location with its own fragment wins.
  assert.equal(resolveLocation(base, '/moved#other').hash, '#other');
  // A bare trailing '#' is an EXPLICIT empty fragment, not "no fragment": nothing inherited.
  assert.equal(resolveLocation(base, '/moved#').hash, '');
  // No fragment anywhere stays no fragment.
  assert.equal(resolveLocation(new URL('https://o.example/p'), '/x').hash, '');
});

test('raw bytes above 0x7F are percent-encoded as themselves, deterministically', () => {
  const base = new URL('https://origin.example/');
  // é is how a latin-1 header decode presents wire byte 0xE9. It must become %E9 (the
  // original octet), not %C3%A9 (a UTF-8 re-encode that names a different resource).
  assert.equal(resolveLocation(base, '/café').href, 'https://origin.example/caf%E9');
  assert.equal(resolveLocation(base, '/aÿb').href, 'https://origin.example/a%FFb');
});

test('code units above 0xFF cannot come from the wire and are rejected', async () => {
  const base = new URL('https://origin.example/');
  await rejectsWithCode(
    () => resolveLocation(base, '/snowman☃'),
    'REDIRECT_INVALID_LOCATION',
  );
});

test('absent, empty and unparseable Locations are REDIRECT_INVALID_LOCATION', async () => {
  const base = new URL('https://origin.example/');
  await rejectsWithCode(() => resolveLocation(base, null), 'REDIRECT_INVALID_LOCATION');
  await rejectsWithCode(() => resolveLocation(base, undefined), 'REDIRECT_INVALID_LOCATION');
  await rejectsWithCode(() => resolveLocation(base, ''), 'REDIRECT_INVALID_LOCATION');
  await rejectsWithCode(() => resolveLocation(base, '   '), 'REDIRECT_INVALID_LOCATION');
  await rejectsWithCode(() => resolveLocation(base, 'http://['), 'REDIRECT_INVALID_LOCATION');
  // And through nextRequest with the header missing entirely:
  await rejectsWithCode(() => nextRequest(req(), res(302)), 'REDIRECT_INVALID_LOCATION');
});

test('non-http(s) schemes are refused by name: javascript:, file:, data:, ftp:', async () => {
  const base = new URL('https://origin.example/');
  const cases = [
    ['javascript:alert(1)', 'javascript'],
    ['file:///etc/passwd', 'file'],
    ['data:text/html,hi', 'data'],
    ['ftp://host/x', 'ftp'],
  ];
  for (const [location, scheme] of cases) {
    const err = await rejectsWithCode(() => resolveLocation(base, location), 'REDIRECT_SCHEME');
    assert.match(err.message, new RegExp(scheme), `error must name the scheme for ${location}`);
    assert.equal(err.detail.scheme, scheme);
  }
});

// ---------------------------------------------------------------- loops and limits

test('an A -> B -> A chain is detected as a loop', async () => {
  const history = [];
  const hop1 = nextRequest(
    req({ url: 'https://o.example/a' }),
    res(302, '/b'),
    { history },
  );
  assert.equal(hop1.url.href, 'https://o.example/b');
  await rejectsWithCode(
    () => nextRequest({ ...hop1, url: hop1.url }, res(302, '/a'), { history }),
    'REDIRECT_LOOP',
  );
});

test('a self-redirect is a loop on the first hop', async () => {
  await rejectsWithCode(
    () => nextRequest(req({ url: 'https://o.example/a' }), res(302, '/a'), { history: [] }),
    'REDIRECT_LOOP',
  );
});

test('303 revisiting the same URL with a rewritten method is NOT a loop', () => {
  // POST /form -> 303 -> GET /form is the canonical post/redirect/get pattern.
  const next = nextRequest(
    req({ method: 'POST', url: 'https://o.example/form', body: BODY }),
    res(303, '/form'),
    { history: [] },
  );
  assert.equal(next.method, 'GET');
  assert.equal(next.url.href, 'https://o.example/form');
});

test('fragments do not defeat loop detection', async () => {
  // /a#x and /a#y are the same wire request; a chain bouncing between them is a loop.
  const history = [];
  nextRequest(req({ url: 'https://o.example/a#x' }), res(302, '/b'), { history });
  await rejectsWithCode(
    () =>
      nextRequest({ method: 'GET', url: 'https://o.example/b' }, res(302, '/a#y'), { history }),
    'REDIRECT_LOOP',
  );
});

test('maxRedirects is enforced with the default of 20', async () => {
  assert.equal(DEFAULT_MAX_REDIRECTS, 20);
  const history = [];
  let current = req({ url: 'https://o.example/hop0' });
  for (let i = 0; i < 20; i++) {
    current = { ...nextRequest(current, res(302, `/hop${i + 1}`), { history }), method: 'GET' };
  }
  const err = await rejectsWithCode(
    () => nextRequest(current, res(302, '/hop-too-far'), { history }),
    'LIMIT_REDIRECTS',
  );
  assert.match(err.message, /20/);
});

test('a small explicit maxRedirects is honoured', async () => {
  const history = [];
  let current = req({ url: 'https://o.example/h0' });
  current = { ...nextRequest(current, res(302, '/h1'), { history, maxRedirects: 2 }) };
  current = { ...nextRequest(current, res(302, '/h2'), { history, maxRedirects: 2 }) };
  await rejectsWithCode(
    () => nextRequest(current, res(302, '/h3'), { history, maxRedirects: 2 }),
    'LIMIT_REDIRECTS',
  );
});

// ---------------------------------------------------------------- body replayability

test('307 with a stream body fails loudly instead of replaying nothing', async () => {
  const stream = new ReadableStream({ start(c) { c.close(); } });
  const err = await rejectsWithCode(
    () => nextRequest(req({ method: 'POST', body: stream }), res(307, '/next')),
    'CONFIG_INVALID',
  );
  assert.equal(err.detail.reason, 'body-not-replayable');
  assert.match(err.message, /stream/);
});

test('303 with a stream body is fine: the body is dropped, not replayed', () => {
  const stream = new ReadableStream({ start(c) { c.close(); } });
  const next = nextRequest(req({ method: 'POST', body: stream }), res(303, '/next'));
  assert.equal(next.body, null);
});

test('307 with a byte-array body replays it', () => {
  const next = nextRequest(req({ method: 'POST', body: BODY }), res(307, '/next'));
  assert.equal(next.body, BODY);
});

test('nextRequest on a non-redirect status is a caller error', async () => {
  await rejectsWithCode(() => nextRequest(req(), res(200, '/x')), 'CONFIG_INVALID');
});
