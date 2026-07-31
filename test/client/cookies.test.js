// CookieJar semantics. Time is ALWAYS driven through the injected clock: on the target
// runtime Date.now() freezes during synchronous execution, so any test relying on real time
// passing would be testing behaviour the production environment cannot exhibit.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CookieJar,
  parseCookieDate,
  defaultPath,
  pathMatches,
  domainMatches,
} from '../../src/client/cookies.js';

/** A jar whose clock the test owns. */
function makeJar(opts = {}) {
  const clock = { t: 1_000_000_000_000 }; // an arbitrary fixed epoch
  const jar = new CookieJar({ now: () => clock.t, ...opts });
  return { jar, clock };
}

// ---------------------------------------------------------------- date parsing

test('parseCookieDate: the canonical RFC 1123 shape', () => {
  assert.equal(
    parseCookieDate('Sun, 06 Nov 1994 08:49:37 GMT'),
    Date.UTC(1994, 10, 6, 8, 49, 37),
  );
});

test('parseCookieDate: RFC 850 dashes and a two-digit year', () => {
  assert.equal(
    parseCookieDate('Sunday, 06-Nov-94 08:49:37 GMT'),
    Date.UTC(1994, 10, 6, 8, 49, 37),
  );
});

test('parseCookieDate: two-digit year pivot at 70/99', () => {
  assert.equal(parseCookieDate('06-Nov-70 00:00:00'), Date.UTC(1970, 10, 6));
  assert.equal(parseCookieDate('06-Nov-99 00:00:00'), Date.UTC(1999, 10, 6));
  assert.equal(parseCookieDate('06-Nov-69 00:00:00'), Date.UTC(2069, 10, 6));
  assert.equal(parseCookieDate('06-Nov-00 00:00:00'), Date.UTC(2000, 10, 6));
});

test('parseCookieDate: components in any order, odd delimiters, junk tokens', () => {
  // The RFC finds day/month/year/time wherever they appear.
  assert.equal(parseCookieDate('Thu Feb 17 2015 10:00:00 GMT'), Date.UTC(2015, 1, 17, 10, 0, 0));
  assert.equal(parseCookieDate('17 feb 2015 10:00:00'), Date.UTC(2015, 1, 17, 10, 0, 0));
  // Month names longer than three letters match by prefix.
  assert.equal(parseCookieDate('17 February 2015 10:00:00'), Date.UTC(2015, 1, 17, 10, 0, 0));
  // Single-digit time fields are legal (hh:mm:ss are 1*2DIGIT).
  assert.equal(parseCookieDate('6 Nov 1994 8:9:7'), Date.UTC(1994, 10, 6, 8, 9, 7));
});

test('parseCookieDate: rejects what Date.parse would silently mangle', () => {
  assert.equal(parseCookieDate(''), null);
  assert.equal(parseCookieDate('not a date'), null);
  assert.equal(parseCookieDate('Nov 1994 08:49:37'), null); // no day
  assert.equal(parseCookieDate('06 Nov 08:49:37'), null); // time found, then no year token
  assert.equal(parseCookieDate('06 Nov 1994'), null); // no time
  assert.equal(parseCookieDate('32 Nov 1994 08:49:37'), null); // day out of range
  assert.equal(parseCookieDate('06 Nov 1994 24:00:00'), null); // hour out of range
  assert.equal(parseCookieDate('06 Nov 1994 08:60:00'), null); // minute out of range
  assert.equal(parseCookieDate('06 Nov 1600 08:49:37'), null); // before the 1601 floor
});

// ---------------------------------------------------------------- pure matchers

test('defaultPath derivation per s5.1.4', () => {
  assert.equal(defaultPath('/'), '/');
  assert.equal(defaultPath('/page'), '/');
  assert.equal(defaultPath('/dir/page'), '/dir');
  assert.equal(defaultPath('/dir/'), '/dir');
  assert.equal(defaultPath(''), '/');
  assert.equal(defaultPath('nonslash'), '/');
});

test('pathMatches honours the slash boundary', () => {
  assert.equal(pathMatches('/dir/page', '/dir'), true);
  assert.equal(pathMatches('/dir', '/dir'), true);
  assert.equal(pathMatches('/dirx', '/dir'), false); // /dir must not match /dirx
  assert.equal(pathMatches('/dir/page', '/dir/'), true);
  assert.equal(pathMatches('/', '/'), true);
  assert.equal(pathMatches('/other', '/dir'), false);
});

test('domainMatches requires a label boundary, not a string suffix', () => {
  assert.equal(domainMatches('example.com', 'example.com'), true);
  assert.equal(domainMatches('sub.example.com', 'example.com'), true);
  assert.equal(domainMatches('example.com', 'ample.com'), false); // string suffix, wrong label
  assert.equal(domainMatches('example.com', 'sub.example.com'), false); // superdomain only
});

// ---------------------------------------------------------------- storing and sending

test('a plain cookie round-trips on the same host and is invisible elsewhere', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://example.com/', ['session=abc123']);
  assert.equal(jar.headerFor('https://example.com/'), 'session=abc123');
  assert.equal(jar.headerFor('https://other.example/'), null);
  assert.equal(jar.rejected, 0);
});

test('without a Domain attribute the cookie is host-only: subdomains excluded', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://example.com/', ['a=1']);
  assert.equal(jar.headerFor('https://sub.example.com/'), null);
  assert.equal(jar.headerFor('https://example.com/'), 'a=1');
});

// Uses the RFC 6761 `.test` TLD rather than example.com so that BOTH the real domain and the
// lookalike are names that provably resolve nowhere — `notexample.com` is a registrable domain
// somebody owns, and no test should name one even when it never dials it.
test('Domain=example.test widens to subdomains; a leading dot is equivalent', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://example.test/', ['a=1; Domain=example.test']);
  jar.setFromResponse('https://example.test/', ['b=2; Domain=.example.test']);
  assert.equal(jar.headerFor('https://deep.sub.example.test/'), 'a=1; b=2');
  assert.equal(jar.headerFor('https://example.test/'), 'a=1; b=2');
  // But not a lookalike host that merely ends with the same string, off a label boundary.
  assert.equal(jar.headerFor('https://notexample.test/'), null);
});

test('a subdomain may set a cookie for its parent, not for a sibling or stranger', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://api.example.com/', ['up=1; Domain=example.com']);
  assert.equal(jar.headerFor('https://www.example.com/'), 'up=1');
  jar.setFromResponse('https://api.example.com/', ['x=1; Domain=other.test']);
  jar.setFromResponse('https://example.com/', ['y=1; Domain=sub.example.com']); // superdomain->sub
  assert.equal(jar.headerFor('https://other.test/'), null);
  // sub.example.com still sees up=1 (Domain=example.com covers it) but never y=1: a
  // superdomain must not be able to plant cookies on a more specific host.
  assert.equal(jar.headerFor('https://sub.example.com/x'), 'up=1');
  assert.equal(jar.rejected, 2, 'both mismatched Domains are ignored and counted');
});

test('Domain=com (bare TLD, no dot) is refused and counted', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://example.com/', ['evil=1; Domain=com']);
  assert.equal(jar.headerFor('https://example.com/'), null);
  assert.equal(jar.headerFor('https://victim.test/'), null);
  assert.equal(jar.rejected, 1);
});

test('Domain=localhost on localhost is the legitimate no-dot case: stored host-only', () => {
  const { jar } = makeJar();
  jar.setFromResponse('http://localhost/', ['dev=1; Domain=localhost']);
  assert.equal(jar.headerFor('http://localhost/'), 'dev=1');
  assert.equal(jar.rejected, 0);
});

test('a Domain attribute on an IP-literal host must match exactly', () => {
  const { jar } = makeJar();
  jar.setFromResponse('http://10.0.0.1/', ['a=1; Domain=10.0.0.1']);
  jar.setFromResponse('http://10.0.0.1/', ['b=2; Domain=0.0.1']);
  assert.equal(jar.headerFor('http://10.0.0.1/'), 'a=1');
  assert.equal(jar.rejected, 1);
});

// ---------------------------------------------------------------- paths

test('default path comes from the request URL directory', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/dir/page', ['a=1']); // default path is /dir
  assert.equal(jar.headerFor('https://e.test/dir/other'), 'a=1');
  assert.equal(jar.headerFor('https://e.test/dir'), 'a=1');
  assert.equal(jar.headerFor('https://e.test/dirx'), null); // boundary, not string prefix
  assert.equal(jar.headerFor('https://e.test/'), null);
});

test('an explicit Path attribute overrides the default; a non-/ path falls back', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/deep/dir/page', ['a=1; Path=/']);
  jar.setFromResponse('https://e.test/deep/dir/page', ['b=2; Path=relative']); // invalid -> default
  assert.equal(jar.headerFor('https://e.test/anywhere'), 'a=1');
  assert.equal(jar.headerFor('https://e.test/deep/dir/x'), 'b=2; a=1');
});

// ---------------------------------------------------------------- Secure

test('Secure cookies are refused when set over http', () => {
  const { jar } = makeJar();
  jar.setFromResponse('http://e.test/', ['s=1; Secure']);
  assert.equal(jar.headerFor('https://e.test/'), null);
  assert.equal(jar.rejected, 1);
});

test('Secure cookies are sent over https only; plain cookies cross the scheme', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/', ['s=1; Secure', 'p=2']);
  assert.equal(jar.headerFor('https://e.test/'), 's=1; p=2');
  assert.equal(jar.headerFor('http://e.test/'), 'p=2');
});

// ---------------------------------------------------------------- expiry and the clock

test('Max-Age drives expiry through the injected clock', () => {
  const { jar, clock } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1; Max-Age=10']);
  clock.t += 9_999;
  assert.equal(jar.headerFor('https://e.test/'), 'a=1');
  clock.t += 2; // now 10 001 ms after creation
  assert.equal(jar.headerFor('https://e.test/'), null);
});

test('Max-Age wins over Expires regardless of attribute order', () => {
  const { jar, clock } = makeJar();
  const farFuture = 'Fri, 01 Jan 2100 00:00:00 GMT';
  jar.setFromResponse('https://e.test/', [
    `a=1; Expires=${farFuture}; Max-Age=5`,
    `b=2; Max-Age=5; Expires=${farFuture}`,
  ]);
  assert.equal(jar.headerFor('https://e.test/'), 'a=1; b=2');
  clock.t += 5_001;
  assert.equal(jar.headerFor('https://e.test/'), null, 'Max-Age=5 must win over Expires=2100');
});

test('Max-Age=0 and negative Max-Age delete an existing cookie', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1', 'b=2']);
  jar.setFromResponse('https://e.test/', ['a=gone; Max-Age=0']);
  assert.equal(jar.headerFor('https://e.test/'), 'b=2');
  jar.setFromResponse('https://e.test/', ['b=gone; Max-Age=-1']);
  assert.equal(jar.headerFor('https://e.test/'), null);
  assert.equal(jar.rejected, 0, 'deletion is a successful operation, not a rejection');
});

test('a non-numeric Max-Age is ignored as an attribute, not an error', () => {
  const { jar, clock } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1; Max-Age=forever']);
  clock.t += 1_000_000;
  assert.equal(jar.headerFor('https://e.test/'), 'a=1', 'falls back to a session cookie');
  // And when a valid Expires is also present, THAT governs.
  jar.setFromResponse('https://e.test/', ['b=2; Max-Age=nope; Expires=Sun, 06 Nov 1994 08:49:37 GMT']);
  assert.equal(jar.headerFor('https://e.test/'), 'a=1', 'b expired in 1994');
});

test('Expires in the past (including two-digit years) never stores', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/', ['old=1; Expires=Sun, 06-Nov-94 08:49:37 GMT']);
  assert.equal(jar.headerFor('https://e.test/'), null);
});

test('an unparseable Expires is ignored: the cookie becomes a session cookie', () => {
  const { jar, clock } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1; Expires=whenever']);
  clock.t += 1_000_000_000;
  assert.equal(jar.headerFor('https://e.test/'), 'a=1');
});

// ---------------------------------------------------------------- header assembly

test('emitted order: path length descending, then creation ascending', () => {
  const { jar, clock } = makeJar();
  jar.setFromResponse('https://e.test/a/b/c', ['shallow=1; Path=/']);
  clock.t += 10;
  jar.setFromResponse('https://e.test/a/b/c', ['deep=2; Path=/a/b']);
  clock.t += 10;
  jar.setFromResponse('https://e.test/a/b/c', ['mid=3; Path=/a']);
  assert.equal(jar.headerFor('https://e.test/a/b/x'), 'deep=2; mid=3; shallow=1');
});

test('equal path lengths tie-break by creation time even under a frozen clock', () => {
  const { jar } = makeJar(); // clock never advances: creation timestamps are identical
  jar.setFromResponse('https://e.test/', ['first=1', 'second=2', 'third=3']);
  assert.equal(jar.headerFor('https://e.test/'), 'first=1; second=2; third=3');
});

test('overwriting a cookie keeps its original creation-order slot', () => {
  const { jar, clock } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1']);
  clock.t += 10;
  jar.setFromResponse('https://e.test/', ['b=2']);
  clock.t += 10;
  jar.setFromResponse('https://e.test/', ['a=9']); // refresh a: still sorts before b
  assert.equal(jar.headerFor('https://e.test/'), 'a=9; b=2');
  assert.equal(jar.size, 2);
});

test('same name at different paths or domains are distinct cookies', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/x/page', ['a=path; Path=/x']);
  jar.setFromResponse('https://e.test/', ['a=root; Path=/']);
  // Both match /x/page; the longer path comes first, duplicates names and all.
  assert.equal(jar.headerFor('https://e.test/x/page'), 'a=path; a=root');
  assert.equal(jar.size, 2);
});

test('quoted values are stored unquoted; whitespace around name and value is trimmed', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/', ['  a  =  "quoted value"  ']);
  assert.equal(jar.headerFor('https://e.test/'), 'a=quoted value');
});

test('malformed pairs are rejected and counted: no =, empty name, control bytes', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/', [
    'noequalsign',
    '=onlyvalue',
    'ctl=\x00bad',
    'ok=1',
  ]);
  assert.equal(jar.headerFor('https://e.test/'), 'ok=1');
  assert.equal(jar.rejected, 3);
});

test('attribute names are case-insensitive and unknown attributes are ignored', () => {
  const { jar, clock } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1; MAX-AGE=5; SECURE; Priority=High; SameSite=Lax']);
  assert.equal(jar.headerFor('https://e.test/'), 'a=1');
  assert.equal(jar.headerFor('http://e.test/'), null, 'SECURE flag was honoured');
  clock.t += 5_001;
  assert.equal(jar.headerFor('https://e.test/'), null, 'MAX-AGE was honoured');
});

test('headerFor returns null for non-http(s) schemes', () => {
  const { jar } = makeJar();
  jar.setFromResponse('https://e.test/', ['a=1']);
  assert.equal(jar.headerFor('ftp://e.test/'), null);
});

// ---------------------------------------------------------------- caps and eviction

test('the per-domain cap evicts the oldest cookies of that domain', () => {
  const { jar, clock } = makeJar({ maxPerDomain: 3 });
  for (const n of ['a', 'b', 'c', 'd']) {
    jar.setFromResponse('https://e.test/', [`${n}=1`]);
    clock.t += 10;
  }
  assert.equal(jar.headerFor('https://e.test/'), 'b=1; c=1; d=1', 'oldest (a) evicted');
  assert.equal(jar.size, 3);
});

test('the global cap evicts the oldest cookie across domains', () => {
  const { jar, clock } = makeJar({ maxCookies: 3, maxPerDomain: 2 });
  jar.setFromResponse('https://one.example/', ['a=1']);
  clock.t += 10;
  jar.setFromResponse('https://two.example/', ['b=1']);
  clock.t += 10;
  jar.setFromResponse('https://three.example/', ['c=1']);
  clock.t += 10;
  jar.setFromResponse('https://four.example/', ['d=1']);
  assert.equal(jar.size, 3);
  assert.equal(jar.headerFor('https://one.example/'), null, 'oldest evicted globally');
  assert.equal(jar.headerFor('https://four.example/'), 'd=1');
});

test('expired cookies are purged before live ones are evicted', () => {
  const { jar, clock } = makeJar({ maxPerDomain: 2 });
  jar.setFromResponse('https://e.test/', ['dying=1; Max-Age=5']);
  clock.t += 10_000; // dying is now expired
  jar.setFromResponse('https://e.test/', ['keep1=1']);
  jar.setFromResponse('https://e.test/', ['keep2=1']);
  // The cap is 2: the expired cookie must be the one that made room, not keep1.
  assert.equal(jar.headerFor('https://e.test/'), 'keep1=1; keep2=1');
});
