// End-to-end tests for the fetch facade over an in-memory network.
//
// These run the real stack — request serialisation, response framing, redirects, cookies,
// decompression, pooling — against a scripted origin, with no TLS in the way. TLS has its own
// loopback suite; separating the two means a framing bug cannot hide behind a handshake bug.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client, createFetch, install } from '../src/client.js';
import {
  chunkedBody,
  fakeNetwork,
  gzip,
  readRequestHead,
  response,
  sequenceServer,
} from './_fakenet.js';
import { CookieJar } from '../src/client/cookies.js';
import { latin1, utf8 } from '../src/util/bytes.js';
import { rejectsWithCode } from './_harness.js';

/** A Client wired to a scripted origin. `forceTunnel` keeps the platform fetch out of the way. */
function clientFor(handler, options = {}) {
  const net = fakeNetwork(handler);
  const client = new Client({ connect: net.connect, forceTunnel: true, ...options });
  return { client, net };
}

test('a plain GET goes out well formed and comes back parsed', async () => {
  const server = sequenceServer([response({ body: 'hello world' })]);
  const { client, net } = clientFor(server.handler);

  const res = await client.fetch('http://origin.example/path?q=1');
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'hello world');

  const req = server.seen[0];
  assert.equal(req.method, 'GET');
  assert.equal(req.target, '/path?q=1', 'origin-form target, query included');
  assert.equal(req.version, 'HTTP/1.1');
  assert.equal(req.headers.get('host'), 'origin.example', 'default port is omitted from Host');
  assert.equal(req.order[0], 'host', 'Host must be the first header field');
  assert.equal(req.headers.get('accept-encoding'), 'gzip, deflate');
  assert.ok(
    !/\bbr\b|zstd/.test(req.headers.get('accept-encoding')),
    'never advertise a coding we cannot decode',
  );
  assert.deepEqual(net.calls[0].addr, { hostname: 'origin.example', port: 80 });
  await client.close();
});

test('a non-default port appears in Host', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client, net } = clientFor(server.handler);
  await (await client.fetch('http://origin.example:8080/')).text();
  assert.equal(server.seen[0].headers.get('host'), 'origin.example:8080');
  assert.equal(net.calls[0].addr.port, 8080);
  await client.close();
});

test('a POST body is sent with a matching Content-Length', async () => {
  const server = sequenceServer([
    async (head) => response({ body: `saw ${head.headers.get('content-length')} bytes` }),
  ]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/submit', {
    method: 'POST',
    body: 'name=value',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(await res.text(), 'saw 10 bytes');
  assert.equal(server.seen[0].headers.get('content-type'), 'application/x-www-form-urlencoded');
  await client.close();
});

test('a body-bearing method with no body still declares Content-Length: 0', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  await (await client.fetch('http://origin.example/', { method: 'POST' })).text();
  assert.equal(server.seen[0].headers.get('content-length'), '0');
  await client.close();
});

test('caller headers survive and are not clobbered', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  await (
    await client.fetch('http://origin.example/', {
      headers: { authorization: 'Bearer token', 'x-custom': 'v' },
    })
  ).text();
  assert.equal(server.seen[0].headers.get('authorization'), 'Bearer token');
  assert.equal(server.seen[0].headers.get('x-custom'), 'v');
  await client.close();
});

function concatBytes(a, b) {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

const CHUNKED_HEAD = utf8('HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n');

test('chunked responses are reassembled and trailers do not leak into the body', async () => {
  const server = sequenceServer([
    concatBytes(CHUNKED_HEAD, chunkedBody(['chun', 'ked ', 'body'], { 'x-trailer': 'yes' })),
  ]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/');
  assert.equal(await res.text(), 'chunked body', 'chunk sizes and trailers are framing, not payload');
  await client.close();
});

test('a chunked connection is eligible for reuse once the terminal chunk is consumed', async () => {
  const server = sequenceServer([
    concatBytes(CHUNKED_HEAD, chunkedBody(['a', 'b'])),
    response({ body: 'second' }),
  ]);
  const { client, net } = clientFor(server.handler);
  assert.equal(await (await client.fetch('http://origin.example/1')).text(), 'ab');
  assert.equal(await (await client.fetch('http://origin.example/2')).text(), 'second');
  assert.equal(net.calls.length, 1, 'chunked framing has a determinate end, so reuse is safe');
  await client.close();
});

test('a gzip response is decoded and its stale Content-Length is dropped', async () => {
  const packed = await gzip('compressed payload');
  const server = sequenceServer([
    response({ headers: { 'content-encoding': 'gzip' }, body: packed }),
  ]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/');
  assert.equal(await res.text(), 'compressed payload');
  assert.equal(res.headers.get('content-encoding'), 'gzip', 'the wire coding stays visible');
  assert.equal(
    res.headers.get('content-length'),
    null,
    'a length describing the encoded form would be a lie once decoded',
  );
  await client.close();
});

test('decompress:false hands back the encoded bytes untouched', async () => {
  const packed = await gzip('raw');
  const server = sequenceServer([
    response({ headers: { 'content-encoding': 'gzip' }, body: packed }),
  ]);
  const { client } = clientFor(server.handler, { decompress: false });
  const res = await client.fetch('http://origin.example/');
  assert.equal((await res.bytes()).byteLength, packed.byteLength);
  await client.close();
});

test('HEAD produces no body even when Content-Length says otherwise', async () => {
  const server = sequenceServer([utf8('HTTP/1.1 200 OK\r\ncontent-length: 99\r\n\r\n')]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/', { method: 'HEAD' });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), '');
  await client.close();
});

test('204 has no body and does not desynchronise the connection', async () => {
  const server = sequenceServer([
    utf8('HTTP/1.1 204 No Content\r\n\r\n'),
    response({ body: 'second' }),
  ]);
  const { client } = clientFor(server.handler);
  const first = await client.fetch('http://origin.example/a');
  assert.equal(first.status, 204);
  assert.equal(await first.text(), '');
  const second = await client.fetch('http://origin.example/b');
  assert.equal(await second.text(), 'second');
  assert.equal(server.seen.length, 2);
  await client.close();
});

// ------------------------------------------------------------------ keep-alive

test('a second request to the same origin reuses the connection', async () => {
  const server = sequenceServer([response({ body: 'one' }), response({ body: 'two' })]);
  const { client, net } = clientFor(server.handler);
  assert.equal(await (await client.fetch('http://origin.example/1')).text(), 'one');
  assert.equal(await (await client.fetch('http://origin.example/2')).text(), 'two');
  assert.equal(net.calls.length, 1, 'the second request must not open a new socket');
  assert.equal(client.pool.stats.hits, 1);
  await client.close();
});

test('Connection: close prevents reuse', async () => {
  const server = sequenceServer([
    response({ headers: { connection: 'close' }, body: 'one' }),
    response({ body: 'two' }),
  ]);
  const { client, net } = clientFor(server.handler);
  await (await client.fetch('http://origin.example/1')).text();
  await (await client.fetch('http://origin.example/2')).text();
  assert.equal(net.calls.length, 2, 'a connection the server said it would close cannot be pooled');
  await client.close();
});

test('a small body cancelled after the socket already drained it is still reusable', async () => {
  // The reuse rule is about the SOCKET reaching the framed end, not about the caller reading
  // everything. A short body is pulled into the stream's queue in one go, so the wire is already
  // at a clean boundary; discarding the buffered copy changes nothing on the connection.
  const server = sequenceServer([response({ body: 'ignored' }), response({ body: 'second' })]);
  const { client, net } = clientFor(server.handler);
  const first = await client.fetch('http://origin.example/1');
  await first.body.cancel();
  const second = await client.fetch('http://origin.example/2');
  assert.equal(await second.text(), 'second', 'the second response must not be the first one’s tail');
  assert.equal(net.calls.length, 1);
  await client.close();
});

test('a body abandoned mid-stream is never pooled', async () => {
  // This is the case that matters: bytes are still in flight, so the connection's position is
  // unknown and reusing it would splice the remains of one response onto the next request.
  const big = 'x'.repeat(300_000);
  const server = sequenceServer([response({ body: big }), response({ body: 'second' })]);
  const { client, net } = clientFor(server.handler);
  const first = await client.fetch('http://origin.example/1');
  const reader = first.body.getReader();
  const chunk = await reader.read();
  assert.ok(chunk.value.byteLength < big.length, 'the body must genuinely be unfinished');
  await reader.cancel(new Error('caller stopped reading'));
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(client.pool.idleCount, 0, 'an unfinished body has no safe reuse point');
  assert.equal(client.pool.stats.discarded, 1);
  const second = await client.fetch('http://origin.example/2');
  assert.equal(await second.text(), 'second', 'the second response must not be the first one’s tail');
  assert.equal(net.calls.length, 2);
  await client.close();
});

test('an EOF-framed body is read to the close and never pooled', async () => {
  const server = sequenceServer(
    [concatBytes(utf8('HTTP/1.1 200 OK\r\n\r\n'), utf8('framed by close'))],
    { closeAfterLast: true },
  );
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/');
  assert.equal(res.tunnelfetch.framing, 'until-close');
  assert.equal(await res.text(), 'framed by close');
  assert.equal(client.pool.idleCount, 0, 'a body with no determinate end has no safe reuse point');
  await client.close();
});

test('different origins do not share a pooled connection', async () => {
  const server = sequenceServer([response({ body: 'a' }), response({ body: 'b' })]);
  const { client, net } = clientFor(server.handler);
  await (await client.fetch('http://one.example/')).text();
  await (await client.fetch('http://two.example/')).text();
  assert.equal(net.calls.length, 2);
  await client.close();
});

// ------------------------------------------------------------------ redirects

test('a 302 to a relative path is followed and reports the final url', async () => {
  const server = sequenceServer([
    response({ status: 302, reason: 'Found', headers: { location: '/final' }, body: '' }),
    response({ body: 'arrived' }),
  ]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/start');
  assert.equal(await res.text(), 'arrived');
  assert.equal(res.url, 'http://origin.example/final');
  assert.equal(res.redirected, true);
  assert.deepEqual(server.seen.map((r) => r.target), ['/start', '/final']);
  await client.close();
});

test('a 302 rewrites POST to GET and drops the body', async () => {
  const server = sequenceServer([
    response({ status: 302, headers: { location: '/after' }, body: '' }),
    response({ body: 'done' }),
  ]);
  const { client } = clientFor(server.handler);
  await (await client.fetch('http://origin.example/post', { method: 'POST', body: 'x=1' })).text();
  assert.equal(server.seen[1].method, 'GET');
  assert.equal(server.seen[1].headers.get('content-length'), undefined);
  await client.close();
});

test('307 preserves the method and replays the body', async () => {
  const server = sequenceServer([
    response({ status: 307, headers: { location: '/again' }, body: '' }),
    response({ body: 'ok' }),
  ]);
  const { client } = clientFor(server.handler);
  await (await client.fetch('http://origin.example/p', { method: 'POST', body: 'payload' })).text();
  assert.equal(server.seen[1].method, 'POST');
  assert.equal(server.seen[1].headers.get('content-length'), '7');
  await client.close();
});

test('credentials are stripped when a redirect crosses hosts', async () => {
  const server = sequenceServer([
    response({ status: 302, headers: { location: 'http://elsewhere.example/x' }, body: '' }),
    response({ body: 'ok' }),
  ]);
  const { client } = clientFor(server.handler);
  await (
    await client.fetch('http://origin.example/', {
      headers: { authorization: 'Bearer secret', cookie: 'sid=1' },
    })
  ).text();
  const second = server.seen[1];
  assert.equal(second.headers.get('authorization'), undefined, 'Authorization must not follow');
  assert.equal(second.headers.get('cookie'), undefined, 'Cookie must not follow');
  assert.equal(second.headers.get('host'), 'elsewhere.example');
  await client.close();
});

test('credentials survive a same-origin redirect', async () => {
  const server = sequenceServer([
    response({ status: 302, headers: { location: '/next' }, body: '' }),
    response({ body: 'ok' }),
  ]);
  const { client } = clientFor(server.handler);
  await (
    await client.fetch('http://origin.example/', { headers: { authorization: 'Bearer keep' } })
  ).text();
  assert.equal(server.seen[1].headers.get('authorization'), 'Bearer keep');
  await client.close();
});

test('redirect:manual hands the 3xx straight back', async () => {
  const server = sequenceServer([
    response({ status: 302, headers: { location: '/never' }, body: '' }),
  ]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/', { redirect: 'manual' });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get('location'), '/never');
  assert.equal(server.seen.length, 1);
  await client.close();
});

test('an endless redirect chain is stopped by the limit', async () => {
  const server = sequenceServer([
    (head) => response({ status: 302, headers: { location: `${head.target}x` }, body: '' }),
  ]);
  const { client } = clientFor(server.handler, { maxRedirects: 3 });
  await rejectsWithCode(() => client.fetch('http://origin.example/a'), 'LIMIT_REDIRECTS');
  await client.close();
});

test('a redirect to a non-http scheme is refused', async () => {
  const server = sequenceServer([
    response({ status: 302, headers: { location: 'file:///etc/passwd' }, body: '' }),
  ]);
  const { client } = clientFor(server.handler);
  await rejectsWithCode(() => client.fetch('http://origin.example/'), 'REDIRECT_SCHEME');
  await client.close();
});

// ------------------------------------------------------------------ cookies

test('a cookie jar stores Set-Cookie and replays it to the same host', async () => {
  const server = sequenceServer([
    response({ headers: { 'set-cookie': ['sid=abc; Path=/', 'pref=dark; Path=/'] }, body: 'one' }),
    response({ body: 'two' }),
  ]);
  const { client } = clientFor(server.handler, { cookies: true });
  await (await client.fetch('http://origin.example/')).text();
  await (await client.fetch('http://origin.example/next')).text();
  const cookie = server.seen[1].headers.get('cookie');
  assert.match(cookie, /sid=abc/);
  assert.match(cookie, /pref=dark/);
  await client.close();
});

test('Set-Cookie stays separable on the Response despite header folding', async () => {
  const server = sequenceServer([
    response({ headers: { 'set-cookie': ['a=1; Path=/', 'b=2; Path=/'] }, body: '' }),
  ]);
  const { client } = clientFor(server.handler, { cookies: true });
  const res = await client.fetch('http://origin.example/');
  assert.deepEqual(res.headers.getSetCookie?.() ?? [], ['a=1; Path=/', 'b=2; Path=/']);
  await client.close();
});

test('cookies are not sent to a different host', async () => {
  const server = sequenceServer([
    response({ headers: { 'set-cookie': 'sid=abc; Path=/' }, body: '' }),
    response({ body: '' }),
  ]);
  const { client } = clientFor(server.handler, { cookies: true });
  await (await client.fetch('http://one.example/')).text();
  await (await client.fetch('http://two.example/')).text();
  assert.equal(server.seen[1].headers.get('cookie'), undefined);
  await client.close();
});

// ------------------------------------------------------------------ configuration and limits

test('a request needing a tunnel with no connect function says exactly what is missing', async () => {
  const client = new Client({ proxy: 'http://p.example:8080' });
  const err = await rejectsWithCode(
    () => client.fetch('http://origin.example/'),
    'CONFIG_UNSATISFIABLE',
  );
  assert.match(err.message, /proxy was configured/);
  assert.match(err.message, /connect/);
  await client.close();
});

test('an over-limit body is refused from the declared length alone', async () => {
  const server = sequenceServer([response({ body: 'x'.repeat(5000) })]);
  const { client } = clientFor(server.handler, { maxBodyBytes: 100 });
  await rejectsWithCode(() => client.fetch('http://origin.example/'), 'LIMIT_BODY');
  await client.close();
});

test('a closed Client refuses further requests', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  await client.close();
  await rejectsWithCode(() => client.fetch('http://origin.example/'), 'POOL_CLOSED');
});

test('connection metadata is attached to the response', async () => {
  const server = sequenceServer([response({ body: 'ok', version: '1.0' })]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/');
  await res.text();
  assert.equal(res.tunnelfetch.httpVersion, '1.0');
  assert.equal(res.tunnelfetch.proxied, false);
  assert.equal(res.tunnelfetch.tls, null);
  assert.equal(res.tunnelfetch.framing, 'content-length');
  await client.close();
});

test('an HTTP/1.0 response without keep-alive is not pooled', async () => {
  const server = sequenceServer([response({ body: 'ok', version: '1.0' })]);
  const { client } = clientFor(server.handler);
  await (await client.fetch('http://origin.example/')).text();
  assert.equal(client.pool.idleCount, 0, 'HTTP/1.0 defaults to close');
  await client.close();
});

// ------------------------------------------------------------------ install()

test('install replaces the global fetch and its undo restores it', async () => {
  const before = globalThis.fetch;
  const server = sequenceServer([response({ body: 'via global' })]);
  const net = fakeNetwork(server.handler);
  const uninstall = install({ connect: net.connect, forceTunnel: true });
  try {
    assert.notEqual(globalThis.fetch, before, 'the global must actually be replaced');
    const res = await globalThis.fetch('http://origin.example/');
    assert.equal(await res.text(), 'via global');
  } finally {
    uninstall();
  }
  assert.equal(globalThis.fetch, before, 'uninstall must restore exactly what was there');
  uninstall(); // idempotent
  assert.equal(globalThis.fetch, before);
});

test('uninstall does not clobber a third party that replaced the global after us', () => {
  const before = globalThis.fetch;
  const uninstall = install({});
  const theirs = () => {};
  globalThis.fetch = theirs;
  uninstall();
  assert.equal(globalThis.fetch, theirs, 'someone else owns the global now; leave it alone');
  globalThis.fetch = before;
});

test('createFetch produces a standalone function that closes its own client', async () => {
  const server = sequenceServer([response({ body: 'standalone' })]);
  const net = fakeNetwork(server.handler);
  const f = createFetch({ connect: net.connect, forceTunnel: true });
  assert.equal(await (await f('http://origin.example/')).text(), 'standalone');
});

test('the module never installs itself on import', async () => {
  const before = globalThis.fetch;
  await import('../src/index.js');
  assert.equal(globalThis.fetch, before, 'importing must never touch the global');
});

test('header values carrying CRLF cannot smuggle a second request', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  // Headers itself rejects most of these, so assert the request never reaches the wire either way.
  await assert.rejects(async () => {
    const res = await client.fetch('http://origin.example/', {
      headers: [['x-evil', 'a\r\nGET /admin HTTP/1.1\r\nHost: origin.example']],
    });
    await res.text();
  });
  assert.equal(server.seen.length, 0, 'nothing may be written for a request that cannot be framed');
  await client.close();
});

test('a header carrying a high octet is decoded as latin-1, not mangled as UTF-8', async () => {
  // Header field values are opaque octets (RFC 9110 obs-text). 0xE9 is a lone byte that is not
  // valid UTF-8; decoding it as UTF-8 would produce U+FFFD and lose the value irrecoverably.
  const head = new Uint8Array([
    ...utf8('HTTP/1.1 200 OK\r\nx-note: caf'),
    0xe9,
    ...utf8('\r\ncontent-length: 2\r\n\r\nok'),
  ]);
  const server = sequenceServer([head]);
  const { client } = clientFor(server.handler);
  const res = await client.fetch('http://origin.example/');
  assert.equal(await res.text(), 'ok');
  assert.equal(res.headers.get('x-note'), `caf${latin1(new Uint8Array([0xe9]))}`);
  assert.ok(!res.headers.get('x-note').includes('�'), 'the octet must not become a replacement char');
  await client.close();
});

test('a Client keeps its own copy of the trust policy, so later mutation cannot cross the pool', () => {
  // `{ ...options }` was a shallow copy, so `client.options.trust` stayed the caller's object: a
  // caller could flip revocation or swap pins after construction and the next request would run
  // under the new policy over connections verified under the old one. The pool key covers every
  // field the verifier reads, but a key computed from a mutable object is only as stable as it is.
  const pins = ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='];
  const trust = { mode: 'pinned', pins };
  const client = new Client({ trust });

  trust.revocation = 'require-staple';
  trust.mode = 'none';
  pins.push('sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=');

  assert.equal(client.options.trust.mode, 'pinned');
  assert.equal(client.options.trust.revocation, undefined);
  assert.equal(client.options.trust.pins.length, 1);
  assert.equal(Object.isFrozen(client.options), true);
});

test('a registered decoder reaches both the advertisement and the body, end to end', async () => {
  // Proves the wiring, not just the unit: `decoders` must reach the Accept-Encoding the request
  // layer writes AND the decode stage the response body passes through. Those are two separate
  // call sites and a change to one without the other silently breaks the invariant that we only
  // ask for codings we can read.
  //
  // The stand-in "brotli" is a byte-reversal, so a body that came back right cannot have skipped
  // the decoder or run it twice.
  const reverse = (stream) =>
    stream.pipeThrough(
      new TransformStream({
        transform(chunk, c) {
          c.enqueue(chunk.slice().reverse());
        },
      }),
    );
  const server = sequenceServer([
    response({ body: 'olleh', headers: { 'content-encoding': 'br' } }),
  ]);
  const { client } = clientFor(server.handler, { decoders: { br: reverse } });

  const res = await client.fetch('http://origin.example/');
  assert.equal(await res.text(), 'hello');
  assert.equal(server.seen[0].headers.get('accept-encoding'), 'gzip, deflate, br');
  await client.close();
});

test('without a decoder a br body is refused rather than handed back as garbage', async () => {
  const server = sequenceServer([
    response({ body: 'not really brotli', headers: { 'content-encoding': 'br' } }),
  ]);
  const { client } = clientFor(server.handler);
  await assert.rejects(
    () => client.fetch('http://origin.example/'),
    (e) => e.code === 'HTTP_CONTENT_ENCODING',
  );
  await client.close();
});

test('a Client copies the BYTES of its trust anchors, not just the array holding them', async () => {
  // Found in review, and the gap in an earlier fix: freezing `[...anchors]` gives a frozen array
  // whose elements are still the caller's Uint8Arrays, and freezing a typed array does not freeze
  // its bytes. Writing into an anchor's DER after construction therefore changed the certificate
  // material the Client validated against — while the pool key stayed put, because anchorDigest
  // memoises per array object and never saw a new one.
  const { poolKey } = await import('../src/pool.js');
  const der = Uint8Array.from([0x30, 0x82, 0x01, 0x00, 0xaa, 0xbb, 0xcc]);
  const client = new Client({ trust: { mode: 'anchors', anchors: [der] } });

  const keyOf = () =>
    poolKey({
      scheme: 'https:', hostname: 'a.example', port: 443,
      proxy: null, tls: null, trust: client.options.trust,
    });
  const before = keyOf();
  const seen = Array.from(client.options.trust.anchors[0]);

  der[4] = 0x00;
  der[5] = 0x11;
  der[6] = 0x22;

  assert.deepEqual(
    Array.from(client.options.trust.anchors[0]),
    seen,
    'mutating the caller\'s DER changed what this Client trusts',
  );
  assert.equal(keyOf(), before, 'the pool key moved when nothing the Client owns had changed');
});

test('the config copy leaves live objects and function identity alone', () => {
  // The copy must not be indiscriminate. `trust.verify` is what distinguishes one custom policy
  // from another in the pool key, via a WeakMap on the function itself — a copy would make every
  // Client look like a different policy. A CookieJar and an AbortSignal are behaviour, not data.
  const verify = async () => {};
  const jar = new CookieJar();
  const ac = new AbortController();
  const client = new Client({ trust: { mode: 'custom', verify }, cookies: true, jar, signal: ac.signal });
  assert.equal(client.options.trust.verify, verify);
  assert.equal(client.jar, jar);
  assert.equal(client.options.signal, ac.signal);
});

test('mutable tls options are copied too, not only trust', () => {
  const groups = [0x001d, 0x0017];
  const clientRandom = Uint8Array.from({ length: 32 }, (_, i) => i);
  const client = new Client({ tls: { groups, clientRandom } });
  groups.push(0x0018);
  clientRandom[0] = 0xff;
  assert.deepEqual(client.options.tls.groups, [0x001d, 0x0017]);
  assert.equal(client.options.tls.clientRandom[0], 0);
});
