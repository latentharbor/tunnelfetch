// The fetch facade over HTTP/2. These drive the real public `client.fetch`, so they exercise
// everything sendAndReceiveH2 touches — request header building (pseudo-header order, dropped
// connection headers, :authority), the response detail (httpVersion '2', framing 'h2'), cookies,
// content decoding, redirects, and request bodies — end to end against the scriptable h2 server.
//
// The one seam: an h2 connection is pre-registered in the Client's h2 map rather than negotiated
// through a real TLS handshake, because ALPN negotiation needs a real userland handshake (proven
// on the edge, and in tls-h2.test.js). Everything ABOVE the negotiation runs unmodified here.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { poolKey } from '../../src/pool.js';
import { Http2Connection } from '../../src/http2/connection.js';
import { duplexPair } from '../_harness.js';
import { h2Server } from './_server.js';
import { FRAME } from '../../src/http2/constants.js';
import { gzip } from '../_fakenet.js';

const enc = new TextEncoder();

/**
 * A Client with an HTTP/2 connection pre-registered for `https://origin.example/`. `forceTunnel`
 * keeps the platform fetch out of the way; `connect` is a poison pill because the h2 path must be
 * taken from the registry, never dialled.
 */
function h2Client(info = {}) {
  const client = new Client({
    forceTunnel: true,
    connect: () => {
      throw new Error('the pre-registered h2 connection must be used, not a fresh dial');
    },
    ...info.clientOptions,
  });
  const { a, b } = duplexPair();
  const server = h2Server(b);
  const conn = new Http2Connection(a, {
    info: {
      url: 'https://origin.example/',
      proxied: true,
      proxy: 'http://proxy.example:8080',
      tls: { version: 0x0304, cipherSuite: 0x1301, group: 0x001d, alpnProtocol: 'h2', hostname: 'origin.example' },
    },
  });
  const key = poolKey({
    scheme: 'https:',
    hostname: 'origin.example',
    port: 443,
    proxy: null,
    trust: { mode: 'system' },
    tls: {},
  });
  // Register exactly as registerHttp2 does: into the keyed dispatch map and the live-connection set.
  client._h2.set(key, conn);
  client._h2conns.add(conn);
  return { client, server, conn };
}

/** Answer the next request the server receives with a scripted response. */
async function answer(server, streamId, fields, body, { trailers } = {}) {
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === streamId);
  const endOnHeaders = body === undefined && !trailers;
  await server.sendResponse(streamId, fields, { endStream: endOnHeaders });
  if (body !== undefined) {
    await server.sendData(streamId, typeof body === 'string' ? enc.encode(body) : body, !trailers);
  }
  if (trailers) await server.sendTrailers(streamId, trailers);
}

test('a GET over h2 returns the response and the tunnelfetch detail reports h2', async () => {
  const { client, server } = h2Client();
  const p = client.fetch('https://origin.example/thing');
  await answer(server, 1, [{ name: ':status', value: '200' }, { name: 'content-type', value: 'text/plain' }], 'hi h2');
  const res = await p;
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'hi h2');
  assert.equal(res.tunnelfetch.httpVersion, '2');
  assert.equal(res.tunnelfetch.framing, 'h2');
  assert.equal(res.tunnelfetch.proxied, true);
  assert.equal(res.tunnelfetch.tls.alpnProtocol, 'h2');
  await client.close();
});

test('the request carries pseudo-headers in curl order and a proper :authority', async () => {
  const { client, server } = h2Client();
  const p = client.fetch('https://origin.example/a/b?q=1', { headers: { 'x-custom': 'v' } });
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 1);
  const req = server.requests.get(1);
  const names = req.pairs.map(([n]) => n);
  assert.deepEqual(names.slice(0, 4), [':method', ':scheme', ':authority', ':path']);
  assert.equal(req.headers.get(':authority'), 'origin.example', 'authority from the URL, default port omitted');
  assert.equal(req.headers.get(':path'), '/a/b?q=1');
  assert.equal(req.headers.get(':scheme'), 'https');
  assert.equal(req.headers.get('x-custom'), 'v');
  assert.equal(req.headers.get('accept'), '*/*', 'a default accept is added');
  assert.equal(req.headers.get('accept-encoding'), 'gzip, deflate');
  assert.equal(req.headers.has('connection'), false, 'no connection-specific header in h2');
  assert.equal(req.headers.has('host'), false, 'Host becomes :authority, never a regular field');
  await server.sendResponse(1, [{ name: ':status', value: '200' }], { endStream: true });
  await p;
  await client.close();
});

test('a gzip response is decoded and its Content-Length is dropped', async () => {
  const { client, server } = h2Client();
  const packed = await gzip('compressed over h2');
  const p = client.fetch('https://origin.example/');
  await answer(
    server,
    1,
    [{ name: ':status', value: '200' }, { name: 'content-encoding', value: 'gzip' }, { name: 'content-length', value: String(packed.byteLength) }],
    packed,
  );
  const res = await p;
  assert.equal(await res.text(), 'compressed over h2');
  assert.equal(res.headers.get('content-encoding'), 'gzip');
  assert.equal(res.headers.get('content-length'), null);
  await client.close();
});

test('a POST body is sent with a matching content-length', async () => {
  const { client, server } = h2Client();
  const p = client.fetch('https://origin.example/submit', { method: 'POST', body: 'name=value' });
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 1);
  const req = server.requests.get(1);
  assert.equal(req.headers.get('content-length'), '10');
  assert.equal(req.headers.get(':method'), 'POST');
  // wait for the body DATA to arrive
  await new Promise((r) => setTimeout(r, 20));
  const got = req.body.reduce((s, c) => s + c.byteLength, 0);
  assert.equal(got, 10);
  await server.sendResponse(1, [{ name: ':status', value: '201' }], { endStream: true });
  assert.equal((await p).status, 201);
  await client.close();
});

test('set-cookie from an h2 response is stored and sent on the next request', async () => {
  const { client, server } = h2Client({ clientOptions: { cookies: true } });
  const p1 = client.fetch('https://origin.example/login');
  await answer(server, 1, [{ name: ':status', value: '200' }, { name: 'set-cookie', value: 'sid=abc; Path=/' }], 'ok');
  await (await p1).text();

  const p2 = client.fetch('https://origin.example/next');
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 3);
  assert.equal(server.requests.get(3).headers.get('cookie'), 'sid=abc');
  await server.sendResponse(3, [{ name: ':status', value: '200' }], { endStream: true });
  await p2;
  await client.close();
});

test('multiple set-cookie fields stay separate (not folded)', async () => {
  const { client, server } = h2Client({ clientOptions: { cookies: true } });
  const p = client.fetch('https://origin.example/');
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 1);
  await server.sendResponse(
    1,
    [
      { name: ':status', value: '200' },
      { name: 'set-cookie', value: 'a=1; Path=/' },
      { name: 'set-cookie', value: 'b=2; Path=/' },
    ],
    { endStream: true },
  );
  const res = await p;
  const cookies = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get('set-cookie')];
  assert.ok(cookies.some((c) => c.startsWith('a=1')));
  assert.ok(cookies.some((c) => c.startsWith('b=2')));
  await client.close();
});

test('a 302 redirect is followed over the same h2 connection', async () => {
  const { client, server } = h2Client();
  const p = client.fetch('https://origin.example/old');
  await answer(server, 1, [{ name: ':status', value: '302' }, { name: 'location', value: 'https://origin.example/new' }], '');
  await answer(server, 3, [{ name: ':status', value: '200' }], 'landed');
  const res = await p;
  assert.equal(res.status, 200);
  assert.equal(await res.text(), 'landed');
  assert.equal(res.redirected, true);
  assert.equal(server.requests.get(3).headers.get(':path'), '/new');
  await client.close();
});

test('a streaming h2 body is delivered incrementally through fetch', async () => {
  const { client, server } = h2Client();
  const p = client.fetch('https://origin.example/stream');
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 1);
  await server.sendResponse(1, [{ name: ':status', value: '200' }, { name: 'content-type', value: 'text/event-stream' }]);
  const res = await p;
  const reader = res.body.getReader();
  await server.sendData(1, enc.encode('event: one\n\n'), false);
  const first = await reader.read();
  assert.match(new TextDecoder().decode(first.value), /event: one/);
  await server.sendData(1, enc.encode('event: two\n\n'), true);
  const second = await reader.read();
  assert.match(new TextDecoder().decode(second.value), /event: two/);
  assert.equal((await reader.read()).done, true);
  await client.close();
});

test('close() reaches an h2 connection orphaned from the keyed map (race safety)', async () => {
  const { client, server } = h2Client();
  const p = client.fetch('https://origin.example/');
  await answer(server, 1, [{ name: ':status', value: '200' }], '');
  await (await p).text();
  // Simulate the loser of a concurrent-first-request race: still live and in the tracking set,
  // but no longer the keyed connection for its key. close() must still close it.
  const key = [...client._h2.keys()][0];
  const orphan = client._h2.get(key);
  client._h2.delete(key);
  assert.ok(client._h2conns.has(orphan), 'the live connection is still tracked outside the map');
  await client.close();
  assert.equal(orphan.canDispatch(), false, 'the orphaned connection was closed by close()');
});

test('a second request reuses the shared h2 connection (no new dial)', async () => {
  const { client, server, conn } = h2Client();
  const p1 = client.fetch('https://origin.example/1');
  await answer(server, 1, [{ name: ':status', value: '200' }], 'a');
  await (await p1).text();
  const p2 = client.fetch('https://origin.example/2');
  await answer(server, 3, [{ name: ':status', value: '200' }], 'b');
  assert.equal(await (await p2).text(), 'b');
  // Both requests were streams on the one connection (ids 1 and 3), never a fresh connection.
  assert.equal(conn._nextStreamId, 5, 'two streams opened on the same connection');
  await client.close();
});

test('a registered decoder is advertised and applied over h2 as well as h1', async () => {
  // h1 and h2 build their request headers in separate functions, so `decoders` reaching one says
  // nothing about the other. This covers buildH2Request; the h1 side is covered in client.test.js.
  const reverse = (stream) =>
    stream.pipeThrough(
      new TransformStream({
        transform(chunk, c) {
          c.enqueue(chunk.slice().reverse());
        },
      }),
    );
  const { client, server } = h2Client({ clientOptions: { decoders: { br: reverse } } });
  const p = client.fetch('https://origin.example/');
  await answer(
    server,
    1,
    [{ name: ':status', value: '200' }, { name: 'content-encoding', value: 'br' }],
    enc.encode('2h revo rb'),
  );
  const res = await p;
  assert.equal(await res.text(), 'br over h2');
  assert.equal(server.requests.get(1).headers.get('accept-encoding'), 'gzip, deflate, br');
  await client.close();
});

test('a Client can set the HTTP/2 SETTINGS flight, so both halves of the fingerprint are reachable', () => {
  // The TLS half is configurable through `tls.extensionOrder` and friends; this is the h2 half.
  // Asserted at the Client boundary because that is where a user actually configures it — the
  // option existing on Http2Connection says nothing about whether it can be reached.
  const flight = [
    [0x1, 65536],
    [0x2, 0],
    [0x4, 6291456],
  ];
  const client = new Client({ http2Settings: flight });
  assert.deepEqual(client.options.http2Settings, flight);
  // Frozen with the rest of the security-relevant config, so it cannot change under a live pool.
  assert.equal(Object.isFrozen(client.options), true);
});
