// Request header order and case, which is the part of a fingerprint visible without inspecting a
// single TLS byte. Any middlebox reads it.
//
// Reference: curl 8.21.0, captured off the wire:
//
//   POST / HTTP/1.1
//   Host / User-Agent / Accept / Accept-Encoding / <the caller's headers, in order>
//   Content-Length / Content-Type
//
// Note where the framing headers go — last, AFTER the caller's — which is why the order list has a
// `'*'` marker instead of being a plain ranking.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { OrderedHeaders, CURL_HEADER_ORDER, callerHeaderOrder } from '../../src/client/header-order.js';
import { fakeNetwork, sequenceServer, response } from '../_fakenet.js';

const clientFor = (handler, options = {}) => {
  const net = fakeNetwork(handler);
  return { client: new Client({ connect: net.connect, forceTunnel: true, ...options }), net };
};

// ------------------------------------------------------------------ the ordered list itself

test('lookup and mutation are case-insensitive, iteration keeps the case it was given', () => {
  const h = new OrderedHeaders([['X-Custom', '1']]);
  assert.equal(h.get('x-CUSTOM'), '1');
  assert.equal(h.has('X-custom'), true);
  assert.deepEqual(h.entries(), [['X-Custom', '1']]);
});

test('set replaces in place rather than moving a field to the end', () => {
  // Otherwise every internal `set` silently reorders the request — a caller who wrote User-Agent
  // first and had it overwritten would find it last.
  const h = new OrderedHeaders([['User-Agent', 'a'], ['Accept', 'b']]);
  h.set('user-agent', 'c');
  assert.deepEqual(h.entries(), [['User-Agent', 'c'], ['Accept', 'b']]);
});

test('a repeated field collapses to one value at the first position, like Headers.set', () => {
  const h = new OrderedHeaders([['A', '1'], ['B', '2'], ['a', '3']]);
  h.set('A', 'x');
  assert.deepEqual(h.entries(), [['A', 'x'], ['B', '2']]);
});

test('reorder groups by the list and keeps relative order inside each group', () => {
  const h = new OrderedHeaders([
    ['Content-Length', '3'], ['Zed', '1'], ['Accept', '*/*'], ['Alpha', '2'], ['Host', 'h'],
  ]);
  h.reorder(CURL_HEADER_ORDER);
  assert.deepEqual(
    h.entries().map(([n]) => n),
    // Zed before Alpha: unnamed fields keep the order they arrived in, they are not sorted.
    ['Host', 'Accept', 'Zed', 'Alpha', 'Content-Length'],
  );
});

test("without a '*' marker, unnamed fields go last", () => {
  const h = new OrderedHeaders([['Zed', '1'], ['Accept', '2'], ['Host', '3']]);
  h.reorder(['host', 'accept']);
  assert.deepEqual(h.entries().map(([n]) => n), ['Host', 'Accept', 'Zed']);
});

test('the caller order is recovered from an array or an object, and honestly not from a Headers', () => {
  assert.deepEqual(callerHeaderOrder('http://x/', { headers: [['B', '1'], ['A', '2']] }), [['B', '1'], ['A', '2']]);
  assert.deepEqual(callerHeaderOrder('http://x/', { headers: { B: '1', A: '2' } }), [['B', '1'], ['A', '2']]);
  // A Headers was normalised before this package saw it. There is nothing to reconstruct and
  // pretending otherwise would invent an order the caller never wrote.
  assert.equal(callerHeaderOrder('http://x/', { headers: new Headers({ b: '1' }) }), null);
  assert.equal(callerHeaderOrder('http://x/', {}), null);
});

// ------------------------------------------------------------------ end to end, on the wire

test('the wire order is curl\'s: package headers first, caller\'s in the middle, framing last', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  await client.fetch('http://origin.example/', {
    method: 'POST',
    body: 'x=1',
    headers: [['User-Agent', 'tf/1'], ['Referer', 'https://r.test/'], ['X-Custom', '1']],
  });
  assert.deepEqual(server.seen[0].order, [
    'host',
    'user-agent',
    'accept',
    'accept-encoding',
    'referer',
    'x-custom',
    'connection',
    'content-length',
  ]);
  await client.close();
});

test('a caller header that the package also sets keeps the caller position, not a moved one', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  // `accept` is supplied by the caller AND defaulted by the package; the ordering must not depend
  // on which happened first.
  await client.fetch('http://origin.example/', {
    headers: [['Accept', 'text/html'], ['X-A', '1']],
  });
  const order = server.seen[0].order;
  assert.ok(order.indexOf('accept') < order.indexOf('x-a'), `accept came after x-a: ${order}`);
  assert.equal(server.seen[0].headers.get('accept'), 'text/html', 'the caller value was overwritten');
  await client.close();
});

test('header case reaches the HTTP/1.1 wire, because real clients send `Host:` not `host:`', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler);
  await client.fetch('http://origin.example/', { headers: [['X-Mixed-Case', '1']] });
  // Read the raw request head, not the parsed view: a parser lowercases, and lowercasing is
  // exactly what is under test.
  assert.match(server.seen[0].raw, /\r\nHost: origin\.example\r\n/);
  assert.match(server.seen[0].raw, /\r\nX-Mixed-Case: 1\r\n/);
  await client.close();
});

test('the order is configurable', async () => {
  const server = sequenceServer([response({ body: 'ok' })]);
  const { client } = clientFor(server.handler, {
    headerOrder: ['host', 'x-first', '*', 'accept'],
  });
  await client.fetch('http://origin.example/', { headers: [['X-First', '1'], ['X-Other', '2']] });
  const order = server.seen[0].order;
  assert.equal(order[0], 'host');
  assert.equal(order[1], 'x-first');
  assert.equal(order.at(-1), 'accept', 'a name placed after the marker did not go last');
  await client.close();
});
