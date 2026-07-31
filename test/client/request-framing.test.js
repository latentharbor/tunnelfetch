// Request-side message framing, ported from the RFC 9112 §6 request-smuggling corpus and the
// Fetch-standard "forbidden request headers" list (Content-Length and Transfer-Encoding are the
// user agent's to set, never the caller's).
//
// This is the mirror of bodyFraming(): that function refuses an INBOUND message that carries both
// Content-Length and Transfer-Encoding, calling it "the canonical smuggling probe". A client that
// EMITS that same pair on its own requests hands a front-end/back-end proxy pair the exact
// disagreement the response side is so careful to reject. The client buffers every body whole and
// frames it with Content-Length, so it must never let a caller's stale/ hostile framing header
// reach the wire.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { fakeNetwork, readRequestHead, response } from '../_fakenet.js';

/** A server that records the raw request-head text of every request it sees. */
function captureServer() {
  const heads = [];
  const handler = async ({ reader, write }) => {
    for (;;) {
      let head;
      try {
        head = await readRequestHead(reader);
      } catch {
        return;
      }
      heads.push(head);
      const declared = Number(head.headers.get('content-length') ?? 0);
      if (declared > 0) {
        try {
          await reader.readExactly(declared, 'request body');
        } catch {
          /* client gone */
        }
      }
      await write(response({ body: 'ok' }));
    }
  };
  return { handler, heads };
}

/** Send one request and return the head the server parsed (or null if none arrived). */
async function send(init, url = 'http://origin.example/') {
  const server = captureServer();
  const net = fakeNetwork(server.handler);
  // A short headers deadline so a self-inflicted desync (server waiting for body bytes that never
  // come) surfaces as a bounded failure rather than hanging the test.
  const client = new Client({ connect: net.connect, forceTunnel: true, timeouts: { headersMs: 500 } });
  let error = null;
  try {
    const res = await client.fetch(url, init);
    if (res.body) await res.text();
  } catch (e) {
    error = e.code;
  }
  await client.close();
  return { head: server.heads[0] ?? null, error, calls: net.calls.length };
}

test('a caller Content-Length on a bodyless GET is dropped, not sent as a false body length', async () => {
  // RFC 9110 §8.6: the Content-Length must equal the number of body octets. A GET with no body and
  // "Content-Length: 100" tells the peer to wait for 100 bytes that never arrive — a desync, and
  // through a proxy a request-smuggling primitive.
  const { head } = await send({ method: 'GET', headers: { 'content-length': '100' } });
  assert.equal(head.headers.get('content-length'), undefined, 'the bogus Content-Length must not reach the wire');
});

test('a caller Transfer-Encoding is dropped: this client never chunk-encodes a request body', async () => {
  const { head } = await send({ method: 'POST', body: 'hello', headers: { 'transfer-encoding': 'chunked' } });
  assert.equal(head.headers.get('transfer-encoding'), undefined, 'Transfer-Encoding must not reach the wire');
  assert.equal(head.headers.get('content-length'), '5', 'the body is framed by its true length');
});

test('Content-Length and Transfer-Encoding never appear together (RFC 9112 §6.1)', async () => {
  // The exact ambiguity bodyFraming() throws HTTP_FRAMING_AMBIGUOUS for on the response side.
  const { head } = await send({
    method: 'POST',
    body: 'hello',
    headers: { 'transfer-encoding': 'chunked', 'content-length': '999' },
  });
  const hasTE = head.headers.get('transfer-encoding') !== undefined;
  const hasCL = head.headers.get('content-length') !== undefined;
  assert.ok(!(hasTE && hasCL), 'a request must not carry both framing headers');
  assert.equal(head.headers.get('transfer-encoding'), undefined);
  assert.equal(head.headers.get('content-length'), '5', 'only the true body length is declared');
});

test('a caller Content-Length that understates the real body is overridden with the truth', async () => {
  const { head } = await send({ method: 'POST', body: 'hello', headers: { 'content-length': '3' } });
  assert.equal(head.headers.get('content-length'), '5', 'the wire length must match the bytes actually written');
});

test('a caller Transfer-Encoding on a bodyless GET is dropped (no phantom chunked framing)', async () => {
  const { head } = await send({ method: 'GET', headers: { 'transfer-encoding': 'chunked' } });
  assert.equal(head.headers.get('transfer-encoding'), undefined);
  assert.equal(head.headers.get('content-length'), undefined, 'a bodyless GET declares no body at all');
});

test('body-bearing methods with no body still declare Content-Length: 0', async () => {
  for (const method of ['POST', 'PUT', 'PATCH']) {
    const { head } = await send({ method });
    assert.equal(head.headers.get('content-length'), '0', `${method} with no body`);
  }
});

test('a real body is framed by its exact byte length', async () => {
  const { head } = await send({ method: 'POST', body: 'name=value&x=1' });
  assert.equal(head.headers.get('content-length'), '14');
  assert.equal(head.headers.get('transfer-encoding'), undefined);
});
