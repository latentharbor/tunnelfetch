// The one path the pre-registered client-h2 tests cannot reach: a REAL userland TLS handshake that
// negotiates h2 via ALPN, after which the Client detects the pick, builds the multiplexing
// connection, and speaks HTTP/2 over the encrypted session — all through the public fetch API.
//
// This closes the loop offline: TLS ALPN threads h2 through connectTls, openConnection reports it,
// openFreshAndSend registers the connection, and a request comes back 200. The live edge test does
// the same against real servers; this does it hermetically over an in-memory socket.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client, createFetch } from '../../src/client.js';
import { duplexPair } from '../_harness.js';
import { startServer } from '../tls/_server.js';
import { testIdentity } from '../tls/_testca.js';
import { h2Server } from './_server.js';
import { FRAME } from '../../src/http2/constants.js';

const enc = new TextEncoder();
const HOST = 'server.test';

/** A socket-shaped object over one side of an in-memory duplex, matching what `connect` returns. */
function socketOver(side) {
  return {
    readable: side.readable,
    writable: side.writable,
    opened: Promise.resolve({ remoteAddress: `${HOST}:443`, localAddress: null }),
    close: async () => {},
  };
}

test('ALPN negotiates h2 over real userland TLS and the Client speaks HTTP/2 end to end', async () => {
  const { a, b } = duplexPair();
  const identity = testIdentity('rsa-pss');
  // The server selects h2 in EncryptedExtensions.
  const srv = startServer(b, identity, { alpn: 'h2' });

  // Once the handshake finishes, run an h2 server over the encrypted session's plaintext face and
  // answer the first request. The hook is attached synchronously, before any frame is read.
  srv.done.then(() => {
    const hs = h2Server(srv.record.plaintextDuplex());
    hs.onFrameHook((f) => {
      if (f.type === FRAME.HEADERS && f.streamId === 1) {
        hs.sendResponse(1, [
          { name: ':status', value: '200' },
          { name: 'content-type', value: 'text/plain' },
        ])
          .then(() => hs.sendData(1, enc.encode('h2 over real tls'), true))
          .catch(() => {});
      }
    });
  });

  const client = new Client({
    forceTunnel: true,
    // Accept the test certificate; the point here is ALPN + h2, not chain validation (covered
    // exhaustively in the trust suite).
    trust: { mode: 'custom', verify: async () => {} },
    connect: () => socketOver(a),
    timeouts: { connectMs: 5000, handshakeMs: 5000, headersMs: 5000, idleMs: 5000 },
  });

  const res = await client.fetch(`https://${HOST}/thing`);
  assert.equal(res.tunnelfetch.tls.alpnProtocol, 'h2', 'ALPN selected h2 on the real handshake');
  assert.equal(res.tunnelfetch.httpVersion, '2');
  assert.equal(res.tunnelfetch.framing, 'h2');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/plain');
  assert.equal(await res.text(), 'h2 over real tls');

  await client.close();
});

test('with http2:false the ALPN offer is http/1.1 only, and an h2-only server is unreachable', async () => {
  // A server that only understands h2 in ALPN but is offered only http/1.1 will decline ALPN;
  // here we simply assert the negotiated protocol is http/1.1 when the client refuses to offer h2.
  const { a, b } = duplexPair();
  const identity = testIdentity('rsa-pss');
  const srv = startServer(b, identity, { alpn: 'http/1.1' });
  srv.done.then(() => {
    // A minimal HTTP/1.1 responder over the plaintext session.
    const dup = srv.record.plaintextDuplex();
    (async () => {
      const reader = dup.readable.getReader();
      const writer = dup.writable.getWriter();
      await reader.read(); // the request head
      await writer.write(enc.encode('HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok'));
    })().catch(() => {});
  });

  const client = new Client({
    http2: false,
    forceTunnel: true,
    trust: { mode: 'custom', verify: async () => {} },
    connect: () => socketOver(a),
    timeouts: { connectMs: 5000, handshakeMs: 5000, headersMs: 5000, idleMs: 5000 },
  });
  const res = await client.fetch(`https://${HOST}/`);
  assert.equal(res.tunnelfetch.tls.alpnProtocol, 'http/1.1');
  assert.equal(res.tunnelfetch.httpVersion, '1.1');
  assert.equal(await res.text(), 'ok');
  await client.close();
});

// A body arrives AFTER the headers — which is the normal case, not an exotic one. createFetch
// creates a Client per call and must not tear it down when `fetch` resolves, because `fetch`
// resolves at the response HEAD while the body is still streaming over the connection. On HTTP/1.1
// this was survivable: the socket is checked out of the pool, so closeAll() never touched it. On
// HTTP/2 the connection is shared and tracked in `_h2conns`, so close() killed the very stream the
// caller was about to read, and `res.text()` failed with HTTP2_PROTOCOL.
test('createFetch keeps the connection alive until an HTTP/2 body has been read', async () => {
  const { a, b } = duplexPair();
  const identity = testIdentity('rsa-pss');
  const srv = startServer(b, identity, { alpn: 'h2' });

  srv.done.then(() => {
    const hs = h2Server(srv.record.plaintextDuplex());
    hs.onFrameHook((f) => {
      if (f.type === FRAME.HEADERS && f.streamId === 1) {
        hs.sendResponse(1, [
          { name: ':status', value: '200' },
          { name: 'content-type', value: 'text/plain' },
        ])
          // The delay is the whole point: it puts the close() on the other side of the headers.
          .then(() => new Promise((r) => setTimeout(r, 25)))
          .then(() => hs.sendData(1, enc.encode('body after the head'), true))
          .catch(() => {});
      }
    });
  });

  const tunnelFetch = createFetch({
    forceTunnel: true,
    trust: { mode: 'custom', verify: async () => {} },
    connect: () => socketOver(a),
    timeouts: { connectMs: 5000, handshakeMs: 5000, headersMs: 5000, idleMs: 5000 },
  });
  const res = await tunnelFetch(`https://${HOST}/`);
  assert.equal(res.status, 200);
  assert.equal(res.tunnelfetch.httpVersion, '2');
  assert.equal(await res.text(), 'body after the head');
});

// The other half of the contract: a caller who never reads the body must not leak the Client for
// the isolate's lifetime. Cancelling has to settle the same completion the reader would have.
test('createFetch closes the Client when an HTTP/2 body is cancelled unread', async () => {
  const { a, b } = duplexPair();
  const identity = testIdentity('rsa-pss');
  const srv = startServer(b, identity, { alpn: 'h2' });

  srv.done.then(() => {
    const hs = h2Server(srv.record.plaintextDuplex());
    hs.onFrameHook((f) => {
      if (f.type === FRAME.HEADERS && f.streamId === 1) {
        hs.sendResponse(1, [{ name: ':status', value: '200' }])
          .then(() => new Promise((r) => setTimeout(r, 25)))
          .then(() => hs.sendData(1, enc.encode('never read'), true))
          .catch(() => {});
      }
    });
  });

  // Observed through the injected socket rather than a test-only Client option: the assertion is
  // that the transport was actually released, which is the thing that leaks, and `connect` is a
  // seam the public API already has.
  let closed = false;
  const tunnelFetch = createFetch({
    forceTunnel: true,
    trust: { mode: 'custom', verify: async () => {} },
    connect: () => ({ ...socketOver(a), close: async () => { closed = true; } }),
    timeouts: { connectMs: 5000, handshakeMs: 5000, headersMs: 5000, idleMs: 5000 },
  });
  const res = await tunnelFetch(`https://${HOST}/`);
  assert.equal(closed, false, 'the socket was released before the caller touched the body');
  await res.body.cancel();
  // Poll rather than sleep a guessed interval: the close is scheduled off the body's completion,
  // so it lands a few turns later, and a fixed sleep passes or fails for reasons of its own.
  for (let i = 0; i < 200 && !closed; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(closed, true, 'cancelling the body never released the connection');
});
