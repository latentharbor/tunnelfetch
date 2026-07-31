// The HTTP/2 connection engine (RFC 9113), end to end over an in-memory duplex against a scriptable
// server peer. These are the tests that exercise the parts a unit test of frames or HPACK cannot:
// stream multiplexing, the flow-control loop wired to consumption, trailers, and the fail-closed
// reactions to a peer that violates the protocol.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Http2Connection, Http2Retryable } from '../../src/http2/connection.js';
import { duplexPair, rejectsWithCode } from '../_harness.js';
import { h2Server, readBodyText } from './_server.js';
import { FRAME, FLAG, H2_ERROR, SETTINGS } from '../../src/http2/constants.js';
import { serializeFrame } from '../../src/http2/frames.js';
import { encodeHeaderBlock } from '../../src/http2/hpack.js';
import { ByteReader } from '../../src/util/bytes.js';

const enc = new TextEncoder();

/** Stand up a connected client + server pair over an in-memory duplex. */
function connect(opts = {}) {
  const { a, b } = duplexPair();
  const server = h2Server(b, opts.server);
  const conn = new Http2Connection(a, opts.client);
  return { conn, server };
}

/** Resolve once the server has received the request HEADERS for `streamId`. */
function awaitRequest(server, streamId) {
  return server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === streamId);
}

test('a GET returns status, headers and a body', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({
    method: 'GET',
    scheme: 'https',
    authority: 'origin.example',
    path: '/thing',
    headers: [['user-agent', 'tf/0']],
  });
  await awaitRequest(server, 1);
  await server.sendResponse(1, [{ name: ':status', value: '200' }, { name: 'content-type', value: 'text/plain' }]);
  await server.sendData(1, enc.encode('the body'), true);
  const res = await reqP;
  assert.equal(res.status, 200);
  assert.equal(res.httpVersion, '2');
  assert.equal(res.headers.get('content-type'), 'text/plain');
  assert.equal(await readBodyText(res.body), 'the body');
  assert.equal(await res.body.completed, true);
  await conn.close();
});

test('a response with END_STREAM on the HEADERS has an empty body and completes immediately', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  await server.sendResponse(1, [{ name: ':status', value: '204' }], { endStream: true });
  const res = await reqP;
  assert.equal(res.status, 204);
  assert.equal(await res.body.completed, true, 'completes without the body being read');
  await conn.close();
});

test('the body streams: chunks are delivered as they arrive, not buffered whole', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  await server.sendResponse(1, [{ name: ':status', value: '200' }]);
  const res = await reqP;
  const reader = res.body.getReader();
  await server.sendData(1, enc.encode('one'), false);
  const first = await reader.read();
  assert.equal(new TextDecoder().decode(first.value), 'one', 'first chunk arrives before the second is sent');
  await server.sendData(1, enc.encode('two'), true);
  const second = await reader.read();
  assert.equal(new TextDecoder().decode(second.value), 'two');
  assert.equal((await reader.read()).done, true);
  await conn.close();
});

test('trailers after the body are delivered on the trailers promise', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  await server.sendResponse(1, [{ name: ':status', value: '200' }]);
  await server.sendData(1, enc.encode('payload'), false);
  await server.sendTrailers(1, [{ name: 'x-checksum', value: 'deadbeef' }]);
  const res = await reqP;
  assert.equal(await readBodyText(res.body), 'payload');
  const trailers = await res.body.trailers;
  assert.equal(trailers.get('x-checksum'), 'deadbeef');
  await conn.close();
});

test('WINDOW_UPDATE is sent as the consumer drains, on both the stream and the connection', async () => {
  // Small windows so ordinary reads cross the replenish thresholds (stream 50, conn 100).
  const { conn, server } = connect({ client: { initialWindowSize: 100, connectionWindow: 200 } });
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  await server.sendResponse(1, [{ name: ':status', value: '200' }]);
  const res = await reqP;
  // Deliver 100 bytes (exactly the stream window) then 100 more; the client must reopen the window
  // as it hands bytes to the consumer or the peer would stall — the invariant a broken flow-control
  // path violates. Here the server sends eagerly, so the test asserts the observable emission.
  await server.sendData(1, enc.encode('x'.repeat(100)), false);
  await server.sendData(1, enc.encode('y'.repeat(100)), true);
  assert.equal((await readBodyText(res.body)).length, 200);
  await new Promise((r) => setTimeout(r, 20));
  const updates = server.events.filter((e) => e.kind === 'window_update');
  const streamInc = updates.filter((u) => u.streamId === 1).reduce((s, u) => s + u.inc, 0);
  const connInc = updates.filter((u) => u.streamId === 0).reduce((s, u) => s + u.inc, 0);
  assert.ok(streamInc >= 100, `stream window reopened by ${streamInc}, expected >= 100`);
  assert.ok(connInc >= 100, `connection window reopened by ${connInc}, expected >= 100`);
  await conn.close();
});

test('a POST body larger than the peer window is chunked and waits for WINDOW_UPDATE', async () => {
  // Server advertises a 10-byte initial window; the client must send the 25-byte body in pieces
  // and block until the server grants more.
  const { conn, server } = connect({ server: { settings: [[SETTINGS.INITIAL_WINDOW_SIZE, 10]] } });
  const body = enc.encode('0123456789ABCDEFGHIJKLMNO'); // 25 bytes
  const reqP = conn.request({
    method: 'POST',
    scheme: 'https',
    authority: 'h',
    path: '/',
    headers: [['content-length', '25']],
    body,
  });
  await awaitRequest(server, 1);
  // Grant the rest of the window in two steps so the send side must resume twice.
  await new Promise((r) => setTimeout(r, 20));
  await server.sendWindowUpdate(1, 10);
  await server.sendWindowUpdate(0, 100);
  await new Promise((r) => setTimeout(r, 10));
  await server.sendWindowUpdate(1, 100);
  await new Promise((r) => setTimeout(r, 20));
  const req = server.requests.get(1);
  const got = req.body.reduce((s, c) => s + c.byteLength, 0);
  assert.equal(got, 25, 'the whole body arrived across several flow-controlled DATA frames');
  assert.equal(req.ended, true, 'the last DATA carried END_STREAM');
  await server.sendResponse(1, [{ name: ':status', value: '200' }], { endStream: true });
  assert.equal((await reqP).status, 200);
  await conn.close();
});

test('concurrent streams are demultiplexed even when responses interleave out of order', async () => {
  const { conn, server } = connect();
  const p1 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/1', headers: [] });
  const p2 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/2', headers: [] });
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 3);
  // Answer stream 3 first, and interleave the two bodies.
  await server.sendResponse(3, [{ name: ':status', value: '201' }]);
  await server.sendResponse(1, [{ name: ':status', value: '200' }]);
  await server.sendData(3, enc.encode('BBB'), true);
  await server.sendData(1, enc.encode('AAA'), true);
  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 201);
  assert.equal(await readBodyText(r1.body), 'AAA');
  assert.equal(await readBodyText(r2.body), 'BBB');
  await conn.close();
});

test('a server RST_STREAM rejects the request as a stream error, connection stays usable', async () => {
  const { conn, server } = connect();
  const p1 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/1', headers: [] });
  await awaitRequest(server, 1);
  await server.sendRst(1, H2_ERROR.INTERNAL_ERROR);
  await rejectsWithCode(async () => p1, 'HTTP2_STREAM_CLOSED', /reset/);
  // The connection is still good: a second request succeeds.
  const p2 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/2', headers: [] });
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 3);
  await server.sendResponse(3, [{ name: ':status', value: '200' }], { endStream: true });
  assert.equal((await p2).status, 200);
  await conn.close();
});

test('REFUSED_STREAM is a retryable error (the server never processed it)', async () => {
  const { conn, server } = connect();
  const p1 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  await server.sendRst(1, H2_ERROR.REFUSED_STREAM);
  let err;
  try {
    await p1;
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof Http2Retryable, 'a refused stream is safe to retry elsewhere');
  await conn.close();
});

test('cancelling the body sends RST_STREAM CANCEL', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  const rst = server.waitForFrame((f) => f.type === FRAME.RST_STREAM && f.streamId === 1);
  await server.sendResponse(1, [{ name: ':status', value: '200' }]);
  await server.sendData(1, enc.encode('partial'), false);
  const res = await reqP;
  const reader = res.body.getReader();
  await reader.read();
  await reader.cancel('done');
  await rst;
  assert.equal(await res.body.completed, false, 'a cancelled body did not complete');
  await conn.close();
});

test('GOAWAY makes an unprocessed stream retryable', async () => {
  const { conn, server } = connect();
  // Open two streams; the server will GOAWAY with lastStreamId = 1, refusing stream 3.
  const p1 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/1', headers: [] });
  const p3 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/3', headers: [] });
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 3);
  await server.sendGoaway(1, H2_ERROR.NO_ERROR);
  await server.sendResponse(1, [{ name: ':status', value: '200' }], { endStream: true });
  assert.equal((await p1).status, 200, 'the promised stream still completes');
  let err;
  try {
    await p3;
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof Http2Retryable, 'the stream past lastStreamId is retryable');
  assert.equal(conn.canDispatch(), false, 'the connection accepts no new streams after GOAWAY');
  await conn.close();
});

test('a PING is answered with a PING ACK echoing the opaque data', async () => {
  const { conn, server } = connect();
  const opaque = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
  await server.ready; // send the unsolicited PING only after the server's SETTINGS is on the wire
  const ackP = server.waitForFrame((f) => f.type === FRAME.PING && f.flags & FLAG.ACK);
  await server.sendPing(opaque, false);
  const ack = await ackP;
  assert.deepEqual([...ack.payload], [1, 2, 3, 4, 5, 6, 7, 8]);
  await conn.close();
});

test('the client ACKs the server SETTINGS', async () => {
  const { conn, server } = connect();
  const ack = await server.waitForFrame((f) => f.type === FRAME.SETTINGS && f.flags & FLAG.ACK);
  assert.equal(ack.payload.length, 0);
  await conn.close();
});

test('a PUSH_PROMISE fails the connection closed (we advertised ENABLE_PUSH = 0)', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  // PUSH_PROMISE: promised stream id (4) + a header block.
  const promised = encodeHeaderBlock([{ name: ':method', value: 'GET' }]);
  const payload = new Uint8Array(4 + promised.length);
  payload[3] = 4;
  payload.set(promised, 4);
  await server.sendRaw(serializeFrame(FRAME.PUSH_PROMISE, FLAG.END_HEADERS, 1, payload));
  await rejectsWithCode(async () => reqP, 'HTTP2_PUSH_UNEXPECTED');
  await conn.close();
});

test('an unknown frame type is ignored (RFC 9113 s5.5), the stream still completes', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  // Frame type 0x1f (an extension/GREASE type) on stream 0, before the response.
  await server.sendRaw(serializeFrame(0x1f, 0, 0, enc.encode('greased')));
  await server.sendResponse(1, [{ name: ':status', value: '200' }], { endStream: true });
  assert.equal((await reqP).status, 200);
  await conn.close();
});

test('a header block fragmented across CONTINUATION frames is reassembled', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  // Force the server to split the response header block into HEADERS + CONTINUATION at 1-byte frames.
  await server.sendResponse(
    1,
    [
      { name: ':status', value: '200' },
      { name: 'x-long', value: 'a'.repeat(40) },
    ],
    { endStream: true, maxFrame: 1 },
  );
  const res = await reqP;
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-long'), 'a'.repeat(40));
  await conn.close();
});

test('a response with an uppercase header name is a stream error, connection survives', async () => {
  const { conn, server } = connect();
  const p1 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/1', headers: [] });
  await awaitRequest(server, 1);
  // Encode an illegal uppercase name directly (the encoder does not police this, the peer would).
  await server.sendResponse(1, [{ name: ':status', value: '200' }, { name: 'X-Bad', value: 'v' }], {
    endStream: true,
  });
  await rejectsWithCode(async () => p1, 'HTTP2_HEADER', /uppercase/);
  const p2 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/2', headers: [] });
  await server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === 3);
  await server.sendResponse(3, [{ name: ':status', value: '200' }], { endStream: true });
  assert.equal((await p2).status, 200, 'the connection survived the stream error');
  await conn.close();
});

test('a response with no :status is a stream error', async () => {
  const { conn, server } = connect();
  const p1 = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  await server.sendResponse(1, [{ name: 'content-type', value: 'text/plain' }], { endStream: true });
  await rejectsWithCode(async () => p1, 'HTTP2_HEADER', /:status/);
  await conn.close();
});

test('a first server frame that is not SETTINGS is a connection error', async () => {
  const { a, b } = duplexPair();
  const conn = new Http2Connection(a, {});
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  // Read past the client preface, then send a PING as the very first server frame.
  const reader = new ByteReader(b.readable);
  await reader.readExactly(24, 'preface');
  const writer = b.writable.getWriter();
  await writer.write(serializeFrame(FRAME.PING, 0, 0, new Uint8Array(8)));
  await rejectsWithCode(async () => reqP, 'HTTP2_PROTOCOL', /expected SETTINGS/);
  await conn.close();
});

test('an HPACK error on one stream is fatal to the whole connection (shared decoder)', async () => {
  const { conn, server } = connect();
  const reqP = conn.request({ method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] });
  await awaitRequest(server, 1);
  // A HEADERS frame whose block references dynamic index 62 (empty) — an HPACK error.
  await server.sendRaw(serializeFrame(FRAME.HEADERS, FLAG.END_HEADERS | FLAG.END_STREAM, 1, Uint8Array.of(0xbe)));
  await rejectsWithCode(async () => reqP, 'HTTP2_COMPRESSION');
  assert.equal(conn.canDispatch(), false, 'the connection is dead after a compression error');
  await conn.close();
});
