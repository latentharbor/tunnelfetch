// HTTP/2 against a MALICIOUS SERVER: it controls every frame, and nothing it sends has been
// authenticated by anything above the TLS layer.
//
// These four came out of an adversarial review of v1.1.0 and were all real. They were originally
// written the other way round — asserting the flaw was PRESENT — which passes today and turns red
// the moment someone fixes it, backwards for a regression suite. They now assert the correct
// behaviour, so each failed before its fix and passes after.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Http2Connection } from '../../src/http2/connection.js';
import { duplexPair } from '../_harness.js';
import { h2Server, readBodyText } from './_server.js';
import { FRAME } from '../../src/http2/constants.js';
import { serializeFrame } from '../../src/http2/frames.js';

const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function connect(opts = {}) {
  const { a, b } = duplexPair();
  const server = h2Server(b, opts.server);
  const conn = new Http2Connection(a, opts.client);
  return { conn, server };
}
const awaitRequest = (server, streamId) =>
  server.waitForFrame((f) => f.type === FRAME.HEADERS && f.streamId === streamId);

const GET = { method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] };

// A header block arrives as HEADERS plus any number of CONTINUATION frames and is only decodable
// once the last one lands, so the fragments have to be held. maxHeaderListSize bounds the DECODED
// list and is therefore only reachable after the whole block is already in memory — a peer that
// simply never sets END_HEADERS never reaches it. That is the CONTINUATION flood, the class behind
// CVE-2024-27316 and its siblings, and on a Worker with a fixed memory ceiling it is the cheapest
// way for a hostile origin to kill the isolate.
test('a CONTINUATION flood is refused instead of buffered without bound', async () => {
  const { conn, server } = connect({ client: { maxHeaderBlockBytes: 64 * 1024 } });
  const reqP = conn.request(GET);
  reqP.catch(() => {});
  await awaitRequest(server, 1);

  // HEADERS without END_HEADERS opens a continuation run the server never closes.
  await server.sendRaw(serializeFrame(FRAME.HEADERS, 0, 1, new Uint8Array(0)));
  const chunk = new Uint8Array(16384);
  for (let i = 0; i < 64; i++) {
    // 64 x 16 KiB = 1 MiB against a 64 KiB cap. Stop as soon as the connection has died, which is
    // the point: a client still accepting frames here is the vulnerability.
    if (conn._fatal) break;
    // The write itself rejects once the client tears the transport down, since both ends share the
    // duplex. That is the harness reporting success, not a failure to assert on.
    try {
      await server.sendRaw(serializeFrame(FRAME.CONTINUATION, 0, 1, chunk));
    } catch {
      break;
    }
  }
  await sleep(30);

  assert.ok(conn._fatal, 'the connection accepted an unbounded header block');
  assert.equal(conn._fatal.code, 'HTTP2_PROTOCOL');
  assert.match(conn._fatal.message, /byte cap/);
  assert.equal(conn._continuation, null, 'fragments are still held after the refusal');
  await assert.rejects(reqP);
  await conn.close();
});

// A server may answer before the client has finished uploading, so the remote half can end while
// the local half is still in flight. Every other place that ends a half re-checks whether both are
// done; the local-end path in _sendBody did not, so the stream stayed registered for the life of
// the connection — an unbounded leak driven entirely by the peer's timing.
test('a stream is released when the local half ends last, not only when the remote does', async () => {
  const { conn, server } = connect();
  // 70000 > the default 65535 connection send window, so the upload MUST block mid-body whatever
  // happens with SETTINGS. Deterministic, not a timing guess.
  const reqP = conn.request({
    ...GET,
    method: 'POST',
    headers: [['content-length', '70000']],
    body: new Uint8Array(70000),
  });
  await awaitRequest(server, 1);

  // The complete response arrives while the client is still blocked on the connection window.
  await server.sendResponse(1, [{ name: ':status', value: '200' }], { endStream: true });
  const res = await reqP;
  assert.equal(res.status, 200);
  assert.equal(await res.body.completed, true);
  assert.equal(conn.activeStreams, 1, 'the upload has not finished, so the stream is still live');

  await server.sendWindowUpdate(0, 1_000_000);
  await server.sendWindowUpdate(1, 1_000_000);
  await sleep(40);

  const req = server.requests.get(1);
  assert.equal(
    req.body.reduce((s, c) => s + c.byteLength, 0),
    70000,
    'the client did not finish sending its body',
  );
  assert.equal(req.ended, true, 'the final DATA frame did not carry END_STREAM');
  assert.equal(conn.activeStreams, 0, 'both halves ended but the stream was never released');
  await conn.close();
});

// RFC 9113 s8.1.1: a message whose DATA disagrees with its declared content-length is malformed.
// h1 gets this from its framing; h2 declares the length in a header and delimits with END_STREAM,
// so the two can disagree — and a body that silently differs from what it declared is exactly the
// ambiguity this package refuses everywhere else.
test('a body longer than its content-length is refused', async () => {
  const { conn, server } = connect();
  const reqP = conn.request(GET);
  await awaitRequest(server, 1);
  await server.sendResponse(1, [
    { name: ':status', value: '200' },
    { name: 'content-length', value: '3' },
  ]);
  const res = await reqP;
  await server.sendData(1, enc.encode('hello world'), true); // 11 bytes against a declared 3

  await assert.rejects(
    () => readBodyText(res.body),
    (e) => e.code === 'HTTP2_PROTOCOL' && /content-length/.test(e.message),
    'eleven bytes were delivered under a declared content-length of three',
  );
  await conn.close();
});

test('a body shorter than its content-length is refused', async () => {
  // The other direction, and the more dangerous one: a truncated body that ends cleanly would
  // otherwise reach the caller as a complete response.
  const { conn, server } = connect();
  const reqP = conn.request(GET);
  await awaitRequest(server, 1);
  await server.sendResponse(1, [
    { name: ':status', value: '200' },
    { name: 'content-length', value: '64' },
  ]);
  const res = await reqP;
  await server.sendData(1, enc.encode('short'), true);

  await assert.rejects(
    () => readBodyText(res.body),
    (e) => e.code === 'HTTP2_PROTOCOL' && /content-length/.test(e.message),
    'a truncated body was accepted as complete',
  );
  await conn.close();
});

test('a body that matches its content-length is delivered', async () => {
  // The control. Without it, the two tests above would still pass if content-length checking
  // simply rejected everything.
  const { conn, server } = connect();
  const reqP = conn.request(GET);
  await awaitRequest(server, 1);
  await server.sendResponse(1, [
    { name: ':status', value: '200' },
    { name: 'content-length', value: '11' },
  ]);
  const res = await reqP;
  await server.sendData(1, enc.encode('hello world'), true);
  assert.equal(await readBodyText(res.body), 'hello world');
  await conn.close();
});

// RFC 9113 s6.1: DATA is always associated with a stream, and a zero stream id MUST be a
// connection error. Absorbing it silently gave a peer a way to push bytes with no stream to charge
// them to.
test('DATA on stream 0 is a connection error', async () => {
  const { conn, server } = connect();
  const reqP = conn.request(GET);
  reqP.catch(() => {});
  await awaitRequest(server, 1);
  await server.sendRaw(serializeFrame(FRAME.DATA, 0, 0, enc.encode('junk on stream 0')));
  await sleep(30);

  assert.ok(conn._fatal, 'DATA on stream 0 did not fail the connection');
  assert.equal(conn._fatal.code, 'HTTP2_PROTOCOL');
  assert.match(conn._fatal.message, /stream 0/);
  await assert.rejects(reqP);
  await conn.close();
});
