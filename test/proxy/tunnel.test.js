// The tunnel's readable, tested against a transport that can actually do BYOB.
//
// Every other proxy test in this directory runs over duplexPair, whose readable is a plain stream.
// That is the right shape for asserting wire bytes and failure taxonomy, and it is precisely the
// wrong shape for this module: the fallback is all it can ever exercise, and the fallback is what
// the production path was accidentally getting for every proxied connection. So this file brings
// its own byte-stream socket.
//
// The load-bearing assertion is `the socket sees the caller's own view`. Everything else here would
// still pass if the tunnel quietly went back to copying through a 64 KiB scratch buffer; that one
// fails, because it is the difference the measurement was about.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tunnelReadable } from '../../src/proxy/tunnel.js';
import { ByteReader, concat, utf8 } from '../../src/util/bytes.js';
import { collect } from '../_harness.js';

/**
 * A socket whose readable is a real byte stream, recording the view size handed to it on every
 * pull. `chunks` are delivered in order, split across pulls only when a view is too small.
 */
function byteSocket(chunks) {
  const views = [];
  const queue = chunks.map((c) => (typeof c === 'string' ? utf8(c) : c));
  let pending = null;
  const readable = new ReadableStream({
    type: 'bytes',
    pull(c) {
      const req = c.byobRequest;
      views.push(req.view.byteLength);
      const next = pending ?? queue.shift() ?? null;
      pending = null;
      if (next === null) {
        c.close();
        req.respond(0);
        return;
      }
      const n = Math.min(next.byteLength, req.view.byteLength);
      new Uint8Array(req.view.buffer, req.view.byteOffset, req.view.byteLength)
        .set(next.subarray(0, n));
      if (n < next.byteLength) pending = next.subarray(n);
      req.respond(n);
    },
  });
  return { socket: { readable }, views };
}

/** A socket whose readable is NOT a byte stream — the shape every in-memory fake here has. */
function plainSocket(chunks) {
  const queue = chunks.map((c) => (typeof c === 'string' ? utf8(c) : c));
  return {
    socket: {
      readable: new ReadableStream({
        pull(c) {
          if (queue.length === 0) c.close();
          else c.enqueue(queue.shift());
        },
      }),
    },
  };
}

/**
 * Reproduce what a proxy handshake leaves behind: a ByteReader that has consumed `prefix` bytes and
 * may still be holding tunnel payload that arrived in the same chunk.
 */
async function afterHandshake(socket, prefixLen) {
  const reader = new ByteReader(socket.readable);
  if (prefixLen > 0) await reader.readExactly(prefixLen, 'fake reply');
  return reader;
}

test('the tunnel readable is a byte stream, so BYOB survives the proxy', async () => {
  const { socket } = byteSocket(['REPLY', 'payload']);
  const reader = await afterHandshake(socket, 5);
  const stream = tunnelReadable(socket, reader);
  // The assertion that would have caught the original bug: this call threw before, and the TLS
  // record layer's response to it throwing was to silently use a default reader instead.
  const byob = stream.getReader({ mode: 'byob' });
  const { value } = await byob.read(new Uint8Array(64));
  assert.equal(new TextDecoder().decode(value), 'payload');
});

test('the socket sees the caller\'s own view once the handshake leftovers are drained', async () => {
  // Two chunks: the reply, and a body large enough that several reads are needed.
  const body = new Uint8Array(9000).fill(7);
  const { socket, views } = byteSocket([new Uint8Array(5), body]);
  const reader = await afterHandshake(socket, 5);
  const stream = tunnelReadable(socket, reader);
  const byob = stream.getReader({ mode: 'byob' });
  const before = views.length;
  for (;;) {
    const { done } = await byob.read(new Uint8Array(4096));
    if (done) break;
  }
  const after = views.slice(before);
  assert.ok(after.length > 0, 'the socket should have been read after promotion');
  // 4096 is the caller's view. Anything else — 65536 above all — means the bytes went through a
  // scratch buffer and were copied, which is the cost this module exists to remove.
  assert.deepEqual([...new Set(after)], [4096]);
});

test('bytes buffered by the handshake are delivered first, in order', async () => {
  // The reply and the first payload arrive in ONE chunk, so the reader over-reads: this is the
  // case that loses bytes if the wrapper is wrong, and it is why the wrapper exists at all.
  const { socket } = byteSocket(['REPLYleftover', 'rest']);
  const reader = await afterHandshake(socket, 5);
  const out = await collect(tunnelReadable(socket, reader));
  assert.equal(new TextDecoder().decode(out), 'leftoverrest');
});

test('output does not depend on how the transport chunked the input', async () => {
  const payload = utf8('the quick brown fox jumps over the lazy dog, repeatedly and at length');
  const whole = concat([utf8('REPLY'), payload]);
  const outputs = [];
  for (const chunking of [[whole], [...whole].map((b) => Uint8Array.of(b))]) {
    const { socket } = byteSocket(chunking);
    const reader = await afterHandshake(socket, 5);
    outputs.push(await collect(tunnelReadable(socket, reader)));
  }
  assert.deepEqual(outputs[0], outputs[1]);
  assert.deepEqual(outputs[0], payload);
});

test('a transport that cannot do BYOB still delivers identical bytes', async () => {
  const { socket } = plainSocket(['REPLYleftover', 'rest']);
  const reader = await afterHandshake(socket, 5);
  const out = await collect(tunnelReadable(socket, reader));
  assert.equal(new TextDecoder().decode(out), 'leftoverrest');
});

test('a default reader works too, and gets socket-sized chunks', async () => {
  const { socket } = byteSocket(['REPLY', new Uint8Array(3000).fill(1)]);
  const reader = await afterHandshake(socket, 5);
  const out = await collect(tunnelReadable(socket, reader));
  assert.equal(out.byteLength, 3000);
});

test('EOF closes cleanly for a BYOB reader', async () => {
  const { socket } = byteSocket(['REPLY']);
  const reader = await afterHandshake(socket, 5);
  const byob = tunnelReadable(socket, reader).getReader({ mode: 'byob' });
  const { done, value } = await byob.read(new Uint8Array(16));
  assert.equal(done, true);
  assert.equal(value.byteLength, 0);
});

test('cancel reaches the socket after promotion', async () => {
  let cancelled = null;
  const readable = new ReadableStream({
    type: 'bytes',
    pull(c) {
      const req = c.byobRequest;
      new Uint8Array(req.view.buffer, req.view.byteOffset, req.view.byteLength).fill(9);
      req.respond(Math.min(8, req.view.byteLength));
    },
    cancel(reason) { cancelled = reason; },
  });
  const socket = { readable };
  const reader = new ByteReader(readable);
  await reader.readExactly(4, 'fake reply');
  const stream = tunnelReadable(socket, reader);
  const byob = stream.getReader({ mode: 'byob' });
  await byob.read(new Uint8Array(8)); // drains the leftovers and promotes
  await byob.cancel('done with it');
  assert.equal(cancelled, 'done with it');
});

test('cancel reaches the socket before promotion, while leftovers are still buffered', async () => {
  let cancelled = null;
  const payload = utf8('REPLYleftover');
  let sent = false;
  const readable = new ReadableStream({
    type: 'bytes',
    pull(c) {
      const req = c.byobRequest;
      if (sent) { c.close(); req.respond(0); return; }
      sent = true;
      new Uint8Array(req.view.buffer, req.view.byteOffset, req.view.byteLength).set(payload);
      req.respond(payload.byteLength);
    },
    cancel(reason) { cancelled = reason; },
  });
  const socket = { readable };
  const reader = await afterHandshake(socket, 5);
  // Promotion has not happened: the handshake's reader is still holding tunnel payload, so the
  // cancellation has to travel through it rather than through a socket reader that does not exist.
  assert.ok(reader.buffered > 0, 'the handshake must still be holding payload');
  await tunnelReadable(socket, reader).cancel('early');
  assert.equal(cancelled, 'early');
});
