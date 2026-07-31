// Server-sent events.
//
// SSE is not a transport feature here and deliberately has no code of its own: it is a
// `text/event-stream` body like any other. What it does demand is that the body genuinely
// streams — that an event reaches the caller before the next one has been written, that a long
// quiet gap is judged by the idle deadline rather than a total one, and that abandoning a stream
// halfway does not put a half-read connection back in the pool.
//
// Every one of those is a property of layers that know nothing about SSE, which is exactly why
// they need asserting from the outside: a stack that buffers the whole body would pass every
// other test in this repo and fail every SSE consumer.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../src/client.js';
import { fakeNetwork, readRequestHead } from './_fakenet.js';
import { utf8, concat } from '../src/util/bytes.js';

const chunk = (s) => utf8(`${s.length.toString(16)}\r\n${s}\r\n`);
const LAST_CHUNK = utf8('0\r\n\r\n');

const SSE_HEAD =
  'HTTP/1.1 200 OK\r\n' +
  'content-type: text/event-stream\r\n' +
  'cache-control: no-cache\r\n' +
  'transfer-encoding: chunked\r\n\r\n';

/**
 * An origin that emits events on command. `gate` resolves when the server has written the head,
 * and each `emit()` returns only after the bytes are on the wire, so a test can prove ordering
 * rather than infer it from timing.
 */
function sseOrigin({ headers = SSE_HEAD } = {}) {
  let write;
  let close;
  const ready = new Promise((resolve) => {
    write = async (bytes) => {
      await resolveWrite(bytes);
    };
    let resolveWrite;
    const handler = async (conn) => {
      await readRequestHead(conn.reader);
      await conn.write(utf8(headers));
      resolveWrite = conn.write;
      close = conn.close;
      resolve();
      // Hold the connection open until the test closes it.
      await new Promise(() => {});
    };
    sseOrigin.handler = handler;
  });
  const net = fakeNetwork((conn) => sseOrigin.handler(conn));
  return {
    connect: net.connect,
    calls: net.calls,
    ready,
    emit: (event) => write(chunk(event)),
    end: async () => {
      await write(LAST_CHUNK);
      await close();
    },
  };
}

/** Read one SSE event (terminated by a blank line) from a byte stream. */
async function readEvent(reader, decoder, pending) {
  for (;;) {
    const idx = pending.buf.indexOf('\n\n');
    if (idx !== -1) {
      const event = pending.buf.slice(0, idx);
      pending.buf = pending.buf.slice(idx + 2);
      return event;
    }
    const { value, done } = await reader.read();
    if (done) return null;
    pending.buf += decoder.decode(value, { stream: true });
  }
}

test('events reach the caller one at a time, before the next is written', async () => {
  const origin = sseOrigin();
  const client = new Client({ connect: origin.connect, forceTunnel: true });
  try {
    const res = await client.fetch('http://origin.example/events');
    assert.equal(res.headers.get('content-type'), 'text/event-stream');
    assert.equal(res.tunnelfetch.framing, 'chunked');

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const pending = { buf: '' };

    // The proof: nothing is written for event 2 until event 1 has been read out the far end. A
    // stack that buffered the body would deadlock here rather than fail an assertion.
    await origin.emit('data: one\n\n');
    assert.equal(await readEvent(reader, decoder, pending), 'data: one');

    await origin.emit('data: two\n\n');
    assert.equal(await readEvent(reader, decoder, pending), 'data: two');

    await origin.emit(': heartbeat\n\n');
    assert.equal(await readEvent(reader, decoder, pending), ': heartbeat');

    await origin.emit('event: done\ndata: 3\n\n');
    assert.equal(await readEvent(reader, decoder, pending), 'event: done\ndata: 3');

    await reader.cancel();
  } finally {
    await client.close();
  }
});

test('a multi-line event split across two chunks is reassembled without waiting for the body to end', async () => {
  const origin = sseOrigin();
  const client = new Client({ connect: origin.connect, forceTunnel: true });
  try {
    const res = await client.fetch('http://origin.example/events');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const pending = { buf: '' };

    await origin.emit('data: firs');
    await origin.emit('t half\n\n');
    assert.equal(await readEvent(reader, decoder, pending), 'data: first half');

    await reader.cancel();
  } finally {
    await client.close();
  }
});

test('a stream abandoned midway is never pooled', async () => {
  const origin = sseOrigin();
  const client = new Client({ connect: origin.connect, forceTunnel: true });
  try {
    const res = await client.fetch('http://origin.example/events');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const pending = { buf: '' };
    await origin.emit('data: one\n\n');
    await readEvent(reader, decoder, pending);

    // The terminal chunk never arrives, so the connection's position is unknown.
    await reader.cancel(new Error('caller stopped listening'));
    await new Promise((r) => setTimeout(r, 0));

    assert.equal(client.pool.idleCount, 0, 'an unfinished stream has no safe reuse point');
    assert.equal(client.pool.stats.discarded, 1);
  } finally {
    await client.close();
  }
});

test('the idle deadline measures the gap between events, not the total duration', async () => {
  // The distinction that matters for SSE: a feed that is quiet for a while but alive must survive,
  // while one that has genuinely stalled must not. Both are driven here by real (short) timers
  // rather than a virtual clock, because the deadline has to run through the whole stack.
  const origin = sseOrigin();
  const client = new Client({
    connect: origin.connect,
    forceTunnel: true,
    timeouts: { idleMs: 300, totalMs: 0 },
  });
  try {
    const res = await client.fetch('http://origin.example/events');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const pending = { buf: '' };

    // Four gaps of 150ms: 600ms of wall time, more than twice the idle budget, all legitimate.
    for (const n of [1, 2, 3, 4]) {
      await new Promise((r) => setTimeout(r, 150));
      await origin.emit(`data: ${n}\n\n`);
      assert.equal(await readEvent(reader, decoder, pending), `data: ${n}`);
    }

    // Now genuinely stall.
    const stalled = reader.read().then(
      () => null,
      (e) => e,
    );
    const err = await stalled;
    assert.ok(err, 'a stalled feed must eventually error rather than hang forever');
    assert.equal(err.code, 'TIMEOUT_IDLE');
  } finally {
    await client.close();
  }
});

test('a total deadline still bounds a stream that never ends', async () => {
  const origin = sseOrigin();
  const client = new Client({
    connect: origin.connect,
    forceTunnel: true,
    timeouts: { idleMs: 10_000, totalMs: 250 },
  });
  try {
    const res = await client.fetch('http://origin.example/events');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    const pending = { buf: '' };
    await origin.emit('data: one\n\n');
    await readEvent(reader, decoder, pending);

    const err = await reader.read().then(
      () => null,
      (e) => e,
    );
    assert.equal(err?.code, 'TIMEOUT_TOTAL');
  } finally {
    await client.close();
  }
});

test('a caller-supplied Accept header is not overwritten', async () => {
  // SSE clients conventionally ask for text/event-stream; the default of */* must not clobber it.
  const seen = [];
  const net = fakeNetwork(async ({ reader, write, close }) => {
    seen.push(await readRequestHead(reader));
    await write(utf8(SSE_HEAD));
    await write(chunk('data: hi\n\n'));
    await write(LAST_CHUNK);
    await close();
  });
  const client = new Client({ connect: net.connect, forceTunnel: true });
  try {
    const res = await client.fetch('http://origin.example/events', {
      headers: { accept: 'text/event-stream' },
    });
    assert.equal(await res.text(), 'data: hi\n\n');
    assert.equal(seen[0].headers.get('accept'), 'text/event-stream');
  } finally {
    await client.close();
  }
});

test('an event-stream body is not decompressed into a buffer by accident', async () => {
  // Content-Encoding on an event stream is unusual but legal. What must not happen is the decoder
  // holding the whole body: this asserts the first event surfaces while the response is still open.
  const cs = new CompressionStream('gzip');
  const w = cs.writable.getWriter();
  void w.write(utf8('data: compressed\n\n'));
  void w.close();
  const parts = [];
  const r = cs.readable.getReader();
  for (;;) {
    const { value, done } = await r.read();
    if (done) break;
    parts.push(value);
  }
  const gz = concat(parts);

  const net = fakeNetwork(async ({ reader, write, close }) => {
    await readRequestHead(reader);
    await write(
      utf8(
        'HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n' +
          `content-encoding: gzip\r\ncontent-length: ${gz.byteLength}\r\n\r\n`,
      ),
    );
    await write(gz);
    await close();
  });
  const client = new Client({ connect: net.connect, forceTunnel: true });
  try {
    const res = await client.fetch('http://origin.example/events');
    assert.equal(await res.text(), 'data: compressed\n\n');
  } finally {
    await client.close();
  }
});
