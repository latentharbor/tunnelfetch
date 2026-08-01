// Audit PoC: `maxBodyBytes` bounds only the COMPRESSED wire body; the decompressed output is
// uncapped. A gzip bomb (small compressed, huge decompressed) therefore bypasses the memory bound
// a caller set — the moment they buffer the body (.text()/.json()/.arrayBuffer(), the common case).
// tunnelfetch streams the decoded body with backpressure, so it does not itself hold it all at once
// (why this is medium, not high) — but no cap governs decoded size, unlike the raw-body path which
// enforces maxBytes. Breaks Property 5's "decompressed bodies ... have caps" clause.
//
// This test asserts the CURRENT (uncapped) behavior so it passes, proving the gap exists. The
// desired behavior is the `assert.rejects` at the bottom, which would fail today.

import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { decodeBody } from '../../src/client/decode.js';

const streamOf = (bytes, chunk = 16384) => {
  let o = 0;
  return new ReadableStream({
    pull(c) {
      if (o >= bytes.byteLength) return c.close();
      c.enqueue(bytes.subarray(o, Math.min(o + chunk, bytes.byteLength)));
      o += chunk;
    },
  });
};

test('decodeBody delivers an unbounded gzip bomb: no decoded-size cap exists', async () => {
  const DECOMPRESSED = 20 * 1024 * 1024; // 20 MiB
  const bomb = gzipSync(new Uint8Array(DECOMPRESSED)); // ~20 KB on the wire
  assert.ok(bomb.byteLength < 64 * 1024, 'compressed body is tiny');

  // decodeBody is exactly what client.js:714 calls; it takes NO maxBytes parameter.
  const decoded = decodeBody(streamOf(bomb), 'gzip', null);
  const r = decoded.getReader();
  let total = 0;
  let peakChunk = 0;
  for (;;) {
    const { value, done } = await r.read();
    if (done) break;
    total += value.byteLength;
    peakChunk = Math.max(peakChunk, value.byteLength);
  }
  assert.equal(total, DECOMPRESSED, 'the full 20 MiB was delivered with no cap and no error');
  // Streamed, not buffered whole: the largest single chunk is small, so tunnelfetch itself does
  // not allocate 20 MiB — the caller does when it buffers via .text()/.json()/.arrayBuffer().
  assert.ok(peakChunk <= 128 * 1024, `streamed in ${peakChunk}-byte chunks, not held whole`);
});
