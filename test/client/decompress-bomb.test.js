// A gzip bomb must not walk past `maxBodyBytes`.
//
// The cap was applied to the COMPRESSED wire body only, so a caller asking for at most 1 MB
// received 20 MB from a 20 KB body — and gzip reaches roughly 1000:1, so the gap was not bounded in
// any useful sense. It breaks the fifth property in SECURITY.md, "a peer cannot make this client
// allocate without bound", and it is the caller who allocates: the moment they call `.text()`,
// `.json()` or `.arrayBuffer()`, which is the common case.
//
// Found by an adversarial review, which wrote it asserting the flaw was PRESENT — so it passed, and
// went unnoticed through two releases. Written the correct way round here: it failed before the fix.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { decodeBody } from '../../src/client/decode.js';
import { fakeNetwork, sequenceServer, response } from '../_fakenet.js';

/** A gzip bomb built with the platform's own compressor, so the test needs no node:zlib. */
async function bomb(decompressedBytes) {
  const cs = new CompressionStream('gzip');
  const done = new Response(cs.readable).arrayBuffer();
  const w = cs.writable.getWriter();
  // Written in chunks so a 20 MiB zero buffer never exists whole in the test either.
  const CHUNK = new Uint8Array(64 * 1024);
  for (let o = 0; o < decompressedBytes; o += CHUNK.length) {
    await w.write(CHUNK.subarray(0, Math.min(CHUNK.length, decompressedBytes - o)));
  }
  await w.close();
  return new Uint8Array(await done);
}

const streamOf = (bytes) =>
  new Response(bytes).body;

test('a gzip bomb is refused at maxBodyBytes, which bounds the DECODED size', async () => {
  const DECOMPRESSED = 20 * 1024 * 1024;
  const packed = await bomb(DECOMPRESSED);
  assert.ok(packed.byteLength < 128 * 1024, `the compressed body is small: ${packed.byteLength}`);

  const server = sequenceServer([
    response({ body: packed, headers: { 'content-encoding': 'gzip' } }),
  ]);
  const net = fakeNetwork(server.handler);
  const client = new Client({ connect: net.connect, forceTunnel: true, maxBodyBytes: 1024 * 1024 });

  await assert.rejects(
    async () => {
      const res = await client.fetch('http://origin.example/');
      await res.arrayBuffer();
    },
    (e) => e.code === 'LIMIT_BODY' && /decoded body exceeded/.test(e.message),
    'a 20 MiB decompressed body was delivered under a 1 MiB cap',
  );
  await client.close();
});

test('the cap is on the decoded stream, so it refuses before the caller holds the excess', async () => {
  const packed = await bomb(4 * 1024 * 1024);
  const decoded = decodeBody(streamOf(packed), 'gzip', null, 256 * 1024);
  const reader = decoded.getReader();
  let total = 0;
  await assert.rejects(async () => {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
    }
  }, (e) => e.code === 'LIMIT_BODY');
  // The over-long chunk is refused rather than handed on, so nothing past the cap was delivered.
  assert.ok(total <= 256 * 1024, `${total} bytes reached the consumer past a 262144 byte cap`);
});

test('without a cap the body still decodes whole, so the guard is not a silent truncation', async () => {
  // The dangerous fix would be one that quietly stops early. A body under the cap, and a body with
  // no cap at all, must both arrive complete.
  const packed = await bomb(2 * 1024 * 1024);
  const uncapped = await new Response(decodeBody(streamOf(packed), 'gzip', null)).arrayBuffer();
  assert.equal(uncapped.byteLength, 2 * 1024 * 1024);

  const under = await new Response(
    decodeBody(streamOf(packed), 'gzip', null, 4 * 1024 * 1024),
  ).arrayBuffer();
  assert.equal(under.byteLength, 2 * 1024 * 1024, 'a body under the cap was truncated');
});
