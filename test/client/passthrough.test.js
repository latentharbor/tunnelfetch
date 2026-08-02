// `decompress: 'passthrough'` end to end through the fake network: the body arrives CODED, the
// Content-Encoding survives so a forwarder can relay it, and the Content-Length survives too
// because it now describes exactly what the caller holds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { fakeNetwork, sequenceServer, response } from '../_fakenet.js';

const gzipOf = async (bytes) => {
  const cs = new CompressionStream('gzip');
  const done = new Response(cs.readable).arrayBuffer();
  const w = cs.writable.getWriter();
  await w.write(bytes); await w.close();
  return new Uint8Array(await done);
};
const PAYLOAD = new TextEncoder().encode('x'.repeat(50000));

test("decompress:'passthrough' returns the coded body with its headers intact", async () => {
  const gz = await gzipOf(PAYLOAD);
  const server = sequenceServer([response({ body: gz, headers: {
    'content-encoding': 'gzip', 'content-length': String(gz.byteLength) } })]);
  const client = new Client({ connect: fakeNetwork(server.handler).connect, forceTunnel: true,
    decompress: 'passthrough' });
  const res = await client.fetch('http://origin.example/');
  const got = new Uint8Array(await res.arrayBuffer());
  assert.equal(got.byteLength, gz.byteLength, 'the body was decoded, not passed through');
  assert.equal(res.headers.get('content-encoding'), 'gzip', 'a forwarder cannot relay this');
  assert.equal(res.headers.get('content-length'), String(gz.byteLength),
    'the length must describe what the caller actually holds');
  await client.close();
});

test("decompress:true still decodes, so passthrough is opt-in", async () => {
  const gz = await gzipOf(PAYLOAD);
  const server = sequenceServer([response({ body: gz, headers: { 'content-encoding': 'gzip' } })]);
  const client = new Client({ connect: fakeNetwork(server.handler).connect, forceTunnel: true });
  const res = await client.fetch('http://origin.example/');
  assert.equal((await res.arrayBuffer()).byteLength, PAYLOAD.byteLength);
  await client.close();
});
