// Transcript hash: incremental updates, the RFC 8448 section 3 hashes from real messages,
// and the HelloRetryRequest message_hash substitution against the section 5 trace.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Transcript } from '../../src/tls/transcript.js';
import { concat, toHex } from '../../src/util/bytes.js';
import { codes } from '../../src/errors.js';
import { rejectsWithCode } from '../_harness.js';
import { RFC8448_1RTT as V, RFC8448_HRR as HRR } from './_vectors.js';

const S256 = 'SHA-256';
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);

test('incremental updates equal the one-shot digest, at any granularity', async () => {
  const message = concat([V.clientHello, V.serverHello, V.serverFlightPlaintext]);
  const want = new Uint8Array(await crypto.subtle.digest(S256, message));
  for (const step of [1, 3, 7, 64, 1000, message.byteLength]) {
    const t = new Transcript(S256);
    for (let o = 0; o < message.byteLength; o += step) {
      t.update(message.subarray(o, Math.min(o + step, message.byteLength)));
    }
    eq(await t.hash(), want, `step ${step}`);
  }
});

test('hash() is repeatable and does not consume', async () => {
  const t = new Transcript(S256);
  t.update(V.clientHello);
  const h1 = await t.hash();
  const h2 = await t.hash();
  eq(h1, h2);
  t.update(V.serverHello);
  eq(await t.hash(), V.helloTranscriptHash, 'later updates still land');
});

test('RFC 8448 s3: the three schedule transcript hashes', async () => {
  const t = new Transcript(S256);
  t.update(V.clientHello);
  t.update(V.serverHello);
  eq(await t.hash(), V.helloTranscriptHash, 'CH..SH');
  // The server flight arrives as one record; the transcript is per-message, but hashing the
  // concatenation is identical, and both orders are exercised across this file.
  t.update(V.encryptedExtensions);
  t.update(V.certificate);
  t.update(V.certificateVerify);
  t.update(V.serverFinished);
  eq(await t.hash(), V.finishedTranscriptHash, 'CH..server Finished');
  t.update(V.clientFinished);
  eq(await t.hash(), V.clientFinishedTranscriptHash, 'CH..client Finished');
});

test('empty transcript hashes to the hash of the empty string', async () => {
  const t = new Transcript(S256);
  eq(await t.hash(), V.emptyHash);
  t.update(new Uint8Array(0));
  eq(await t.hash(), V.emptyHash, 'zero-length update is a no-op');
});

test('RFC 8448 s5: HelloRetryRequest message_hash substitution', async () => {
  const t = new Transcript(S256);
  t.update(HRR.clientHello1);
  await t.replaceWithMessageHash();
  t.update(HRR.helloRetryRequest);
  t.update(HRR.clientHello2);
  t.update(HRR.serverHello);
  // This hash feeds "c hs traffic" in the trace; matching it proves the synthetic
  // message_hash message replaced ClientHello1 exactly as s4.4.1 specifies.
  eq(await t.hash(), HRR.helloTranscriptHash);
});

test('message_hash substitution produces fe || uint24 len || Hash(CH1)', async () => {
  const t = new Transcript(S256);
  t.update(HRR.clientHello1);
  const ch1Hash = await t.hash();
  await t.replaceWithMessageHash();
  assert.equal(t.bytesBuffered, 4 + 32, 'buffer collapsed to one synthetic message');
  const synthetic = concat([Uint8Array.from([0xfe, 0x00, 0x00, 0x20]), ch1Hash]);
  eq(await t.hash(), new Uint8Array(await crypto.subtle.digest(S256, synthetic)));
});

test('update after substitution keeps accumulating normally', async () => {
  const a = new Transcript(S256);
  a.update(HRR.clientHello1);
  await a.replaceWithMessageHash();
  a.update(HRR.helloRetryRequest);
  const b = new Transcript(S256);
  b.update(HRR.clientHello1);
  await b.replaceWithMessageHash();
  b.update(HRR.helloRetryRequest);
  eq(await a.hash(), await b.hash());
});

test('the buffer is bounded', async () => {
  const t = new Transcript(S256, { maxBytes: 100 });
  t.update(new Uint8Array(60));
  await rejectsWithCode(async () => t.update(new Uint8Array(41)), codes.TLS_HANDSHAKE, /100/);
  t.update(new Uint8Array(40)); // exactly at the cap still fits
  assert.equal(t.bytesBuffered, 100);
});

test('updates copy their input: caller reuse of a buffer cannot corrupt history', async () => {
  const t = new Transcript(S256);
  const buf = Uint8Array.from([1, 2, 3, 4]);
  t.update(buf);
  const before = await t.hash();
  buf.fill(0xff);
  eq(await t.hash(), before);
});

test('unknown hash names are rejected at construction', async () => {
  await rejectsWithCode(async () => new Transcript('SHA-512'), codes.CONFIG_INVALID);
});

test('SHA-384 transcripts work (the AES-256 suite path)', async () => {
  const t = new Transcript('SHA-384');
  t.update(V.clientHello);
  eq(await t.hash(), new Uint8Array(await crypto.subtle.digest('SHA-384', V.clientHello)));
});
