// HTTP/2 frame layer (RFC 9113 s4, s6).
//
// The frame reader is a byte-stream parser, so it goes through underAllChunkings: the same frames
// must come out whether the transport delivers one byte at a time or the whole flight at once —
// a parser that behaves differently under fragmentation has a bug that only shows up on a real
// network. The serialisers are checked by round-trip, and the payload parsers by their fail-closed
// size rules (a SETTINGS length not a multiple of 6, a 3-byte WINDOW_UPDATE, an oversized frame).

import test from 'node:test';
import assert from 'node:assert/strict';
import { ByteReader } from '../../src/util/bytes.js';
import {
  dataFrame,
  goawayFrame,
  headersFrame,
  parseGoaway,
  parseSettings,
  parseWindowUpdate,
  readFrame,
  rstStreamFrame,
  serializeFrame,
  settingsFrame,
  stripPadding,
  windowUpdateFrame,
} from '../../src/http2/frames.js';
import { FRAME, FLAG, DEFAULT_MAX_FRAME_SIZE } from '../../src/http2/constants.js';
import { concat } from '../../src/util/bytes.js';
import { readableFrom, chunkings, rejectsWithCode } from '../_harness.js';

const enc = new TextEncoder();

/** Read every frame off a readable until EOF. */
async function readAll(readable, maxFrame = DEFAULT_MAX_FRAME_SIZE) {
  const reader = new ByteReader(readable);
  const out = [];
  for (;;) {
    const f = await readFrame(reader, maxFrame);
    if (f === null) break;
    out.push({ type: f.type, flags: f.flags, streamId: f.streamId, payload: [...f.payload] });
  }
  return out;
}

test('a flight of frames reads back identically under every chunking', async () => {
  const flight = concat([
    settingsFrame([[3, 100], [4, 10485760], [2, 0]]),
    windowUpdateFrame(0, 1048510465),
    headersFrame(1, enc.encode('block'), { endStream: false, endHeaders: true }),
    dataFrame(1, enc.encode('hello data'), false),
    dataFrame(1, new Uint8Array(0), true),
    rstStreamFrame(3, 8),
    goawayFrame(7, 0, enc.encode('bye')),
  ]);
  let reference;
  for (const [name, chunks] of chunkings(flight)) {
    const got = await readAll(readableFrom(chunks));
    if (reference === undefined) reference = got;
    else assert.deepEqual(got, reference, `chunking ${name} disagreed`);
  }
  // Spot-check the decoded shape.
  assert.equal(reference[0].type, FRAME.SETTINGS);
  assert.equal(reference[2].type, FRAME.HEADERS);
  assert.equal(reference[2].flags, FLAG.END_HEADERS);
  assert.equal(reference[4].flags, FLAG.END_STREAM, 'the empty final DATA carries END_STREAM');
});

test('readFrame returns null at a clean frame boundary EOF', async () => {
  const reader = new ByteReader(readableFrom([]));
  assert.equal(await readFrame(reader), null);
});

test('a frame larger than our advertised max is a FRAME_SIZE error, refused at the header', async () => {
  // Claim a 20000-byte payload; the default max we advertise is 16384.
  const header = Uint8Array.from([0x00, 0x4e, 0x20, FRAME.DATA, 0x00, 0x00, 0x00, 0x00, 0x01]);
  const reader = new ByteReader(readableFrom([header]));
  await rejectsWithCode(async () => readFrame(reader), 'HTTP2_FRAME_SIZE', /exceeds SETTINGS_MAX_FRAME_SIZE/);
});

test('the reserved high bit of the stream id is ignored, not treated as part of the id', async () => {
  // Set the top bit of the stream-id word; the id must still read as 1.
  const frame = serializeFrame(FRAME.DATA, 0, 1, enc.encode('x'));
  frame[5] |= 0x80;
  const reader = new ByteReader(readableFrom([frame]));
  const f = await readFrame(reader);
  assert.equal(f.streamId, 1);
});

test('SETTINGS round-trips, and a non-multiple-of-6 length is refused', () => {
  const bytes = settingsFrame([[3, 100], [4, 10485760], [2, 0]]);
  // strip the 9-byte header to get the payload
  assert.deepEqual(parseSettings(bytes.subarray(9)), [[3, 100], [4, 10485760], [2, 0]]);
  assert.throws(() => parseSettings(new Uint8Array(5)), /not a multiple of 6/);
});

test('WINDOW_UPDATE parses its 31-bit increment and rejects a wrong length', () => {
  assert.equal(parseWindowUpdate(windowUpdateFrame(0, 1048510465).subarray(9)), 1048510465);
  assert.throws(() => parseWindowUpdate(new Uint8Array(3)), /must be 4/);
});

test('GOAWAY round-trips last-stream-id, code and debug data', () => {
  const g = parseGoaway(goawayFrame(42, 5, enc.encode('nope')).subarray(9));
  assert.equal(g.lastStreamId, 42);
  assert.equal(g.errorCode, 5);
  assert.equal(new TextDecoder().decode(g.debug), 'nope');
});

test('stripPadding removes the pad length and padding, and rejects an over-long pad', () => {
  // pad length 3, one data byte, three padding bytes.
  const padded = Uint8Array.from([3, 0x41, 0, 0, 0]);
  assert.deepEqual([...stripPadding(padded).data], [0x41]);
  // pad length 5 with only 4 bytes following is a protocol error.
  assert.throws(() => stripPadding(Uint8Array.from([5, 0, 0, 0, 0])), /not smaller than/);
});

test('the SETTINGS ACK is an empty frame with the ACK flag', () => {
  const ack = settingsFrame([], true);
  assert.equal(ack.length, 9, 'header only');
  assert.equal(ack[3], FRAME.SETTINGS);
  assert.equal(ack[4], FLAG.ACK);
});
