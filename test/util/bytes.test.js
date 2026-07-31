// The shared byte plumbing is load-bearing for every other layer, so it gets tested against the
// same chunking adversary the protocol parsers face.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ByteReader,
  ByteWriter,
  UnexpectedEofError,
  concat,
  indexOf,
  equal,
  timingSafeEqual,
  toHex,
  fromHex,
  utf8,
  latin1,
  u8,
  u16,
  u24,
  u32,
  readU16,
  readU24,
  readU32,
} from '../../src/util/bytes.js';
import {
  readableFrom,
  recordingWritable,
  chunkings,
  underAllChunkings,
  rejectsWithCode,
  fixedChunks,
  randomChunks,
} from '../_harness.js';

const CRLF = utf8('\r\n');
const CRLFCRLF = utf8('\r\n\r\n');

test('readExactly returns exact lengths under every chunking', async () => {
  const src = new Uint8Array(64);
  for (let i = 0; i < 64; i++) src[i] = i;
  await underAllChunkings(
    src,
    async (readable) => {
      const r = new ByteReader(readable);
      const a = await r.readExactly(1);
      const b = await r.readExactly(31);
      const c = await r.readExactly(32);
      return [toHex(a), toHex(b), toHex(c), r.buffered];
    },
    (x) => x,
  );
});

test('readExactly across chunk boundaries reassembles correctly', async () => {
  const src = fromHex('00112233445566778899aabbccddeeff');
  for (const [, chunks] of chunkings(src)) {
    const r = new ByteReader(readableFrom(chunks));
    assert.equal(toHex(await r.readExactly(5)), '0011223344');
    assert.equal(toHex(await r.readExactly(11)), '5566778899aabbccddeeff');
    assert.equal(await r.readSome(), null);
  }
});

test('readExactly throws UnexpectedEof with the byte counts, not a generic error', async () => {
  const r = new ByteReader(readableFrom([fromHex('0011')]));
  let err;
  try {
    await r.readExactly(5, 'TLS record header');
  } catch (e) {
    err = e;
  }
  assert.ok(err instanceof UnexpectedEofError);
  assert.equal(err.code, 'UNEXPECTED_EOF');
  assert.match(err.message, /after 2 of 5 bytes/);
  assert.match(err.message, /TLS record header/);
});

test('readExactly(0) is legal and consumes nothing', async () => {
  const r = new ByteReader(readableFrom([fromHex('aabb')]));
  assert.equal((await r.readExactly(0)).byteLength, 0);
  assert.equal(toHex(await r.readExactly(2)), 'aabb');
});

test('readSome returns null exactly once at clean EOF', async () => {
  const r = new ByteReader(readableFrom([utf8('hi')]));
  assert.equal(latin1(await r.readSome()), 'hi');
  assert.equal(await r.readSome(), null);
  assert.equal(await r.readSome(), null);
});

test('empty chunks are transparent', async () => {
  const r = new ByteReader(
    readableFrom([new Uint8Array(0), utf8('a'), new Uint8Array(0), new Uint8Array(0), utf8('b')]),
  );
  assert.equal(latin1(await r.readExactly(2)), 'ab');
});

test('readUntil finds a delimiter that straddles chunks', async () => {
  const head = utf8('HTTP/1.0 200 OK\r\nVia: x\r\n\r\n');
  const payload = utf8('PAYLOAD');
  const all = concat([head, payload]);
  await underAllChunkings(all, async (readable) => {
    const r = new ByteReader(readable);
    const block = await r.readUntil(CRLFCRLF, 4096, 'proxy reply');
    const rest = await r.readToEnd();
    return [latin1(block), latin1(rest)];
  });
  // and the values themselves are right
  const r = new ByteReader(readableFrom(fixedChunks(all, 1)));
  assert.equal(latin1(await r.readUntil(CRLFCRLF, 4096)), latin1(head));
  assert.equal(latin1(await r.readToEnd()), 'PAYLOAD');
});

test('readUntil enforces its limit rather than buffering without bound', async () => {
  const flood = new Uint8Array(5000).fill(0x41);
  const r = new ByteReader(readableFrom([flood]));
  await rejectsWithCode(() => r.readUntil(CRLFCRLF, 1024, 'header block'), 'LIMIT_HEADER');
});

test('readUntil rejects when the delimiter lands past the limit', async () => {
  const bytes = concat([new Uint8Array(2000).fill(0x41), CRLFCRLF]);
  const r = new ByteReader(readableFrom([bytes]));
  await rejectsWithCode(() => r.readUntil(CRLFCRLF, 1024), 'LIMIT_HEADER');
});

test('readUntil at EOF without a delimiter throws rather than returning a partial', async () => {
  const r = new ByteReader(readableFrom([utf8('no terminator here')]));
  await rejectsWithCode(() => r.readUntil(CRLF, 4096, 'status line'), 'UNEXPECTED_EOF');
});

test('unshift puts bytes back in front, including after a partial take', async () => {
  const r = new ByteReader(readableFrom([utf8('WORLD')]));
  assert.equal(latin1(await r.readExactly(2)), 'WO');
  r.unshift(utf8('xy'));
  assert.equal(latin1(await r.readExactly(5)), 'xyRLD');
});

test('unshift of an empty array is a no-op', async () => {
  const r = new ByteReader(readableFrom([utf8('ab')]));
  r.unshift(new Uint8Array(0));
  assert.equal(latin1(await r.readExactly(2)), 'ab');
});

test('readToEnd enforces its limit', async () => {
  const r = new ByteReader(readableFrom(fixedChunks(new Uint8Array(3000), 64)));
  await rejectsWithCode(() => r.readToEnd(1000), 'LIMIT_BODY');
});

test('buffered/atEof track state honestly', async () => {
  const r = new ByteReader(readableFrom([utf8('abcd')]));
  assert.equal(r.atEof, false);
  await r.readExactly(4);
  // atEof only becomes true once the source has actually reported done
  assert.equal(await r.readSome(), null);
  assert.equal(r.atEof, true);
  assert.equal(r.buffered, 0);
});

test('a source that errors mid-stream propagates rather than truncating', async () => {
  const boom = new Error('socket reset');
  const readable = new ReadableStream({
    start(c) {
      c.enqueue(utf8('ab'));
    },
    pull(c) {
      c.error(boom);
    },
  });
  const r = new ByteReader(readable);
  await assert.rejects(() => r.readExactly(8), /socket reset/);
});

test('ByteWriter writeAll coalesces into a single write', async () => {
  // `bytes` is a getter over the accumulated chunks; destructuring it would snapshot an empty
  // buffer before anything is written, so hold onto the object.
  const rec = recordingWritable();
  const w = new ByteWriter(rec.stream);
  await w.writeAll([utf8('GET '), utf8('/ '), utf8('HTTP/1.1\r\n')]);
  w.releaseLock();
  assert.equal(rec.chunks.length, 1);
  assert.equal(latin1(rec.bytes), 'GET / HTTP/1.1\r\n');
});

test('ByteWriter close and releaseLock are idempotent', async () => {
  const { stream } = recordingWritable();
  const w = new ByteWriter(stream);
  await w.write(utf8('x'));
  await w.close();
  await w.close();
  w.releaseLock();
});

test('indexOf handles overlap, absence and out-of-range starts', () => {
  const hay = utf8('aaabaaab');
  assert.equal(indexOf(hay, utf8('aab')), 1);
  assert.equal(indexOf(hay, utf8('aab'), 2), 5);
  assert.equal(indexOf(hay, utf8('zzz')), -1);
  assert.equal(indexOf(hay, utf8('b'), 99), -1);
  assert.equal(indexOf(hay, utf8('a'), -5), 0);
});

test('equal and timingSafeEqual agree on content and reject length mismatch', () => {
  const a = fromHex('00ff10');
  assert.equal(equal(a, fromHex('00ff10')), true);
  assert.equal(equal(a, fromHex('00ff11')), false);
  assert.equal(equal(a, fromHex('00ff')), false);
  assert.equal(timingSafeEqual(a, fromHex('00ff10')), true);
  assert.equal(timingSafeEqual(a, fromHex('00ff11')), false);
  assert.equal(timingSafeEqual(a, fromHex('00ff')), false);
  // differing in the first byte vs the last must both be false
  assert.equal(timingSafeEqual(fromHex('ff0000'), fromHex('000000')), false);
  assert.equal(timingSafeEqual(fromHex('0000ff'), fromHex('000000')), false);
});

test('hex round-trips and rejects odd input', () => {
  const b = fromHex('de:ad be ef');
  assert.equal(toHex(b), 'deadbeef');
  assert.throws(() => fromHex('abc'), /odd-length/);
  assert.equal(toHex(new Uint8Array(0)), '');
});

test('latin1 preserves high bytes that UTF-8 decoding would mangle', () => {
  const raw = new Uint8Array([0x74, 0x65, 0x78, 0x74, 0xe9, 0xff]);
  assert.equal(latin1(raw), 'textéÿ');
  assert.notEqual(latin1(raw), new TextDecoder().decode(raw));
});

test('big-endian writers and readers round-trip', () => {
  assert.equal(toHex(u8(0xab)), 'ab');
  assert.equal(toHex(u16(0x1234)), '1234');
  assert.equal(toHex(u24(0x123456)), '123456');
  assert.equal(toHex(u32(0x12345678)), '12345678');
  assert.equal(readU16(fromHex('1234')), 0x1234);
  assert.equal(readU24(fromHex('123456')), 0x123456);
  assert.equal(readU32(fromHex('ffffffff')), 0xffffffff);
  assert.equal(readU32(fromHex('0012345678'), 1), 0x12345678);
  // u32 must not sign-flip at the top bit
  assert.equal(toHex(u32(0xffffffff)), 'ffffffff');
});

test('concat with an explicit total avoids a copy for the single-chunk case', () => {
  const only = fromHex('aabb');
  assert.equal(concat([only], 2), only);
  assert.equal(toHex(concat([fromHex('aa'), fromHex('bb')])), 'aabb');
  assert.equal(concat([]).byteLength, 0);
});

test('randomChunks is deterministic for a given seed', () => {
  const src = new Uint8Array(200).fill(7);
  const a = randomChunks(src, 42).map((c) => c.byteLength);
  const b = randomChunks(src, 42).map((c) => c.byteLength);
  const c = randomChunks(src, 43).map((x) => x.byteLength);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
  assert.equal(
    a.reduce((s, n) => s + n, 0),
    200,
  );
});

test('underAllChunkings surfaces a parser that depends on chunk boundaries', async () => {
  const bytes = utf8('abcdef');
  // A deliberately broken parser: it only looks at the first chunk.
  const broken = async (readable) => {
    const reader = readable.getReader();
    const { value } = await reader.read();
    reader.releaseLock();
    return latin1(value ?? new Uint8Array(0));
  };
  await assert.rejects(() => underAllChunkings(bytes, broken), /disagreed with/);
});

test('underAllChunkings reports a consistent throw as a throw', async () => {
  const bytes = utf8('ab');
  const alwaysThrows = async (readable) => {
    const r = new ByteReader(readable);
    return r.readExactly(99, 'thing');
  };
  const err = await assert.rejects(() => underAllChunkings(bytes, alwaysThrows));
  assert.equal(err, undefined); // assert.rejects resolves undefined; the point is it threw
});
