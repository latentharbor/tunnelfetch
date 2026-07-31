// decodeChunked: grammar-exact decoding under every chunking of the input.
//
// The decoder's data phase must be driven by declared lengths, never by scanning for
// delimiters — the binary-safety test below feeds CRLFs as payload to prove it. Every error
// case asserts a code: a decoder that fails with the wrong error is one refactor away from
// not failing at all.

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeChunked } from '../../src/http1/chunked.js';
import { codes } from '../../src/errors.js';
import { ByteReader, latin1, utf8 } from '../../src/util/bytes.js';
import {
  underAllChunkings,
  readableFrom,
  fixedChunks,
  rejectsWithCode,
  collect,
  rng,
} from '../_harness.js';

/** Decode under the matrix, reporting payload, trailers, and what stayed in the reader. */
const decode = (opts) => async (readable) => {
  const reader = new ByteReader(readable);
  const { stream, trailers } = decodeChunked(reader, opts);
  const payload = latin1(await collect(stream));
  const t = await trailers;
  const leftover = latin1(await reader.readToEnd());
  return { payload, trailers: t === null ? null : [...t], leftover };
};

describe('decodeChunked: well-formed bodies', () => {
  test('single chunk', async () => {
    const got = await underAllChunkings(utf8('5\r\nhello\r\n0\r\n\r\n'), decode());
    assert.deepEqual(got, { payload: 'hello', trailers: [], leftover: '' });
  });

  test('zero-length body', async () => {
    const got = await underAllChunkings(utf8('0\r\n\r\n'), decode());
    assert.deepEqual(got, { payload: '', trailers: [], leftover: '' });
  });

  test('several chunks concatenate in order', async () => {
    const bytes = utf8('3\r\nfoo\r\n4\r\nbarb\r\n2\r\naz\r\n0\r\n\r\n');
    const got = await underAllChunkings(bytes, decode());
    assert.deepEqual(got, { payload: 'foobarbaz', trailers: [], leftover: '' });
  });

  test('uppercase, lowercase, and multi-digit hex sizes', async () => {
    const body =
      'A\r\n' + 'x'.repeat(10) + '\r\n' + 'a\r\n' + 'y'.repeat(10) + '\r\n' +
      '1F\r\n' + 'z'.repeat(31) + '\r\n' + '0\r\n\r\n';
    const got = await underAllChunkings(utf8(body), decode());
    assert.deepEqual(got.payload, 'x'.repeat(10) + 'y'.repeat(10) + 'z'.repeat(31));
  });

  test('chunk extensions are parsed off and ignored, BWS before ";" tolerated', async () => {
    const body =
      '5;name=value\r\nhello\r\n' +
      '5;a=1;b="quoted;stuff"\r\nworld\r\n' +
      '5 ;bws\r\nagain\r\n' +
      '5\t;tab\r\nfinal\r\n' +
      '0\r\n\r\n';
    const got = await underAllChunkings(utf8(body), decode());
    assert.equal(got.payload, 'helloworldagainfinal');
  });

  test('payload with CRLFs and chunk-header lookalikes is inert (binary safety)', async () => {
    // Data is "\r\n\r\n" and "0\r\n\r\n" — if any part of the data phase scanned for
    // delimiters instead of counting bytes, this would end the body early.
    const bytes = utf8('4\r\n\r\n\r\n\r\n6\r\n0\r\n\r\n0\r\n0\r\n\r\n');
    const got = await underAllChunkings(bytes, decode());
    assert.deepEqual(got, { payload: '\r\n\r\n0\r\n\r\n0', trailers: [], leftover: '' });
  });

  test('bytes after the terminal CRLF stay in the reader for the next message', async () => {
    const got = await underAllChunkings(utf8('3\r\nabc\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n'), decode());
    assert.deepEqual(got, { payload: 'abc', trailers: [], leftover: 'HTTP/1.1 200 OK\r\n' });
  });

  test('many pseudo-random chunks survive every chunking', async () => {
    const next = rng(0xc0ffee);
    let wire = '';
    let expected = '';
    for (let i = 0; i < 25; i++) {
      const len = 1 + Math.floor(next() * 40);
      let data = '';
      for (let j = 0; j < len; j++) data += String.fromCharCode(33 + Math.floor(next() * 90));
      expected += data;
      wire += `${len.toString(16)}\r\n${data}\r\n`;
    }
    wire += '0\r\n\r\n';
    const got = await underAllChunkings(utf8(wire), decode());
    assert.deepEqual(got, { payload: expected, trailers: [], leftover: '' });
  });
});

describe('decodeChunked: trailers', () => {
  test('trailer fields are parsed and exposed, duplicates folded', async () => {
    const got = await underAllChunkings(
      utf8('5\r\nhello\r\n0\r\nExpires: never\r\nX-A: 1\r\nX-A: 2\r\n\r\n'),
      decode(),
    );
    assert.deepEqual(got, {
      payload: 'hello',
      trailers: [
        ['expires', 'never'],
        ['x-a', '1, 2'],
      ],
      leftover: '',
    });
  });

  test('malformed trailer lines are rejected', async () => {
    const bad = [
      'no-colon-here', // no name/value separator
      ' X-Fold: 1', // obs-fold / leading whitespace
      'Bad Name: 1', // name is not a token
      ': empty-name', // empty name
      'X-Ctl: a\x01b', // control byte in value
    ];
    for (const line of bad) {
      await rejectsWithCode(
        () => underAllChunkings(utf8(`0\r\n${line}\r\n\r\n`), decode()),
        codes.HTTP_TRAILER,
      );
    }
  });

  test('an oversized trailer section hits the limit', async () => {
    const bytes = utf8(`0\r\nX-Big: ${'a'.repeat(64)}\r\n\r\n`);
    for (const chunks of [[bytes], fixedChunks(bytes, 1)]) {
      await rejectsWithCode(async () => {
        const reader = new ByteReader(readableFrom(chunks));
        const { stream } = decodeChunked(reader, { maxTrailerBytes: 32 });
        await collect(stream);
      }, codes.LIMIT_HEADER);
    }
  });
});

describe('decodeChunked: malformed framing', () => {
  const rejects = (body, code, msgMatch) =>
    rejectsWithCode(() => underAllChunkings(utf8(body), decode()), code, msgMatch);

  test('chunk data not followed by CRLF', async () => {
    // Size says 5 but a sixth data byte sits where CRLF must be: the sender's own framing
    // disagrees with itself, and resynchronising would be guessing.
    await rejects('5\r\nhelloX\r\n0\r\n\r\n', codes.HTTP_CHUNK, /CRLF/);
    await rejects('5\r\nhello\rX0\r\n\r\n', codes.HTTP_CHUNK, /CRLF/);
  });

  test('leading whitespace, signs, and other non-hex prefixes on the size', async () => {
    for (const line of [' 5', '+5', '-5', '0x5', '5 ', 'g5', '']) {
      await rejects(`${line}\r\nhello\r\n0\r\n\r\n`, codes.HTTP_CHUNK, /chunk size/);
    }
  });

  test('a bare-LF size line is rejected', async () => {
    await rejects('5\nhello\r\n0\r\n\r\n', codes.HTTP_CHUNK, /bare LF/);
  });

  test('a size that overflows a safe integer', async () => {
    await rejects('FFFFFFFFFFFFFFFF\r\nx\r\n0\r\n\r\n', codes.HTTP_CHUNK, /overflow/);
  });

  test('a size over maxChunkSize', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('11\r\n' + 'x'.repeat(17) + '\r\n0\r\n\r\n'),
        decode({ maxChunkSize: 16 })),
      codes.HTTP_CHUNK,
      /maxChunkSize/,
    );
  });

  test('an unbounded chunk-size line cannot make us buffer forever', async () => {
    await rejects(`1;${'e'.repeat(4096)}\r\nx\r\n0\r\n\r\n`, codes.HTTP_CHUNK, /exceeded/);
  });

  test('total payload over maxBytes is rejected at the size line', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n'),
        decode({ maxBytes: 8 })),
      codes.LIMIT_BODY,
    );
  });
});

describe('decodeChunked: truncation', () => {
  const truncated = (body) =>
    rejectsWithCode(() => underAllChunkings(utf8(body), decode()), codes.HTTP_BODY_TRUNCATED);

  test('EOF at every stage before the terminator is HTTP_BODY_TRUNCATED', async () => {
    await truncated(''); // before any chunk
    await truncated('5'); // inside the size line
    await truncated('5\r\n'); // before any data
    await truncated('5\r\nhel'); // inside chunk data
    await truncated('5\r\nhello'); // before the data CRLF
    await truncated('5\r\nhello\r'); // inside the data CRLF
    await truncated('5\r\nhello\r\n'); // before the terminal chunk
    await truncated('5\r\nhello\r\n0\r\n'); // before the final CRLF
    await truncated('5\r\nhello\r\n0\r\nX-T: 1\r\n'); // inside the trailer section
  });
});

describe('decodeChunked: cancellation', () => {
  test('cancelling the stream resolves trailers to null (connection not reusable)', async () => {
    const reader = new ByteReader(readableFrom([utf8('5\r\nhello\r\n0\r\n\r\n')]));
    const { stream, trailers } = decodeChunked(reader);
    await stream.cancel();
    assert.equal(await trailers, null);
  });
});
