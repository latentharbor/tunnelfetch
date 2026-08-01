// Chunked transfer decoding. Every chunk size is a hex length the peer chose, and the body ends
// only when the framing says so — "the caller stopped reading" is not an ending. Getting this wrong
// in either direction (accepting a truncated body, or mis-summing sizes) is a correctness hole
// that the pool would then hand to the next request on the same socket.

import { ByteReader } from '../../../src/util/bytes.js';
import { decodeChunked } from '../../../src/http1/chunked.js';
import { readableFrom, collect } from '../../_harness.js';

const enc = new TextEncoder();
const body = (s) => enc.encode(s);

export default {
  name: 'http1.decodeChunked',
  corpus: [
    body('5\r\nhello\r\n0\r\n\r\n'),
    body('a\r\n0123456789\r\n3\r\nabc\r\n0\r\ntrailer: x\r\n\r\n'),
    body('5;ext=1\r\nhello\r\n0\r\n\r\n'),
    body('0\r\n\r\n'),
  ],
  run: async (input) => {
    const { stream, trailers } = decodeChunked(new ByteReader(readableFrom([input])));
    await collect(stream);
    await trailers;
  },
};
