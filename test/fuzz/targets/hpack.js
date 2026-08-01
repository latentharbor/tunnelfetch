// HPACK: a stateful decoder with a dynamic table the PEER controls the size of, plus Huffman
// decoding. State that a peer drives across frames is exactly where a decoder desynchronises.

import { HpackDecoder } from '../../../src/http2/hpack.js';
import { encodeHeaderBlock } from '../../../src/http2/hpack.js';

export default {
  name: 'http2.HpackDecoder.decode',
  corpus: [
    encodeHeaderBlock([
      { name: ':status', value: '200' },
      { name: 'content-type', value: 'text/html; charset=utf-8' },
    ]),
    encodeHeaderBlock([{ name: ':status', value: '404' }]),
    encodeHeaderBlock([
      { name: 'set-cookie', value: 'session=abcdefghijklmnop; Path=/; Secure; HttpOnly' },
      { name: 'x-custom-header-name-that-is-long', value: 'and a value to match' },
    ]),
  ],
  // A fresh decoder per case: the dynamic table is per-connection, and carrying it across
  // unrelated cases would make failures depend on iteration order rather than on the input.
  run: (input) => new HpackDecoder({}).decode(input),
};
