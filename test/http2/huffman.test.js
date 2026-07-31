// HPACK Huffman coding (RFC 7541 s5.2, Appendix B).
//
// The table is the RFC's, so the strongest checks are against the RFC's own encoded examples
// (Appendix C.4/C.6 use Huffman) and against a real curl capture, plus the three decoding errors
// s5.2 names. A Huffman decoder that is lax about padding lets two peers read a header differently,
// which is the HPACK equivalent of a framing disagreement.

import test from 'node:test';
import assert from 'node:assert/strict';
import { huffmanDecode, huffmanEncode } from '../../src/http2/huffman.js';
import { rejectsWithCode } from '../_harness.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = (s) => Uint8Array.from(Buffer.from(s.replace(/\s/g, ''), 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');

test('RFC 7541 C.6.1 encoded values decode to the documented strings', () => {
  // "www.example.com", "no-cache", the date, and the location URL from the response examples.
  assert.equal(dec.decode(huffmanDecode(hex('f1e3c2e5f23a6ba0ab90f4ff'))), 'www.example.com');
  assert.equal(dec.decode(huffmanDecode(hex('a8eb10649cbf'))), 'no-cache');
  assert.equal(
    dec.decode(huffmanDecode(hex('d07abe941054d444a8200595040b8166e082a62d1bff'))),
    'Mon, 21 Oct 2013 20:13:21 GMT',
  );
  assert.equal(
    dec.decode(huffmanDecode(hex('9d29ad171863c78f0b97c8e9ae82ae43d3'))),
    'https://www.example.com',
  );
});

test('encoding matches the RFC vectors byte for byte', () => {
  assert.equal(toHex(huffmanEncode(enc.encode('www.example.com'))), 'f1e3c2e5f23a6ba0ab90f4ff');
  assert.equal(toHex(huffmanEncode(enc.encode('no-cache'))), 'a8eb10649cbf');
});

test('a real curl User-Agent value encodes to exactly the captured bytes', () => {
  // Captured from curl 8.7.1 / nghttp2 1.69.0 over a live ALPN h2 handshake.
  assert.equal(toHex(huffmanEncode(enc.encode('curl/8.7.1'))), '25b650c3cbbab87f');
});

test('encode/decode round-trips over the whole byte range, including obs-text', async (t) => {
  const samples = [
    '',
    'a',
    '/',
    'custom-key',
    'custom-header',
    'text/html,application/xhtml+xml',
    'Mon, 21 Oct 2013 20:13:22 GMT',
    '!#$%&\'()*+,-./0123456789',
  ];
  for (const s of samples) {
    const b = enc.encode(s);
    assert.deepEqual(huffmanDecode(huffmanEncode(b)), b, `round trip ${JSON.stringify(s)}`);
  }
  // every single octet value
  const all = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all[i] = i;
  assert.deepEqual(huffmanDecode(huffmanEncode(all)), all, 'all 256 octet values');
});

test('padding that is not the EOS prefix (a zero bit) is rejected', async () => {
  // 0x00 = eight zero bits: no symbol completes, and the leftover is not all-ones EOS padding.
  await rejectsWithCode(async () => huffmanDecode(hex('00')), 'HTTP2_COMPRESSION', /padding/i);
});

test('padding longer than seven bits is rejected', async () => {
  // Encode a short symbol then append a whole byte of ones: that trailing byte is 8 bits of
  // padding, over the 7-bit maximum (a full extra byte could have carried another symbol).
  // '0' (sym 48) is the 5-bit code 00000; follow it with 11 ones -> 16 bits, last 11 are padding.
  await rejectsWithCode(async () => huffmanDecode(hex('07ff')), 'HTTP2_COMPRESSION', /padding|EOS/i);
});

test('a decoded EOS symbol is rejected', async () => {
  // 30 one-bits form the EOS code; 0xffffffff carries it and then some.
  await rejectsWithCode(async () => huffmanDecode(hex('ffffffff')), 'HTTP2_COMPRESSION', /EOS|padding/i);
});
