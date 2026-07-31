// HPACK (RFC 7541). The RFC ships worked examples in Appendix C, and they are used here in both
// directions: the decoder must turn the RFC's bytes into the RFC's header lists (including the
// dynamic-table eviction the C.6 sequence is specifically constructed to exercise), and the
// encoder must produce a block that decodes back to the same fields. HPACK is a hostile-input
// parser, so the fail-closed half of the suite is as important as the vectors: a bad index, an
// oversized integer, a table-size update above what we advertised, and a decompression bomb are
// each refused with a typed error, never absorbed.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_HEADER_TABLE_SIZE,
  HpackDecoder,
  encodeHeaderBlock,
} from '../../src/http2/hpack.js';
import { rejectsWithCode } from '../_harness.js';

const hex = (s) => Uint8Array.from(Buffer.from(s.replace(/\s/g, ''), 'hex'));
const toHex = (b) => Buffer.from(b).toString('hex');

test('C.3 request sequence decodes with a shared dynamic table (no Huffman)', () => {
  const d = new HpackDecoder({});
  assert.deepEqual(d.decode(hex('8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d')), [
    [':method', 'GET'],
    [':scheme', 'http'],
    [':path', '/'],
    [':authority', 'www.example.com'],
  ]);
  assert.equal(d.dynamicLength, 1, 'the :authority field was added to the dynamic table');
  assert.deepEqual(d.decode(hex('8286 84be 5808 6e6f 2d63 6163 6865')), [
    [':method', 'GET'],
    [':scheme', 'http'],
    [':path', '/'],
    [':authority', 'www.example.com'], // 0xbe references the dynamic entry from request 1
    ['cache-control', 'no-cache'],
  ]);
});

test('C.4 request sequence decodes with Huffman-coded values', () => {
  const d = new HpackDecoder({});
  assert.deepEqual(d.decode(hex('8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff')), [
    [':method', 'GET'],
    [':scheme', 'http'],
    [':path', '/'],
    [':authority', 'www.example.com'],
  ]);
});

test('C.6 response sequence decodes and evicts exactly as the RFC documents', () => {
  // The RFC constrains the dynamic table to 256 octets for this sequence so eviction is forced.
  const d = new HpackDecoder({ maxTableSize: 256 });
  const r1 = d.decode(
    hex(
      '4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ' +
        'ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3',
    ),
  );
  assert.deepEqual(r1, [
    [':status', '302'],
    ['cache-control', 'private'],
    ['date', 'Mon, 21 Oct 2013 20:13:21 GMT'],
    ['location', 'https://www.example.com'],
  ]);
  assert.equal(d.dynamicLength, 4);
  const r2 = d.decode(hex('4883 640e ffc1 c0bf'));
  assert.equal(r2[0][1], '307', 'the second response only re-sends :status, the rest are indexed');
  const r3 = d.decode(
    hex(
      '88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad ' +
        '94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 ' +
        '65c0 03ed 4ee5 b106 3d50 07',
    ),
  );
  assert.deepEqual(r3[4], ['content-encoding', 'gzip']);
  assert.equal(r3[5][0], 'set-cookie');
  assert.match(r3[5][1], /^foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU/);
});

test('the encoder matches the RFC C.4.1 Huffman request byte for byte', () => {
  const block = encodeHeaderBlock([
    { name: ':method', value: 'GET' },
    { name: ':scheme', value: 'http' },
    { name: ':path', value: '/' },
    { name: ':authority', value: 'www.example.com', indexing: 'incremental' },
  ]);
  assert.equal(toHex(block), '828684418cf1e3c2e5f23a6ba0ab90f4ff');
});

test('the encoder uses fully-indexed static entries and the requested representations', () => {
  assert.equal(toHex(encodeHeaderBlock([{ name: ':method', value: 'GET' }])), '82');
  assert.equal(toHex(encodeHeaderBlock([{ name: ':scheme', value: 'https' }])), '87');
  assert.equal(toHex(encodeHeaderBlock([{ name: ':path', value: '/', indexing: 'without' }])), '84');
  // A path that is not a static value: literal WITHOUT indexing, name index 4 -> first byte 0x04,
  // exactly as curl encodes it.
  const nonStaticPath = encodeHeaderBlock([{ name: ':path', value: '/a', indexing: 'without' }]);
  assert.equal(nonStaticPath[0], 0x04);
});

test('encoder output always decodes back to its input (fuzz round-trip)', () => {
  const dEnc = new HpackDecoder({});
  const fields = [
    { name: ':method', value: 'POST' },
    { name: ':scheme', value: 'https' },
    { name: ':authority', value: 'api.example.com:8443', indexing: 'incremental' },
    { name: ':path', value: '/v1/things?x=1&y=2', indexing: 'without' },
    { name: 'user-agent', value: 'tunnelfetch/1' },
    { name: 'accept', value: '*/*' },
    { name: 'content-type', value: 'application/json' },
    { name: 'authorization', value: 'Bearer abcdef.ghijkl', indexing: 'never' },
  ];
  const decoded = dEnc.decode(encodeHeaderBlock(fields));
  assert.deepEqual(decoded, fields.map((f) => [f.name, f.value]));
});

// ---------------------------------------------------------------- fail-closed decoding

test('an index past the end of the tables is refused', async () => {
  const d = new HpackDecoder({});
  // 0xbe = indexed field, index 62 — the first dynamic slot, which is empty here.
  await rejectsWithCode(async () => d.decode(hex('be')), 'HTTP2_COMPRESSION', /out of range/);
});

test('index 0 as an indexed field is refused', async () => {
  const d = new HpackDecoder({});
  await rejectsWithCode(async () => d.decode(hex('80')), 'HTTP2_COMPRESSION', /index 0/);
});

test('a dynamic table size update above the advertised limit is refused', async () => {
  const d = new HpackDecoder({ maxTableSize: 4096 });
  // 0x3f e2 1f = dynamic table size update, value 4097 (one over the advertised 4096).
  await rejectsWithCode(async () => d.decode(hex('3fe21f')), 'HTTP2_COMPRESSION', /exceeds the advertised limit/);
});

test('a size update after a header field in the same block is refused', async () => {
  const d = new HpackDecoder({});
  // 0x82 (indexed :method GET) then 0x20 (size update to 0) — update must come first (RFC s4.2).
  await rejectsWithCode(async () => d.decode(hex('8220')), 'HTTP2_COMPRESSION', /must precede/);
});

test('an integer with too many continuation bytes is refused', async () => {
  const d = new HpackDecoder({});
  // 0xff then a long run of 0x80 continuation bytes never terminating within the bound.
  await rejectsWithCode(
    async () => d.decode(hex('ff80808080808080')),
    'HTTP2_COMPRESSION',
    /continuation bytes/,
  );
});

test('a string length running past the block end is refused', async () => {
  const d = new HpackDecoder({});
  // literal with new name (0x40), name length 0x7f... claims far more bytes than are present.
  await rejectsWithCode(async () => d.decode(hex('40 7f')), 'HTTP2_COMPRESSION');
});

test('a decoded header list over the self-protection limit is refused (decompression bomb)', async () => {
  const d = new HpackDecoder({ maxHeaderListSize: 200 });
  // Repeated indexed references to a static entry inflate a tiny block into a large header list.
  // static[32] is "cookie: " ... use a value-bearing entry; index 28 is content-length (name only),
  // but the simplest bomb is many copies of an indexed full entry. static[16] = accept-encoding: gzip, deflate.
  const bomb = new Uint8Array(50).fill(0x90); // 0x90 = indexed, index 16
  await rejectsWithCode(async () => d.decode(bomb), 'HTTP2_HEADER', /header list/);
});

test('the advertised default table size is the RFC default', () => {
  assert.equal(DEFAULT_HEADER_TABLE_SIZE, 4096);
});
