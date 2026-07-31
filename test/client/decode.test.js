// Content-Encoding and charset. The deflate tests are the point of the file: RFC 9110 says
// zlib-wrapped, half the internet sends raw, and both shapes must decode.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeBody,
  ACCEPT_ENCODING,
  charsetFor,
  charsetFromContentType,
  decodeText,
} from '../../src/client/decode.js';
import { utf8, latin1, concat } from '../../src/util/bytes.js';
import { readableFrom, collect, rejectsWithCode, fixedChunks } from '../_harness.js';

const PAYLOAD = utf8('The quick brown fox jumps over the lazy dog. '.repeat(40));

/** Compress bytes with a web CompressionStream — the same primitive the runtime offers. */
async function compress(bytes, format) {
  const cs = new CompressionStream(format);
  const done = collect(cs.readable);
  const w = cs.writable.getWriter();
  await w.write(bytes);
  await w.close();
  return done;
}

// ---------------------------------------------------------------- content-encoding

test('the advertised Accept-Encoding is exactly what decodeBody supports', () => {
  // If this changes, the decode side changed without the request side (or vice versa).
  assert.equal(ACCEPT_ENCODING, 'gzip, deflate');
});

test('gzip round-trips', async () => {
  const wire = await compress(PAYLOAD, 'gzip');
  const out = await collect(decodeBody(readableFrom([wire]), 'gzip'));
  assert.deepEqual(out, PAYLOAD);
});

test('x-gzip is an alias for gzip', async () => {
  const wire = await compress(PAYLOAD, 'gzip');
  const out = await collect(decodeBody(readableFrom([wire]), 'x-gzip'));
  assert.deepEqual(out, PAYLOAD);
});

test('deflate: zlib-wrapped data (the RFC shape) decodes', async () => {
  const wire = await compress(PAYLOAD, 'deflate');
  // Sanity-check the premise of the sniff: this really is a zlib header.
  assert.equal(wire[0] & 0x0f, 8);
  assert.equal(((wire[0] << 8) | wire[1]) % 31, 0);
  const out = await collect(decodeBody(readableFrom([wire]), 'deflate'));
  assert.deepEqual(out, PAYLOAD);
});

test('deflate: RAW deflate (the broken-server shape) is sniffed and decodes', async () => {
  const wire = await compress(PAYLOAD, 'deflate-raw');
  // Premise check: raw deflate must NOT look like a zlib header, or the sniff is vacuous.
  const looksZlib = (wire[0] & 0x0f) === 8 && ((wire[0] << 8) | wire[1]) % 31 === 0;
  assert.equal(looksZlib, false);
  const out = await collect(decodeBody(readableFrom([wire]), 'deflate'));
  assert.deepEqual(out, PAYLOAD);
});

test('the deflate sniff survives byte-by-byte delivery of both shapes', async () => {
  for (const format of ['deflate', 'deflate-raw']) {
    const wire = await compress(PAYLOAD, format);
    const out = await collect(decodeBody(readableFrom(fixedChunks(wire, 1)), 'deflate'));
    assert.deepEqual(out, PAYLOAD, format);
  }
});

test('identity and an absent Content-Encoding pass bytes through untouched', async () => {
  for (const ce of ['identity', '', null, undefined, 'identity, identity']) {
    const out = await collect(decodeBody(readableFrom([PAYLOAD]), ce));
    assert.deepEqual(out, PAYLOAD, String(ce));
  }
});

test('chained codings decode in reverse order of application: gzip, gzip', async () => {
  const once = await compress(PAYLOAD, 'gzip');
  const twice = await compress(once, 'gzip');
  const out = await collect(decodeBody(readableFrom([twice]), 'gzip, gzip'));
  assert.deepEqual(out, PAYLOAD);
});

test('mixed chain: Content-Encoding "gzip, deflate" means deflate was applied last', async () => {
  const gzipped = await compress(PAYLOAD, 'gzip');
  const wire = await compress(gzipped, 'deflate');
  const out = await collect(decodeBody(readableFrom([wire]), 'gzip, deflate'));
  assert.deepEqual(out, PAYLOAD);
});

test('identity inside a chain is a no-op stage', async () => {
  const wire = await compress(PAYLOAD, 'gzip');
  const out = await collect(decodeBody(readableFrom([wire]), 'gzip, identity'));
  assert.deepEqual(out, PAYLOAD);
});

test('coding names are case-insensitive and whitespace-tolerant', async () => {
  const wire = await compress(PAYLOAD, 'gzip');
  const out = await collect(decodeBody(readableFrom([wire]), '  GZip  '));
  assert.deepEqual(out, PAYLOAD);
});

test('br is rejected up front, naming the runtime limitation', async () => {
  const err = await rejectsWithCode(
    () => decodeBody(readableFrom([PAYLOAD]), 'br'),
    'HTTP_CONTENT_ENCODING',
  );
  assert.match(err.message, /DecompressionStream/);
  assert.match(err.message, /never advertises/);
  assert.equal(err.detail.coding, 'br');
});

test('zstd is rejected the same way', async () => {
  await rejectsWithCode(
    () => decodeBody(readableFrom([PAYLOAD]), 'zstd'),
    'HTTP_CONTENT_ENCODING',
  );
});

test('an unknown coding is rejected by name', async () => {
  const err = await rejectsWithCode(
    () => decodeBody(readableFrom([PAYLOAD]), 'lzma'),
    'HTTP_CONTENT_ENCODING',
  );
  assert.match(err.message, /lzma/);
});

test('one bad coding anywhere in the list fails synchronously, before consuming the body', async () => {
  const stream = readableFrom([PAYLOAD]);
  await rejectsWithCode(() => decodeBody(stream, 'gzip, br'), 'HTTP_CONTENT_ENCODING');
  // The body was not touched: it is still fully readable.
  assert.deepEqual(await collect(stream), PAYLOAD);
});

test('a zero-byte body under a Content-Encoding decodes to zero bytes', async () => {
  for (const ce of ['gzip', 'deflate', 'gzip, gzip']) {
    const out = await collect(decodeBody(readableFrom([]), ce));
    assert.equal(out.byteLength, 0, ce);
  }
});

test('corrupt gzip data surfaces as a stream error carrying HTTP_CONTENT_ENCODING', async () => {
  const garbage = utf8('this is definitely not gzip');
  const err = await rejectsWithCode(
    () => collect(decodeBody(readableFrom([garbage]), 'gzip')),
    'HTTP_CONTENT_ENCODING',
  );
  assert.match(err.message, /gzip/);
});

test('truncated gzip data errors rather than yielding a silent partial body', async () => {
  const wire = await compress(PAYLOAD, 'gzip');
  const truncated = wire.subarray(0, wire.byteLength - 8); // drop the CRC32 + ISIZE trailer
  await rejectsWithCode(
    () => collect(decodeBody(readableFrom([truncated]), 'gzip')),
    'HTTP_CONTENT_ENCODING',
  );
});

// ---------------------------------------------------------------- charset selection

test('charsetFromContentType: plain, quoted, extra parameters, case folding', () => {
  assert.equal(charsetFromContentType('text/html; charset=ISO-8859-4'), 'iso-8859-4');
  assert.equal(charsetFromContentType('text/plain; charset="UTF-16BE"'), 'utf-16be');
  assert.equal(
    charsetFromContentType('multipart/form-data; boundary=xyz; charset=utf-8'),
    'utf-8',
  );
  assert.equal(charsetFromContentType('text/html; CHARSET=Big5; foo=bar'), 'big5');
  assert.equal(charsetFromContentType('text/html'), null);
  assert.equal(charsetFromContentType(null), null);
  assert.equal(charsetFromContentType('text/html; charset=""'), null);
});

test('charsetFor: explicit header charset is used when there is no BOM', () => {
  assert.equal(charsetFor('text/plain; charset=shift_jis', utf8('plain text')), 'shift_jis');
  assert.equal(charsetFor('text/plain; charset=shift_jis'), 'shift_jis');
});

test('charsetFor: a BOM beats a conflicting declared charset', () => {
  const utf8Bom = concat([new Uint8Array([0xef, 0xbb, 0xbf]), utf8('hello')]);
  assert.equal(charsetFor('text/plain; charset=iso-8859-1', utf8Bom), 'utf-8');
  assert.equal(charsetFor('text/html; charset=gbk', new Uint8Array([0xfe, 0xff, 0, 0x68])), 'utf-16be');
  assert.equal(charsetFor(null, new Uint8Array([0xff, 0xfe, 0x68, 0])), 'utf-16le');
});

test('charsetFor: <meta charset> is sniffed for text/html without a declared charset', () => {
  const body = utf8('<!doctype html><html><head><meta charset="gbk"></head><body>');
  assert.equal(charsetFor('text/html', body), 'gbk');
  const unquoted = utf8('<html><head><meta charset=big5></head>');
  assert.equal(charsetFor('text/html', unquoted), 'big5');
});

test('charsetFor: the http-equiv meta form is sniffed too', () => {
  const body = utf8(
    '<html><head><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"></head>',
  );
  assert.equal(charsetFor('text/html', body), 'shift_jis');
});

test('charsetFor: meta sniffing is limited to the first 1024 bytes', () => {
  const late = concat([
    utf8('<!doctype html>' + '<!-- padding -->'.repeat(70)), // > 1024 bytes of preamble
    utf8('<meta charset="gbk">'),
  ]);
  assert.ok(late.byteLength > 1024 + 20);
  assert.equal(charsetFor('text/html', late), 'utf-8');
});

test('charsetFor: meta is ignored for non-HTML types and loses to a declared charset', () => {
  const body = utf8('<meta charset="gbk">');
  assert.equal(charsetFor('text/plain', body), 'utf-8');
  assert.equal(charsetFor('text/html; charset=big5', body), 'big5');
});

test('charsetFor: nothing stated defaults to utf-8, matching Response.text()', () => {
  assert.equal(charsetFor(null, utf8('hello')), 'utf-8');
  assert.equal(charsetFor(undefined, undefined), 'utf-8');
  assert.equal(charsetFor('application/octet-stream', new Uint8Array([1, 2, 3])), 'utf-8');
});

// ---------------------------------------------------------------- text decoding

test('decodeText: gbk, shift_jis and big5 decode their canonical byte sequences', () => {
  assert.equal(decodeText(new Uint8Array([0xc4, 0xe3, 0xba, 0xc3]), 'gbk'), '你好');
  assert.equal(
    decodeText(new Uint8Array([0x82, 0xb1, 0x82, 0xf1, 0x82, 0xc9, 0x82, 0xbf, 0x82, 0xcd]),
      'shift_jis'),
    'こんにちは',
  );
  assert.equal(decodeText(new Uint8Array([0xa4, 0xa4, 0xa4, 0xe5]), 'big5'), '中文');
});

test('decodeText: iso-8859-1 maps to windows-1252 per WHATWG — 0x80 is the euro sign', () => {
  // This looks like a bug and is not: every browser decodes "latin-1" as windows-1252, so
  // 0x80-0x9F become punctuation rather than C1 control characters.
  assert.equal(decodeText(new Uint8Array([0x80]), 'iso-8859-1'), '€');
  assert.equal(decodeText(new Uint8Array([0x93, 0x94]), 'latin1'), '“”');
});

test('decodeText: a matching BOM is stripped, like Response.text() does', () => {
  const withBom = concat([new Uint8Array([0xef, 0xbb, 0xbf]), utf8('hi')]);
  assert.equal(decodeText(withBom, 'utf-8'), 'hi');
});

test('decodeText: an unsupported label is HTTP_CHARSET, naming the label', async () => {
  const err = await rejectsWithCode(
    () => decodeText(utf8('x'), 'klingon-8'),
    'HTTP_CHARSET',
  );
  assert.match(err.message, /klingon-8/);
  assert.equal(err.detail.charset, 'klingon-8');
});

test('decodeText defaults to utf-8', () => {
  assert.equal(decodeText(utf8('héllo')), 'héllo');
});

test('end to end: gzip body, meta-declared charset, decoded text', async () => {
  // The full client path: decode the Content-Encoding, sniff the charset, decode the text.
  const html = concat([
    utf8('<html><head><meta charset=gbk></head><body>'),
    new Uint8Array([0xc4, 0xe3, 0xba, 0xc3]),
    utf8('</body></html>'),
  ]);
  const wire = await compress(html, 'gzip');
  const bytes = await collect(decodeBody(readableFrom(fixedChunks(wire, 7)), 'gzip'));
  const charset = charsetFor('text/html', bytes.subarray(0, 1024));
  assert.equal(charset, 'gbk');
  assert.equal(latin1(bytes).includes('<body>'), true);
  assert.match(decodeText(bytes, charset), /你好/);
});
