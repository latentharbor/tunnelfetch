// Content-Encoding and charset. The deflate tests are the point of the file: RFC 9110 says
// zlib-wrapped, half the internet sends raw, and both shapes must decode.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeBody,
  acceptEncodingFor,
  ACCEPT_ENCODING,
  charsetFor,
  charsetFromContentType,
  decodeText,
} from '../../src/client/decode.js';
import { utf8, latin1, concat } from '../../src/util/bytes.js';
import {
  readableFrom, readableThatErrors, collect, rejectsWithCode, fixedChunks,
} from '../_harness.js';

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
  assert.match(err.message, /does not advertise/);
  // The refusal must name the way out, or it reads as "impossible" rather than "not built in".
  assert.match(err.message, /decoders/);
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

// ---------------------------------------------------------------- the BYOB drain path
//
// On the target runtime DecompressionStream's readable is a byte stream, and the decode stage
// drains it with a BYOB reader (one large view per read) instead of a default reader (one
// 4 KiB chunk per read) — measured at ~35 ms/MB against ~5 ms/MB on the edge. Node's
// DecompressionStream readable is NOT byte-oriented, so the fallback path is what every other
// test in this file exercises. These tests force the BYOB branch by wrapping the real
// decompressor's readable in a `type: 'bytes'` stream, which Node's BYOB reader does accept.

/** Re-expose `readable` as a byte stream so getReader({mode:'byob'}) works on it. */
function byteStreamOver(readable, flags = {}) {
  const r = readable.getReader();
  let leftover = null;
  return new ReadableStream({
    type: 'bytes',
    async pull(c) {
      let chunk = leftover;
      leftover = null;
      if (!chunk) {
        const { value, done } = await r.read();
        if (done) {
          c.close();
          c.byobRequest?.respond(0);
          return;
        }
        chunk = value;
      }
      const req = c.byobRequest;
      if (req) {
        flags.sawByobRequest = true;
        const view = req.view;
        const n = Math.min(view.byteLength, chunk.byteLength);
        new Uint8Array(view.buffer, view.byteOffset, n).set(chunk.subarray(0, n));
        if (n < chunk.byteLength) leftover = chunk.subarray(n);
        req.respond(n);
      } else {
        c.enqueue(chunk);
      }
    },
    cancel(reason) {
      return r.cancel(reason);
    },
  });
}

/** Run `fn` with DecompressionStream swapped for one whose readable is a byte stream. */
async function withByobDecompressionStream(flags, fn) {
  const Real = globalThis.DecompressionStream;
  globalThis.DecompressionStream = class {
    constructor(format) {
      const real = new Real(format);
      this.writable = real.writable;
      this.readable = byteStreamOver(real.readable, flags);
    }
  };
  try {
    return await fn();
  } finally {
    globalThis.DecompressionStream = Real;
  }
}

test('the BYOB drain is taken when the decompressor exposes a byte stream, and round-trips', async () => {
  const flags = {};
  const wire = await compress(PAYLOAD, 'gzip');
  const out = await withByobDecompressionStream(flags, () =>
    collect(decodeBody(readableFrom(fixedChunks(wire, 7)), 'gzip')),
  );
  assert.deepEqual(out, PAYLOAD);
  assert.equal(flags.sawByobRequest, true, 'the byte-stream source saw BYOB reads, so the ' +
    'BYOB branch (not the default-reader fallback) is what this test exercised');
});

test('the BYOB drain survives byte-by-byte input and both deflate shapes', async () => {
  for (const format of ['gzip', 'deflate', 'deflate-raw']) {
    const flags = {};
    const wire = await compress(PAYLOAD, format);
    const declared = format === 'gzip' ? 'gzip' : 'deflate';
    const out = await withByobDecompressionStream(flags, () =>
      collect(decodeBody(readableFrom(fixedChunks(wire, 1)), declared)),
    );
    assert.deepEqual(out, PAYLOAD, format);
    assert.equal(flags.sawByobRequest, true, format);
  }
});

test('corrupt data on the BYOB path still surfaces HTTP_CONTENT_ENCODING', async () => {
  const flags = {};
  const err = await withByobDecompressionStream(flags, () =>
    rejectsWithCode(
      () => collect(decodeBody(readableFrom([utf8('not gzip at all')]), 'gzip')),
      'HTTP_CONTENT_ENCODING',
    ));
  assert.match(err.message, /gzip/);
});

test('a source error mid-body is wrapped as HTTP_CONTENT_ENCODING naming the coding', async () => {
  // The raw body erroring under the decoder (a torn connection, an idle timeout) must surface
  // on the decoded stream as the decode stage's own typed error, as it always has.
  const wire = await compress(PAYLOAD, 'gzip');
  const err = await rejectsWithCode(
    () => collect(decodeBody(
      readableThatErrors([wire.subarray(0, 40)], new Error('boom mid-body')), 'gzip')),
    'HTTP_CONTENT_ENCODING',
  );
  assert.match(err.message, /decoding "gzip" failed/);
  assert.match(err.message, /boom mid-body/);
});

test('cancelling the decoded stream cancels the raw source (pool-discard prerequisite)', async () => {
  // A consumer that abandons a compressed body must tear the connection down: the pool only
  // ever reuses a connection whose body was consumed to its framed end, and the cancel
  // reaching the raw stream is what lets the client observe the abandonment.
  const wire = await compress(PAYLOAD, 'gzip');
  let cancelledWith = null;
  let fed = false;
  const source = new ReadableStream({
    pull(c) {
      if (!fed) {
        fed = true;
        c.enqueue(wire.subarray(0, 64)); // enough for the sniff and a real decompressor
        return;
      }
      return new Promise(() => {}); // then stall forever, like a quiet socket
    },
    cancel(reason) {
      cancelledWith = reason;
    },
  });
  const decoded = decodeBody(source, 'gzip');
  const reader = decoded.getReader();
  await reader.cancel('caller lost interest');
  assert.equal(cancelledWith, 'caller lost interest');
});

test('zero-length chunks from a decompressor are skipped, not delivered', async () => {
  // No real decompressor emits them, but the drain loop must not surface one as data or stall.
  const Real = globalThis.DecompressionStream;
  globalThis.DecompressionStream = class {
    constructor(format) {
      const real = new Real(format);
      this.writable = real.writable;
      const r = real.readable.getReader();
      let sentEmpty = false;
      this.readable = new ReadableStream({
        async pull(c) {
          if (!sentEmpty) {
            sentEmpty = true;
            c.enqueue(new Uint8Array(0));
            return;
          }
          const { value, done } = await r.read();
          if (done) c.close();
          else c.enqueue(value);
        },
        cancel(reason) {
          return r.cancel(reason);
        },
      });
    }
  };
  try {
    const wire = await compress(PAYLOAD, 'gzip');
    const out = await collect(decodeBody(readableFrom([wire]), 'gzip'));
    assert.deepEqual(out, PAYLOAD);
  } finally {
    globalThis.DecompressionStream = Real;
  }
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

// ---------------------------------------------------------------- caller-supplied decoders
//
// `br` and `zstd` are not built in: the runtime's DecompressionStream has neither, and adding a
// WASM decoder would cost this package its zero dependencies AND its ability to be imported
// without a bundler (a `.wasm` import is not portable ESM). So the coding is pluggable instead —
// the caller brings the decoder, and its cost and its supply chain are visible as theirs.
//
// The invariant these tests protect: what is advertised and what can be decoded never drift
// apart. Advertising a coding we cannot read turns every such response into garbage.

/** A stand-in decoder: uppercases, so "it ran" is visible in the output. */
const upperDecoder = (stream) =>
  stream.pipeThrough(
    new TransformStream({
      transform(chunk, c) {
        c.enqueue(utf8(latin1(chunk).toUpperCase()));
      },
    }),
  );

test('a registered decoder is advertised in Accept-Encoding, in registration order', () => {
  assert.equal(acceptEncodingFor(null), 'gzip, deflate');
  assert.equal(acceptEncodingFor({}), 'gzip, deflate');
  assert.equal(acceptEncodingFor({ br: upperDecoder }), 'gzip, deflate, br');
  // The order a browser sends, which is the reason to register these at all.
  assert.equal(
    acceptEncodingFor({ br: upperDecoder, zstd: upperDecoder }),
    'gzip, deflate, br, zstd',
  );
  // Registering a built-in is refused outright rather than quietly ignored — see the dedicated
  // test below for why the two entry points have to agree about that.
});

test('a coding name that is not an HTTP token is refused, so it cannot inject a header', () => {
  for (const bad of ['br\r\nX-Evil: 1', 'br, zstd', 'br;q=1', 'b r', '']) {
    assert.throws(
      () => acceptEncodingFor({ [bad]: upperDecoder }),
      (e) => e.code === 'HTTP_CONTENT_ENCODING',
      `"${bad}" was accepted as a coding name`,
    );
  }
});

test('a registered decoder is not a function is refused at registration', () => {
  assert.throws(
    () => acceptEncodingFor({ br: 'not a function' }),
    (e) => e.code === 'HTTP_CONTENT_ENCODING',
  );
});

test('a registered decoder decodes the body it was registered for', async () => {
  const out = decodeBody(readableFrom([utf8('hello')]), 'br', {
    br: upperDecoder,
  });
  assert.equal(latin1(await collect(out)), 'HELLO');
});

test('decoder lookup is case-insensitive, as Content-Encoding is', async () => {
  const out = decodeBody(readableFrom([utf8('hi')]), 'BR', { br: upperDecoder });
  assert.equal(latin1(await collect(out)), 'HI');
});

test('a decoder composes with the built-ins in the order the server applied them', async () => {
  // `Content-Encoding: br, gzip` means br first, then gzip — so undo gzip, then undo br.
  const gzipped = await compress(utf8('layered'), 'gzip');
  const out = decodeBody(readableFrom([gzipped]), 'br, gzip', { br: upperDecoder });
  assert.equal(latin1(await collect(out)), 'LAYERED');
});

test('a decoder that returns something other than a stream is named, not left to fail deep', () => {
  assert.throws(
    () => decodeBody(readableFrom([PAYLOAD]), 'br', { br: () => null }),
    (e) => e.code === 'HTTP_CONTENT_ENCODING' && /did not return a ReadableStream/.test(e.message),
  );
});

test('a decoder that throws fails the body closed rather than truncating it', async () => {
  const out = decodeBody(readableFrom([PAYLOAD]), 'br', {
    br: (s) =>
      s.pipeThrough(
        new TransformStream({
          transform() {
            throw new Error('corrupt brotli stream');
          },
        }),
      ),
  });
  await assert.rejects(() => collect(out), /corrupt brotli stream/);
});

test('an unregistered coding is still refused, so the pluggability cannot fail open', async () => {
  await rejectsWithCode(
    () => decodeBody(readableFrom([PAYLOAD]), 'zstd', { br: upperDecoder }),
    'HTTP_CONTENT_ENCODING',
  );
});

test('a built-in coding cannot be replaced by a caller-supplied decoder', () => {
  // Found while measuring: a caller passing `{ gzip: fn }` had their function silently replace the
  // runtime's native gzip, which is ~3x faster than the fastest JavaScript inflate — a quiet
  // downgrade of exactly the kind this package refuses everywhere else. Worse, the two entry
  // points disagreed: acceptEncodingFor treated gzip as already covered and left the header alone,
  // while decodeBody used the override. Both now refuse.
  for (const coding of ['gzip', 'x-gzip', 'deflate', 'identity', 'GZIP']) {
    assert.throws(
      () => acceptEncodingFor({ [coding]: upperDecoder }),
      (e) => e.code === 'HTTP_CONTENT_ENCODING' && /natively and cannot be replaced/.test(e.message),
      `${coding} was accepted as an overridable coding`,
    );
  }
});

test('a gzip body still takes the native path even if a decoder was smuggled past registration', async () => {
  // decodeBody is exported and reachable on its own, so the rule has to hold where the decoding
  // happens and not only where registration is validated.
  const packed = await compress(utf8('native please'), 'gzip');
  const out = decodeBody(readableFrom([packed]), 'gzip', { gzip: upperDecoder });
  assert.equal(latin1(await collect(out)), 'native please');
});
