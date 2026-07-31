// readResponseBody: end-to-end head -> framing -> body, with the completion contract.
//
// The assertions that matter most here are about what the body reader does NOT consume:
// bytes past a Content-Length, and bytes after a chunked terminator, must stay in the reader.
// Consuming them corrupts pipelined/keep-alive connections — the next response's head would
// be missing its first bytes, and its payload would be answered to the wrong request.

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readResponseHead, bodyFraming, readResponseBody } from '../../src/http1/response.js';
import { codes } from '../../src/errors.js';
import { ByteReader, latin1, utf8 } from '../../src/util/bytes.js';
import {
  underAllChunkings,
  readableFrom,
  fixedChunks,
  rejectsWithCode,
  collect,
} from '../_harness.js';

/** Full pipeline under the chunking matrix: parse head, decide framing, stream body.
 * Reports the payload, the completion outcome, and what stayed unconsumed in the reader. */
const roundTrip = (method, opts) => async (readable) => {
  const reader = new ByteReader(readable);
  const head = await readResponseHead(reader);
  const framing = bodyFraming({ status: head.status, method, headers: head.headers });
  const body = readResponseBody(reader, framing, opts);
  const payload = await collect(body).then(
    (b) => ({ ok: latin1(b) }),
    (e) => ({ code: e.code }),
  );
  const completed = await body.completed.then(
    (v) => ({ v }),
    (e) => ({ code: e.code }),
  );
  const trailers = await body.trailers.then(
    (t) => (t === null ? null : [...t]),
    (e) => ({ code: e.code }),
  );
  const leftover = latin1(await reader.readToEnd());
  const { kind, keepAliveEligible: keepAlive } = framing;
  return { kind, keepAlive, payload, completed, trailers, leftover };
};

describe('readResponseBody: content-length', () => {
  test('reads exactly the declared bytes and completes', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello'),
      roundTrip('GET'),
    );
    assert.deepEqual(got, {
      kind: 'content-length',
      keepAlive: true,
      payload: { ok: 'hello' },
      completed: { v: true },
      trailers: null,
      leftover: '',
    });
  });

  test('bytes beyond the declared length are NOT consumed (pipelining survives)', async () => {
    // "EXTRA" stands in for the next response on a keep-alive connection. If any chunking
    // shape steals even one of its bytes, the connection is desynchronised.
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA'),
      roundTrip('GET'),
    );
    assert.deepEqual(got.payload, { ok: 'hello' });
    assert.deepEqual(got.completed, { v: true });
    assert.equal(got.leftover, 'EXTRA');
  });

  test('a short body is truncation, never a silent success', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel'),
      roundTrip('GET'),
    );
    assert.deepEqual(got.payload, { code: codes.HTTP_BODY_TRUNCATED });
    assert.deepEqual(got.completed, { code: codes.HTTP_BODY_TRUNCATED });
  });

  test('Content-Length: 0 completes without a single read', async () => {
    const reader = new ByteReader(readableFrom([utf8('NEXT')]));
    const body = readResponseBody(reader, {
      kind: 'content-length',
      length: 0,
      keepAliveEligible: true,
    });
    // Settled at creation: the pool must not have to drain an empty stream to learn this.
    assert.equal(await body.completed, true);
    assert.equal(latin1(await collect(body)), '');
    assert.equal(latin1(await reader.readToEnd()), 'NEXT');
  });

  test('a declared length over maxBytes is rejected before reading any of it', async () => {
    const bytes = utf8('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n');
    await rejectsWithCode(async () => {
      const reader = new ByteReader(readableFrom([bytes]));
      const head = await readResponseHead(reader);
      const framing = bodyFraming({ status: head.status, method: 'GET', headers: head.headers });
      readResponseBody(reader, framing, { maxBytes: 100 });
    }, codes.LIMIT_BODY);
  });

  test('cancelling mid-body resolves completed to false (socket position unknown)', async () => {
    const reader = new ByteReader(readableFrom([utf8('abcdefghij')]));
    const body = readResponseBody(reader, {
      kind: 'content-length',
      length: 10,
      keepAliveEligible: true,
    });
    await body.cancel();
    assert.equal(await body.completed, false);
  });
});

describe('readResponseBody: none', () => {
  test('HEAD with Content-Length: the reader is left completely untouched', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\n'),
      roundTrip('HEAD'),
    );
    assert.deepEqual(got, {
      kind: 'none',
      keepAlive: true,
      payload: { ok: '' },
      completed: { v: true },
      trailers: null,
      // The "body" bytes here are really the next response; not one byte may be consumed.
      leftover: 'HTTP/1.1 404 Not Found\r\n\r\n',
    });
  });

  test('204 with a stray Content-Length behaves the same', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 204 No Content\r\nContent-Length: 7\r\n\r\nNEXT'),
      roundTrip('GET'),
    );
    assert.deepEqual(got.kind, 'none');
    assert.deepEqual(got.payload, { ok: '' });
    assert.equal(got.leftover, 'NEXT');
  });
});

describe('readResponseBody: until-close', () => {
  test('reads to EOF and completes, but the framing is not reusable', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.0 200 OK\r\nX-A: 1\r\n\r\neverything until close'),
      roundTrip('GET'),
    );
    assert.deepEqual(got, {
      kind: 'until-close',
      keepAlive: false,
      payload: { ok: 'everything until close' },
      completed: { v: true },
      trailers: null,
      leftover: '',
    });
  });

  test('an empty until-close body is legal', async () => {
    const got = await underAllChunkings(utf8('HTTP/1.1 200 OK\r\n\r\n'), roundTrip('GET'));
    assert.deepEqual(got.payload, { ok: '' });
    assert.deepEqual(got.completed, { v: true });
  });

  test('maxBytes bounds a body with no declared end', async () => {
    const bytes = utf8('HTTP/1.1 200 OK\r\n\r\n' + 'x'.repeat(64));
    for (const chunks of [[bytes], fixedChunks(bytes, 1)]) {
      await rejectsWithCode(async () => {
        const reader = new ByteReader(readableFrom(chunks));
        const head = await readResponseHead(reader);
        const framing = bodyFraming({ status: head.status, method: 'GET', headers: head.headers });
        await collect(readResponseBody(reader, framing, { maxBytes: 32 }));
      }, codes.LIMIT_BODY);
    }
  });
});

describe('readResponseBody: chunked', () => {
  test('full pipeline: chunked body, trailers, and untouched next-message bytes', async () => {
    const got = await underAllChunkings(
      utf8(
        'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' +
          '5\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: ok\r\n\r\n' +
          'NEXT',
      ),
      roundTrip('GET'),
    );
    assert.deepEqual(got, {
      kind: 'chunked',
      keepAlive: true,
      payload: { ok: 'hello world' },
      completed: { v: true },
      trailers: [['x-sum', 'ok']],
      leftover: 'NEXT',
    });
  });

  test('a truncated chunked body rejects completion', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel'),
      roundTrip('GET'),
    );
    assert.deepEqual(got.payload, { code: codes.HTTP_BODY_TRUNCATED });
    assert.deepEqual(got.completed, { code: codes.HTTP_BODY_TRUNCATED });
    assert.deepEqual(got.trailers, { code: codes.HTTP_BODY_TRUNCATED });
  });
});
