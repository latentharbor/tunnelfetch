// serializeRequestHead: byte-for-byte vectors and the request-splitting defences.
//
// The serialiser is a pure function, so every success case is asserted against exact bytes:
// a request head that is "close enough" is how injected headers slip through code review.

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeRequestHead } from '../../src/http1/request.js';
import { codes } from '../../src/errors.js';
import { latin1 } from '../../src/util/bytes.js';
import { rejectsWithCode } from '../_harness.js';

const asString = (args) => latin1(serializeRequestHead(args));

describe('serializeRequestHead: exact bytes', () => {
  test('origin-form request with ordered headers', () => {
    const bytes = serializeRequestHead({
      method: 'GET',
      target: '/path?q=1',
      headers: [
        ['Host', 'example.test'],
        ['Accept', '*/*'],
        ['X-Empty', ''],
      ],
    });
    assert.ok(bytes instanceof Uint8Array);
    assert.equal(
      latin1(bytes),
      'GET /path?q=1 HTTP/1.1\r\n' +
        'Host: example.test\r\n' +
        'Accept: */*\r\n' +
        'X-Empty: \r\n' +
        '\r\n',
    );
  });

  test('absolute-form target, as sent to a forward proxy for plain http', () => {
    assert.equal(
      asString({
        method: 'GET',
        target: 'http://origin.test/p?x=1',
        headers: [['Host', 'origin.test']],
      }),
      'GET http://origin.test/p?x=1 HTTP/1.1\r\nHost: origin.test\r\n\r\n',
    );
  });

  test('asterisk-form and authority-form targets pass the character rules', () => {
    assert.equal(
      asString({ method: 'OPTIONS', target: '*', headers: [] }),
      'OPTIONS * HTTP/1.1\r\n\r\n',
    );
    assert.equal(
      asString({ method: 'CONNECT', target: 'origin.test:443', headers: [] }),
      'CONNECT origin.test:443 HTTP/1.1\r\n\r\n',
    );
  });

  test('HTTP/1.0 version is serialised when asked', () => {
    assert.equal(
      asString({ method: 'GET', target: '/', headers: [], httpVersion: '1.0' }),
      'GET / HTTP/1.0\r\n\r\n',
    );
  });

  test('no headers at all yields just the request line and blank line', () => {
    assert.equal(asString({ method: 'DELETE', target: '/x' }), 'DELETE /x HTTP/1.1\r\n\r\n');
  });

  test('caller order and duplicates are preserved, never sorted or merged', () => {
    assert.equal(
      asString({
        method: 'GET',
        target: '/',
        headers: [
          ['B-Second', '1'],
          ['A-First', '2'],
          ['B-Second', '3'],
        ],
      }),
      'GET / HTTP/1.1\r\nB-Second: 1\r\nA-First: 2\r\nB-Second: 3\r\n\r\n',
    );
  });

  test('a Headers instance is accepted (its own iteration order: lowercased, sorted)', () => {
    const h = new Headers([
      ['X-B', '2'],
      ['X-A', '1'],
    ]);
    assert.equal(
      asString({ method: 'GET', target: '/', headers: h }),
      'GET / HTTP/1.1\r\nx-a: 1\r\nx-b: 2\r\n\r\n',
    );
  });

  test('value OWS is trimmed; interior whitespace survives', () => {
    assert.equal(
      asString({ method: 'GET', target: '/', headers: [['X-T', ' \t a b \t ']] }),
      'GET / HTTP/1.1\r\nX-T: a b\r\n\r\n',
    );
  });

  test('values keep opaque high octets (latin1, not UTF-8)', () => {
    const bytes = serializeRequestHead({
      method: 'GET',
      target: '/',
      headers: [['X-O', '\xe9\xff']],
    });
    // One byte per char code: 0xE9 0xFF on the wire, not a UTF-8 expansion.
    assert.equal(latin1(bytes), 'GET / HTTP/1.1\r\nX-O: \xe9\xff\r\n\r\n');
    assert.equal(bytes.byteLength, 'GET / HTTP/1.1\r\nX-O: \xe9\xff\r\n\r\n'.length);
  });
});

describe('serializeRequestHead: header injection is rejected', () => {
  const inject = (headers) => () => serializeRequestHead({ method: 'GET', target: '/', headers });

  test('CRLF in a value (the classic request-splitting probe)', async () => {
    await rejectsWithCode(inject([['a', 'a\r\nX-Injected: 1']]), codes.HTTP_HEADER, /injection/);
  });

  test('lone CR, lone LF, and NUL in a value', async () => {
    await rejectsWithCode(inject([['a', 'x\ry']]), codes.HTTP_HEADER);
    await rejectsWithCode(inject([['a', 'x\ny']]), codes.HTTP_HEADER);
    await rejectsWithCode(inject([['a', 'x\0y']]), codes.HTTP_HEADER);
  });

  test('CRLF smuggled through a header name', async () => {
    await rejectsWithCode(inject([['a\r\nX-Injected: 1', 'v']]), codes.HTTP_HEADER);
  });

  test('names that are not RFC 9110 tokens', async () => {
    for (const name of ['', 'a b', 'a:b', 'a(b)', 'naïve', 'a\tb', '"a"']) {
      await rejectsWithCode(inject([[name, 'v']]), codes.HTTP_HEADER, /token/);
    }
  });

  test('values that cannot be represented as octets', async () => {
    await rejectsWithCode(inject([['a', '€']]), codes.HTTP_HEADER, /octet/);
  });

  test('headers that are not iterable', async () => {
    await rejectsWithCode(
      () => serializeRequestHead({ method: 'GET', target: '/', headers: { a: '1' } }),
      codes.HTTP_HEADER,
    );
  });
});

describe('serializeRequestHead: request line validation', () => {
  test('methods that are not tokens', async () => {
    for (const method of ['', 'GE T', 'GET\r\nX: 1', 'GÉT', 'GET ', undefined]) {
      await rejectsWithCode(
        () => serializeRequestHead({ method, target: '/' }),
        codes.HTTP_REQUEST_LINE,
        /token/,
      );
    }
  });

  test('targets with whitespace or control bytes split the request line', async () => {
    const bad = ['', '/a b', '/a\rb', '/a\nb', '/a\tb', '/a\x01b', '/a\x7fb', ' /', undefined];
    for (const target of bad) {
      await rejectsWithCode(
        () => serializeRequestHead({ method: 'GET', target }),
        codes.HTTP_REQUEST_LINE,
      );
    }
  });

  test('non-ASCII targets must arrive pre-encoded', async () => {
    await rejectsWithCode(
      () => serializeRequestHead({ method: 'GET', target: '/caf\xe9' }),
      codes.HTTP_REQUEST_LINE,
    );
  });

  test('unsupported HTTP versions', async () => {
    for (const httpVersion of ['2', '1.2', '1', '']) {
      await rejectsWithCode(
        () => serializeRequestHead({ method: 'GET', target: '/', httpVersion }),
        codes.HTTP_REQUEST_LINE,
      );
    }
  });
});
