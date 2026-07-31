// Request-head serialisation grammar, ported from the RFC 9110/9112 field-value rules and the
// header-validation cases in httpx's tests/models/test_headers.py + tests/test_utils.py.
//
// The serialiser's contract is that anything it will not accept on receipt it must not emit on
// send: a client that refuses a control byte in a RESPONSE header but writes the same byte into a
// REQUEST header has a one-sided grammar, and the laxer side is the exploitable one. These tests
// pin both directions to the SAME field-value alphabet (HTAB / SP..~ / obs-text 0x80-0xFF).

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { serializeRequestHead } from '../../src/http1/request.js';
import { latin1 } from '../../src/util/bytes.js';
import { rejectsWithCode } from '../_harness.js';

const line = (bytes, name) =>
  latin1(bytes)
    .split('\r\n')
    .find((l) => l.toLowerCase().startsWith(name.toLowerCase() + ':'));

describe('serializeRequestHead: field-value grammar', () => {
  test('obs-text octets (0x80-0xFF) are legal field content and survive verbatim', () => {
    const bytes = serializeRequestHead({ method: 'GET', target: '/', headers: [['x-o', '\xe9\xff']] });
    assert.equal(line(bytes, 'x-o'), 'x-o: \xe9\xff');
  });

  test('interior HTAB is legal field content and is preserved', () => {
    const bytes = serializeRequestHead({ method: 'GET', target: '/', headers: [['x-t', 'a\tb']] });
    assert.equal(line(bytes, 'x-t'), 'x-t: a\tb');
  });

  test('CR, LF or NUL in a value is header injection and is rejected, never trimmed', async () => {
    for (const v of ['a\r\nEvil: 1', 'a\rb', 'a\nb', 'a\0b', 'trailing\r\n']) {
      await rejectsWithCode(
        () => serializeRequestHead({ method: 'GET', target: '/', headers: [['x-a', v]] }),
        'HTTP_HEADER',
      );
    }
  });

  // BUG (found by this port, fixed): the serialiser used to reject only CR/LF/NUL, so every other
  // control byte the field-value grammar forbids — SOH, BEL, backspace, VT, FF, ESC, DEL — was
  // written straight onto the wire, even though readResponseHead's FIELD_VALUE_RE refuses them on
  // receipt. The serialiser now enforces the same alphabet it parses.
  test('other control bytes (0x01-0x08, VT, FF, 0x0E-0x1F, DEL) are refused, matching the parser', async () => {
    for (const code of [0x01, 0x07, 0x08, 0x0b, 0x0c, 0x1b, 0x1f, 0x7f]) {
      const v = 'a' + String.fromCharCode(code) + 'b';
      await rejectsWithCode(
        () => serializeRequestHead({ method: 'GET', target: '/', headers: [['x-a', v]] }),
        'HTTP_HEADER',
        /control byte/,
      );
    }
  });

  test('a value that is only OWS serialises to an empty field-value after trimming', () => {
    const bytes = serializeRequestHead({ method: 'GET', target: '/', headers: [['x-a', '  \t ']] });
    // The serialiser always writes "name: " (an empty field-value is legal per RFC 9110).
    assert.equal(line(bytes, 'x-a'), 'x-a: ');
    assert.match(latin1(bytes), /\r\nx-a: \r\n/);
  });
});

describe('serializeRequestHead: name and method grammar (httpx test_headers)', () => {
  test('header names must be RFC 9110 tokens; space, colon, non-ASCII rejected', async () => {
    for (const name of ['Bad Name', 'X:Y', 'X\tY', 'na\xefve', '', 'X\r']) {
      await rejectsWithCode(
        () => serializeRequestHead({ method: 'GET', target: '/', headers: [[name, 'v']] }),
        'HTTP_HEADER',
      );
    }
  });

  test('methods are tokens sent verbatim, with no case folding', () => {
    const bytes = serializeRequestHead({ method: 'PATCH', target: '/', headers: [] });
    assert.match(latin1(bytes), /^PATCH \/ HTTP\/1\.1\r\n/);
    // A lowercase custom method is a valid token and must not be up-cased.
    const lower = serializeRequestHead({ method: 'weird', target: '/', headers: [] });
    assert.match(latin1(lower), /^weird \/ HTTP\/1\.1\r\n/);
  });

  test('a non-token method is rejected', async () => {
    for (const m of ['GET POST', 'GE T', 'GÉT', 'G\r\nET']) {
      await rejectsWithCode(
        () => serializeRequestHead({ method: m, target: '/', headers: [] }),
        'HTTP_REQUEST_LINE',
      );
    }
  });
});
