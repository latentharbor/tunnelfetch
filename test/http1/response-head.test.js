// readResponseHead: status line grammar, header field grammar, Set-Cookie preservation,
// informational (1xx) handling, and head-size limits.
//
// Every parse runs under the full chunking matrix: the same bytes fed whole and one byte at a
// time must produce the same head (or the same error), because the network chooses the chunking
// and the parser does not get to know.

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readResponseHead } from '../../src/http1/response.js';
import { codes } from '../../src/errors.js';
import { ByteReader, concat, latin1, utf8 } from '../../src/util/bytes.js';
import { underAllChunkings, readableFrom, fixedChunks, rejectsWithCode } from '../_harness.js';

/** Map a head to a plain comparable shape. Headers iterates lowercased and sorted, which is
 * deterministic — exactly what a cross-chunking comparison needs. */
function norm(head) {
  return {
    httpVersion: head.httpVersion,
    status: head.status,
    statusText: head.statusText,
    headers: [...head.headers],
    setCookie: head.setCookie,
    informational: head.informational.map((i) => ({
      httpVersion: i.httpVersion,
      status: i.status,
      statusText: i.statusText,
      headers: [...i.headers],
    })),
  };
}

/** Parse under the chunking matrix and also report what the parser left in the reader —
 * the head must consume exactly itself and not one byte more. */
const parse = (opts) => async (readable) => {
  const reader = new ByteReader(readable);
  const head = await readResponseHead(reader, opts);
  const leftover = latin1(await reader.readToEnd());
  return { ...norm(head), leftover };
};

describe('readResponseHead: status line', () => {
  test('HTTP/1.1 with reason phrase', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nBODY'),
      parse(),
    );
    assert.deepEqual(got, {
      httpVersion: '1.1',
      status: 404,
      statusText: 'Not Found',
      headers: [['content-type', 'text/plain']],
      setCookie: [],
      informational: [],
      leftover: 'BODY',
    });
  });

  test('HTTP/1.0 is accepted', async () => {
    const got = await underAllChunkings(utf8('HTTP/1.0 200 OK\r\n\r\n'), parse());
    assert.equal(got.httpVersion, '1.0');
    assert.equal(got.status, 200);
    assert.equal(got.statusText, 'OK');
  });

  test('missing reason phrase, without the trailing space', async () => {
    const got = await underAllChunkings(utf8('HTTP/1.1 200\r\n\r\n'), parse());
    assert.equal(got.status, 200);
    assert.equal(got.statusText, '');
  });

  test('missing reason phrase, with the trailing space present', async () => {
    const got = await underAllChunkings(utf8('HTTP/1.1 200 \r\n\r\n'), parse());
    assert.equal(got.status, 200);
    assert.equal(got.statusText, '');
  });

  test('reason phrase may contain spaces and separators', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 505 HTTP Version Not Supported: sorry\r\n\r\n'),
      parse(),
    );
    assert.equal(got.statusText, 'HTTP Version Not Supported: sorry');
  });

  test('reason phrase keeps obs-text octets via latin1', async () => {
    const bytes = concat([utf8('HTTP/1.1 200 '), new Uint8Array([0x80, 0xff]), utf8('\r\n\r\n')]);
    const got = await underAllChunkings(bytes, parse());
    assert.equal(got.statusText, '\x80\xff');
  });

  test('malformed status lines are rejected', async () => {
    const bad = [
      'HTTP/1.1 99 TooShort', // 2-digit status
      'HTTP/1.1 9999 TooLong', // 4-digit status
      'HTTP/1.1 20a Nope', // non-digit status
      'HTTP/1.1 099 ZeroClass', // grammatical but semantically void
      'HTTP/2 200 OK', // version we do not speak
      'HTTP/1.2 200 OK',
      'http/1.1 200 OK', // HTTP-name is case-sensitive
      'HTTP/1.1  200 OK', // two spaces
      'HTTP/1.1\t200 OK', // tab separator
      'ICY 200 OK', // not HTTP at all
      '<html>garbage</html>',
      '', // empty status line
    ];
    for (const line of bad) {
      await rejectsWithCode(
        () => underAllChunkings(utf8(`${line}\r\n\r\n`), parse()),
        codes.HTTP_STATUS_LINE,
      );
    }
  });

  test('a bare-LF status line is rejected, not tolerated', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('HTTP/1.1 200 OK\nHost: a\r\n\r\n'), parse()),
      codes.HTTP_STATUS_LINE,
      /bare LF/,
    );
  });
});

describe('readResponseHead: header fields', () => {
  test('empty values, with and without a space after the colon', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nX-A:\r\nX-B: \r\n\r\n'),
      parse(),
    );
    assert.deepEqual(got.headers, [
      ['x-a', ''],
      ['x-b', ''],
    ]);
  });

  test('values keep internal colons; only the first colon splits', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nLocation: http://h.test/a:b:c\r\n\r\n'),
      parse(),
    );
    assert.deepEqual(got.headers, [['location', 'http://h.test/a:b:c']]);
  });

  test('OWS around the value is trimmed, including tabs; interior whitespace stays', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nX-T: \t a  b \t \r\n\r\n'),
      parse(),
    );
    assert.deepEqual(got.headers, [['x-t', 'a  b']]);
  });

  test('ordinary duplicates fold with ", " in the Headers view', async () => {
    const got = await underAllChunkings(
      utf8('HTTP/1.1 200 OK\r\nX-Dup: a\r\nX-Dup: b\r\n\r\n'),
      parse(),
    );
    assert.deepEqual(got.headers, [['x-dup', 'a, b']]);
  });

  test('duplicate Set-Cookie values survive separately, commas and all', async () => {
    // The second cookie's Expires contains a comma: folding would make it unparseable,
    // which is exactly why setCookie must be a separate array.
    const got = await underAllChunkings(
      utf8(
        'HTTP/1.1 200 OK\r\n' +
          'Set-Cookie: a=1; Path=/\r\n' +
          'Set-Cookie: b=2; Expires=Wed, 09 Jun 2021 10:18:14 GMT\r\n' +
          '\r\n',
      ),
      parse(),
    );
    assert.deepEqual(got.setCookie, [
      'a=1; Path=/',
      'b=2; Expires=Wed, 09 Jun 2021 10:18:14 GMT',
    ]);
  });

  test('obs-fold (continuation lines) is rejected, space or tab', async () => {
    for (const fold of [' folded\r\n', '\tfolded\r\n']) {
      await rejectsWithCode(
        () => underAllChunkings(utf8(`HTTP/1.1 200 OK\r\nX-A: 1\r\n${fold}\r\n`), parse()),
        codes.HTTP_HEADER,
        /obs-fold/,
      );
    }
  });

  test('names that are not tokens are rejected', async () => {
    const bad = [
      'Bad Name: x', // space in name
      'Name : x', // space before the colon
      ': x', // empty name
      'Foobar', // no colon at all
      'Na\xc3\xafve: x', // non-ASCII bytes in name
    ];
    for (const line of bad) {
      await rejectsWithCode(
        () => underAllChunkings(utf8(`HTTP/1.1 200 OK\r\n${line}\r\n\r\n`), parse()),
        codes.HTTP_HEADER,
      );
    }
  });

  test('control bytes in a value are rejected; obs-text octets are not', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('HTTP/1.1 200 OK\r\nX-A: a\x01b\r\n\r\n'), parse()),
      codes.HTTP_HEADER,
    );
    const bytes = concat([
      utf8('HTTP/1.1 200 OK\r\nX-O: '),
      new Uint8Array([0xe9, 0xff]),
      utf8('\r\n\r\n'),
    ]);
    const got = await underAllChunkings(bytes, parse());
    assert.deepEqual(got.headers, [['x-o', '\xe9\xff']]);
  });

  test('a bare-LF header line is rejected', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('HTTP/1.1 200 OK\r\nX-A: 1\nX-B: 2\r\n\r\n'), parse()),
      codes.HTTP_HEADER,
      /bare LF/,
    );
  });
});

describe('readResponseHead: limits and truncation', () => {
  // Not run under the full matrix: ByteReader's two limit paths (delimiter found over-limit
  // vs delimiter not found yet) produce different messages depending on chunk shape. The CODE
  // is the contract, so assert it under the two extreme chunkings explicitly.
  test('a head over maxHeaderBytes is rejected with LIMIT_HEADER', async () => {
    const bytes = utf8(`HTTP/1.1 200 OK\r\nX-Big: ${'a'.repeat(100)}\r\n\r\n`);
    for (const chunks of [[bytes], fixedChunks(bytes, 1)]) {
      await rejectsWithCode(async () => {
        await readResponseHead(new ByteReader(readableFrom(chunks)), { maxHeaderBytes: 48 });
      }, codes.LIMIT_HEADER);
    }
  });

  test('EOF before the blank line is an unexpected EOF, not a silent head', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('HTTP/1.1 200 OK\r\nX-A: 1\r\n'), parse()),
      'UNEXPECTED_EOF',
    );
  });
});

describe('readResponseHead: informational responses', () => {
  test('1xx heads are skipped, collected, and the real head is returned', async () => {
    const got = await underAllChunkings(
      utf8(
        'HTTP/1.1 100 Continue\r\n\r\n' +
          'HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n' +
          'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nBODY',
      ),
      parse(),
    );
    assert.deepEqual(got, {
      httpVersion: '1.1',
      status: 200,
      statusText: 'OK',
      headers: [['content-type', 'text/html']],
      setCookie: [],
      informational: [
        { httpVersion: '1.1', status: 100, statusText: 'Continue', headers: [] },
        {
          httpVersion: '1.1',
          status: 103,
          statusText: 'Early Hints',
          headers: [['link', '</s.css>; rel=preload']],
        },
      ],
      leftover: 'BODY',
    });
  });

  test('101 Switching Protocols is fatal: no upgrade was ever offered', async () => {
    await rejectsWithCode(
      () =>
        underAllChunkings(
          utf8('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n'),
          parse(),
        ),
      codes.HTTP_UPGRADE_UNEXPECTED,
    );
  });

  test('maxHeaderBytes bounds the whole head phase: a 1xx flood cannot run forever', async () => {
    const flood = utf8('HTTP/1.1 100 Continue\r\n\r\n'.repeat(50) + 'HTTP/1.1 200 OK\r\n\r\n');
    for (const chunks of [[flood], fixedChunks(flood, 7)]) {
      await rejectsWithCode(async () => {
        await readResponseHead(new ByteReader(readableFrom(chunks)), { maxHeaderBytes: 256 });
      }, codes.LIMIT_HEADER);
    }
  });

  test('EOF after a 1xx head, before the real one, is an unexpected EOF', async () => {
    await rejectsWithCode(
      () => underAllChunkings(utf8('HTTP/1.1 100 Continue\r\n\r\n'), parse()),
      'UNEXPECTED_EOF',
    );
  });
});
