// bodyFraming: the RFC 9112 §6.3 decision table, every branch, in order.
//
// The assertions always cover BOTH fields. `kind` decides where this response ends;
// `keepAliveEligible` decides whether the socket may carry another request. Getting either
// one wrong attributes bytes to the wrong message — the two worst bugs an HTTP client can have.

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { bodyFraming } from '../../src/http1/response.js';
import { codes } from '../../src/errors.js';
import { rejectsWithCode } from '../_harness.js';

const frame = (status, method, pairs = []) =>
  bodyFraming({ status, method, headers: new Headers(pairs) });

describe('bodyFraming rule 1: messages that never have a body', () => {
  test('HEAD, even with a Content-Length present (it describes the unsent body)', () => {
    assert.deepEqual(frame(200, 'HEAD', [['content-length', '5120']]), {
      kind: 'none',
      keepAliveEligible: true,
    });
  });

  test('204 and 304, even with framing headers present', () => {
    for (const status of [204, 304]) {
      assert.deepEqual(frame(status, 'GET', [['content-length', '7']]), {
        kind: 'none',
        keepAliveEligible: true,
      });
    }
    assert.deepEqual(frame(304, 'GET', [['transfer-encoding', 'chunked']]), {
      kind: 'none',
      keepAliveEligible: true,
    });
  });

  test('1xx never has a body', () => {
    assert.deepEqual(frame(100, 'GET'), { kind: 'none', keepAliveEligible: true });
  });

  test('methods are case-sensitive tokens: "head" is not HEAD', () => {
    assert.deepEqual(frame(200, 'head', [['content-length', '3']]), {
      kind: 'content-length',
      length: 3,
      keepAliveEligible: true,
    });
  });
});

describe('bodyFraming rule 2: CONNECT', () => {
  test('2xx to CONNECT is a tunnel: no body, and the socket is no longer HTTP', () => {
    assert.deepEqual(frame(200, 'CONNECT'), { kind: 'none', keepAliveEligible: false });
  });

  test('a failed CONNECT is a normal response with normal framing', () => {
    assert.deepEqual(frame(407, 'CONNECT', [['content-length', '11']]), {
      kind: 'content-length',
      length: 11,
      keepAliveEligible: true,
    });
  });
});

describe('bodyFraming rule 3: Transfer-Encoding', () => {
  test('final coding chunked', () => {
    assert.deepEqual(frame(200, 'GET', [['transfer-encoding', 'chunked']]), {
      kind: 'chunked',
      keepAliveEligible: true,
    });
  });

  test('coding names are case-insensitive', () => {
    assert.deepEqual(frame(200, 'GET', [['transfer-encoding', 'ChUnKeD']]), {
      kind: 'chunked',
      keepAliveEligible: true,
    });
  });

  test('identity then chunked (folded across duplicate fields) is chunked', () => {
    assert.deepEqual(
      frame(200, 'GET', [
        ['transfer-encoding', 'identity'],
        ['transfer-encoding', 'chunked'],
      ]),
      { kind: 'chunked', keepAliveEligible: true },
    );
  });

  test('TE present but final coding not chunked: until-close and NOT reusable', () => {
    assert.deepEqual(frame(200, 'GET', [['transfer-encoding', 'identity']]), {
      kind: 'until-close',
      keepAliveEligible: false,
    });
    assert.deepEqual(frame(200, 'GET', [['transfer-encoding', 'chunked, identity']]), {
      kind: 'until-close',
      keepAliveEligible: false,
    });
  });

  test('a coding we cannot decode is refused by name, wherever it appears', async () => {
    await rejectsWithCode(
      () => frame(200, 'GET', [['transfer-encoding', 'gzip, chunked']]),
      codes.HTTP_FRAMING_AMBIGUOUS,
      /gzip/,
    );
    await rejectsWithCode(
      () => frame(200, 'GET', [['transfer-encoding', 'chunked, br']]),
      codes.HTTP_FRAMING_AMBIGUOUS,
      /br/,
    );
    await rejectsWithCode(
      () => frame(200, 'GET', [['transfer-encoding', 'compress']]),
      codes.HTTP_FRAMING_AMBIGUOUS,
      /compress/,
    );
  });

  test('a Transfer-Encoding that names no coding at all is ambiguous', async () => {
    await rejectsWithCode(
      () => frame(200, 'GET', [['transfer-encoding', ' , ,']]),
      codes.HTTP_FRAMING_AMBIGUOUS,
    );
  });
});

describe('bodyFraming rule 4: TE + CL conflict (the smuggling case)', () => {
  test('both present is an error; neither wins', async () => {
    await rejectsWithCode(
      () =>
        frame(200, 'GET', [
          ['transfer-encoding', 'chunked'],
          ['content-length', '100'],
        ]),
      codes.HTTP_FRAMING_AMBIGUOUS,
    );
  });

  test('the conflict is fatal even when the TE coding itself is undecodable', async () => {
    await rejectsWithCode(
      () =>
        frame(200, 'GET', [
          ['transfer-encoding', 'gzip'],
          ['content-length', '100'],
        ]),
      codes.HTTP_FRAMING_AMBIGUOUS,
    );
  });
});

describe('bodyFraming rule 5: Content-Length validation', () => {
  test('identical duplicates are tolerated (arrives folded as "5, 5")', () => {
    assert.deepEqual(
      frame(200, 'GET', [
        ['content-length', '5'],
        ['content-length', '5'],
      ]),
      { kind: 'content-length', length: 5, keepAliveEligible: true },
    );
  });

  test('disagreeing duplicates are ambiguous', async () => {
    await rejectsWithCode(
      () =>
        frame(200, 'GET', [
          ['content-length', '5'],
          ['content-length', '6'],
        ]),
      codes.HTTP_FRAMING_AMBIGUOUS,
      /disagree/,
    );
  });

  test('textually different duplicates are rejected even when numerically equal', async () => {
    // "05" vs "5": two parsers can disagree about leading zeros, so we refuse to pick.
    await rejectsWithCode(
      () =>
        frame(200, 'GET', [
          ['content-length', '05'],
          ['content-length', '5'],
        ]),
      codes.HTTP_FRAMING_AMBIGUOUS,
    );
  });

  test('non-digit values are ambiguous, not zero', async () => {
    for (const cl of ['abc', '-1', '+5', '5x', '5 5', '0x10', '']) {
      await rejectsWithCode(
        () => frame(200, 'GET', [['content-length', cl]]),
        codes.HTTP_FRAMING_AMBIGUOUS,
      );
    }
  });

  test('a length that overflows a safe integer is ambiguous', async () => {
    await rejectsWithCode(
      () => frame(200, 'GET', [['content-length', '99999999999999999999']]),
      codes.HTTP_FRAMING_AMBIGUOUS,
      /overflow/,
    );
  });
});

describe('bodyFraming rules 6 and 7: Content-Length, then until-close', () => {
  test('a lone Content-Length frames the body and keeps the socket reusable', () => {
    assert.deepEqual(frame(200, 'GET', [['content-length', '42']]), {
      kind: 'content-length',
      length: 42,
      keepAliveEligible: true,
    });
  });

  test('Content-Length: 0 is a complete, empty, reusable body', () => {
    assert.deepEqual(frame(200, 'GET', [['content-length', '0']]), {
      kind: 'content-length',
      length: 0,
      keepAliveEligible: true,
    });
  });

  test('no framing headers at all: until-close, and the socket is spent', () => {
    assert.deepEqual(frame(200, 'GET'), { kind: 'until-close', keepAliveEligible: false });
    assert.deepEqual(frame(200, undefined), { kind: 'until-close', keepAliveEligible: false });
  });
});
