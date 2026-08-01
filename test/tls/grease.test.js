// GREASE (RFC 8701) and Chromium's extension shuffling.
//
// Every assertion here about "what Chromium does" comes from two ClientHellos captured off the wire
// from this machine's Chromium, not from recollection. That capture settled one thing that would
// otherwise have been built wrong: **Chromium shuffles its extension order on every connection.**
// The two hellos carried an identical non-GREASE extension set and entirely different orders, with
// a GREASE extension first and last both times and a different GREASE value each time:
//
//   #1: 51914 27 10 35 16 13 5 43 23 51 65281 18 65037 17613 45 11 35466
//   #2: 23130 13 51 27 18 5 11 35 43 45 23 65037 10 65281 16 17613  6682
//
// So "match Chrome's extension order" is not a fixed list to copy. It is a shuffle.
//
// curl does NOT GREASE, which is why the default is off: turning it on by default would make this
// package look LESS like its stated reference, not more.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildClientHello,
  negotiateCipher,
  SHUFFLE_EXTENSIONS,
  CURL_EXTENSION_ORDER,
} from '../../src/tls/handshake-messages.js';
import { GREASE_VALUES, isGrease } from '../../src/tls/grease.js';
import { EXTENSION, TLS13, TLS12 } from '../../src/tls/constants.js';

/** Local, matching the sibling TLS suites: the harness has no shared version. */
const throwsCode = (fn, code) => {
  try {
    fn();
  } catch (e) {
    assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`);
    return e;
  }
  assert.fail(`expected ${code}, nothing was thrown`);
};

const hello = (extra = {}) =>
  buildClientHello({
    hostname: 'example.com',
    keyShares: [{ group: 0x001d, keyExchange: new Uint8Array(32).fill(7) }],
    random: new Uint8Array(32).fill(1),
    legacySessionId: new Uint8Array(32).fill(2),
    alpn: ['h2', 'http/1.1'],
    versions: [TLS13, TLS12],
    ...extra,
  }).message;

/** Walk a ClientHello to its parts. */
function parse(message) {
  const b = message;
  let p = 4 + 2 + 32;
  p += 1 + b[p];
  const csLen = (b[p] << 8) | b[p + 1];
  p += 2;
  const ciphers = [];
  for (let i = 0; i < csLen; i += 2) ciphers.push((b[p + i] << 8) | b[p + i + 1]);
  p += csLen;
  p += 1 + b[p];
  const total = (b[p] << 8) | b[p + 1];
  p += 2;
  const end = p + total;
  const exts = [];
  while (p < end) {
    const type = (b[p] << 8) | b[p + 1];
    const len = (b[p + 2] << 8) | b[p + 3];
    exts.push({ type, body: b.subarray(p + 4, p + 4 + len) });
    p += 4 + len;
  }
  return { ciphers, exts, types: exts.map((e) => e.type) };
}
const bodyOf = (message, type) => parse(message).exts.find((e) => e.type === type)?.body;

test('the sixteen reserved values are recognised, and real codepoints are not', () => {
  assert.equal(GREASE_VALUES.length, 16);
  assert.ok(GREASE_VALUES.every(isGrease));
  // The four values actually observed coming out of Chromium.
  assert.ok([0xcaca, 0x8a8a, 0x5a5a, 0x1a1a].every(isGrease));
  // Near misses that are real assignments or simply not GREASE.
  assert.ok(![0x1301, 0xc02b, 0x0a0b, 0x1a1b, 0x0a1a].some(isGrease));
});

test('GREASE is off by default, because curl does not send it', () => {
  const { ciphers, types } = parse(hello());
  assert.ok(!ciphers.some(isGrease), 'a GREASE cipher appeared without being asked for');
  assert.ok(!types.some(isGrease), 'a GREASE extension appeared without being asked for');
});

test('enabled, GREASE lands where Chromium puts it and nowhere else', () => {
  const message = hello({ grease: 7 });
  const { ciphers, types } = parse(message);

  assert.ok(isGrease(ciphers[0]), 'cipher list does not start with GREASE');
  assert.equal(ciphers.slice(1).filter(isGrease).length, 0, 'more than one GREASE cipher');

  assert.ok(isGrease(types[0]) && isGrease(types.at(-1)), 'extensions are not bracketed by GREASE');
  assert.equal(types.filter(isGrease).length, 2);

  // supported_groups and supported_versions each lead with one; key_share leads with a one-byte
  // entry. ALPN and signature_algorithms carry none — Chromium does not GREASE either.
  const groups = bodyOf(message, EXTENSION.supported_groups);
  assert.ok(isGrease((groups[2] << 8) | groups[3]), 'supported_groups does not start with GREASE');
  const versions = bodyOf(message, EXTENSION.supported_versions);
  assert.ok(isGrease((versions[1] << 8) | versions[2]), 'supported_versions does not start with GREASE');
  const ks = bodyOf(message, EXTENSION.key_share);
  assert.ok(isGrease((ks[2] << 8) | ks[3]), 'key_share does not start with GREASE');
  assert.equal((ks[4] << 8) | ks[5], 1, 'the GREASE key_share is not the one-byte key Chromium sends');

  const alpn = bodyOf(message, EXTENSION.alpn);
  assert.ok(!/\x0a\x0a/.test(String.fromCharCode(...alpn)), 'ALPN was GREASEd');
});

test('the two GREASE extensions differ from each other, as Chromium never repeats one', () => {
  const { types } = parse(hello({ grease: 7 }));
  assert.notEqual(types[0], types.at(-1));
});

test('shuffling reorders the middle, keeps the set, and pins the ends', () => {
  const a = parse(hello({ grease: 7, extensionOrder: SHUFFLE_EXTENSIONS })).types;
  const b = parse(hello({ grease: 99, extensionOrder: SHUFFLE_EXTENSIONS })).types;
  const real = (t) => t.filter((x) => !isGrease(x)).sort((x, y) => x - y);

  assert.notDeepEqual(a, b, 'two seeds produced the same order — nothing is being shuffled');
  assert.deepEqual(real(a), real(b), 'the extension SET changed, not just the order');
  assert.ok(isGrease(a[0]) && isGrease(a.at(-1)) && isGrease(b[0]) && isGrease(b.at(-1)));
});

test('a seed reproduces a hello exactly, so a fingerprint can be asserted byte for byte', () => {
  assert.deepEqual(
    hello({ grease: 12345, extensionOrder: SHUFFLE_EXTENSIONS }),
    hello({ grease: 12345, extensionOrder: SHUFFLE_EXTENSIONS }),
  );
});

test('pre_shared_key stays last of all, ahead of the trailing GREASE', () => {
  // RFC 8446 s4.2.11: the binder transcript is the hello truncated just before the binders, a
  // well-defined byte range only if nothing follows them. GREASE does not get to break that.
  for (const order of [CURL_EXTENSION_ORDER, SHUFFLE_EXTENSIONS]) {
    const { types } = parse(
      hello({
        grease: 7,
        extensionOrder: order,
        psk: { identity: new Uint8Array(8), obfuscatedTicketAge: 0, binderLen: 32 },
      }),
    );
    assert.equal(types.at(-1), EXTENSION.pre_shared_key, `psk was not last under ${String(order)}`);
    assert.ok(isGrease(types.at(-2)), 'the trailing GREASE is not immediately before the psk');
  }
});

test('a server that negotiates a GREASE cipher is refused, naming GREASE', () => {
  // RFC 8701 s3 requires a server to IGNORE these. One that selects a value we offered would pass
  // the "was it offered" test, which is exactly why this check exists ahead of it.
  const err = throwsCode(
    () =>
      negotiateCipher(
        { cipherSuite: 0x1a1a },
        { offeredCiphers: [0x1a1a, 0x1301], version: TLS13 },
      ),
    'TLS_CIPHER_UNSUPPORTED',
  );
  assert.match(err.message, /GREASE/);
  assert.match(err.message, /RFC 8701/);
});
