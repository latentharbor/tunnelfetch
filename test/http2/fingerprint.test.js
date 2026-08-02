// The h2 client fingerprint, pinned to curl 8.7.1 / nghttp2 1.69.0 as captured on a live ALPN h2
// handshake. NOTE the version: the TLS half of this fingerprint is attributed to curl 8.21.0 /
// OpenSSL 3.6.3 in the README and in src/profiles.js, and these two captures were taken from
// different curl builds. nghttp2's h2 preface has been stable across that range, so the bytes
// below are believed current — but 'believed' is the operative word, and one identity quoting
// two source versions is a discrepancy a reader deserves to see rather than a detail to tidy
// away. Neither capture has an artifact committed anywhere in this repository.
// handshake. This is empirical, not aesthetic: HTTP/2 exists in this package for ACCESS — some
// sites challenge HTTP/1.1 as a bot signal and let curl's h2 through — and a naive h2 fingerprint
// can fail exactly where curl's succeeds. If any of these bytes drift from curl's, that is a
// regression in the one property the whole feature is for, so it is asserted, not left to chance.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Http2Connection, buildRequestFields } from '../../src/http2/connection.js';
import { encodeHeaderBlock } from '../../src/http2/hpack.js';
import { ByteReader, concat } from '../../src/util/bytes.js';
import { duplexPair } from '../_harness.js';
import { readFrame, parseSettings, parseWindowUpdate } from '../../src/http2/frames.js';
import { FRAME } from '../../src/http2/constants.js';
import { applyProfile } from '../../src/profiles.js';
import { chrome as chromeProfile } from '../../src/profile/chrome.js';

/**
 * Drive a connection and read the exact frames it writes as its preface flight. A real peer keeps
 * reading, so after the flight this drains side b in the background — otherwise the GOAWAY that
 * close() writes would block on the in-memory transport's backpressure and hang the test.
 */
async function capturePreface(opts = {}) {
  const { a, b } = duplexPair();
  const conn = new Http2Connection(a, opts);
  const reader = new ByteReader(b.readable);
  const preface = await reader.readExactly(24, 'preface');
  const settings = await readFrame(reader);
  const windowUpdate = await readFrame(reader);
  (async () => {
    for (;;) {
      const f = await readFrame(reader).catch(() => null);
      if (f === null) break;
    }
  })();
  return { conn, reader, preface, settings, windowUpdate, writer: b.writable };
}

test('the connection preface is the exact 24-byte magic', async () => {
  const { conn, preface } = await capturePreface();
  assert.equal(new TextDecoder().decode(preface), 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
  await conn.close();
});

test('SETTINGS matches curl: MAX_CONCURRENT_STREAMS=100, INITIAL_WINDOW_SIZE=10485760, ENABLE_PUSH=0, in that order', async () => {
  const { conn, settings } = await capturePreface();
  assert.equal(settings.type, FRAME.SETTINGS);
  assert.equal(settings.streamId, 0);
  assert.deepEqual(parseSettings(settings.payload), [
    [3, 100], // SETTINGS_MAX_CONCURRENT_STREAMS
    [4, 10485760], // SETTINGS_INITIAL_WINDOW_SIZE (10 MiB)
    [2, 0], // SETTINGS_ENABLE_PUSH
  ]);
  await conn.close();
});

test('the connection WINDOW_UPDATE raises the window to exactly 1000 MiB, like curl', async () => {
  const { conn, windowUpdate } = await capturePreface();
  assert.equal(windowUpdate.type, FRAME.WINDOW_UPDATE);
  assert.equal(windowUpdate.streamId, 0);
  const inc = parseWindowUpdate(windowUpdate.payload);
  assert.equal(inc, 1048510465, 'curl increments by 1000 MiB - 65535');
  assert.equal(65535 + inc, 1048576000, 'the resulting connection window is 1000 MiB');
  await conn.close();
});

test('the whole preface flight is byte-identical to curl (preface, SETTINGS, WINDOW_UPDATE)', async () => {
  const { conn, preface, settings, windowUpdate } = await capturePreface();
  const flight = concat([preface, reserialize(settings), reserialize(windowUpdate)]);
  // The exact bytes captured from curl 8.7.1 over a live ALPN h2 handshake: the 24-byte preface,
  // the SETTINGS frame (ids 3,4,2), then the connection-level WINDOW_UPDATE.
  const curl =
    '505249202a20485454502f322e300d0a0d0a534d0d0a0d0a' +
    '000012040000000000000300000064000400a000000002000000' +
    '000000040800000000003e7f0001';
  assert.equal(Buffer.from(flight).toString('hex'), curl);
  await conn.close();
});

test('request pseudo-headers are emitted in curl order m,s,a,p with curl representations', () => {
  const fields = buildRequestFields({
    method: 'GET',
    scheme: 'https',
    authority: 'origin.example',
    path: '/some/path',
    headers: [['user-agent', 'x'], ['accept', '*/*']],
  });
  assert.deepEqual(
    fields.slice(0, 4).map((f) => f.name),
    [':method', ':scheme', ':authority', ':path'],
    'method, scheme, authority, path — the captured curl order',
  );
  const block = encodeHeaderBlock(fields);
  // 0x82 = indexed :method GET, 0x87 = indexed :scheme https (curl uses fully-indexed static here).
  assert.equal(block[0], 0x82);
  assert.equal(block[1], 0x87);
  // :authority is literal WITH incremental indexing (0x41 = name index 1), like curl's capture.
  assert.equal(block[2], 0x41);
});

/** Re-serialise a parsed frame back to wire bytes for a byte-exact comparison. */
function reserialize(frame) {
  const header = new Uint8Array(9);
  const len = frame.payload.length;
  header[0] = (len >>> 16) & 0xff;
  header[1] = (len >>> 8) & 0xff;
  header[2] = len & 0xff;
  header[3] = frame.type;
  header[4] = frame.flags;
  header[5] = (frame.streamId >>> 24) & 0x7f;
  header[6] = (frame.streamId >>> 16) & 0xff;
  header[7] = (frame.streamId >>> 8) & 0xff;
  header[8] = frame.streamId & 0xff;
  return concat([header, frame.payload]);
}

test('the SETTINGS flight is configurable, ids and order included', async () => {
  // The default is curl's and is pinned above. This is the other half of the contract the TLS side
  // now has: a caller matching some client other than curl must be able to place the settings where
  // that client places them, because an Akamai-style h2 fingerprint reads the ids in wire order.
  const { conn, settings } = await capturePreface({
    settings: [
      [0x1, 65536], // HEADER_TABLE_SIZE
      [0x2, 0], // ENABLE_PUSH
      [0x4, 6291456], // INITIAL_WINDOW_SIZE
      [0x6, 262144], // MAX_HEADER_LIST_SIZE
    ],
  });
  const ids = [];
  for (let o = 0; o < settings.payload.length; o += 6) {
    ids.push((settings.payload[o] << 8) | settings.payload[o + 1]);
  }
  assert.deepEqual(ids, [0x1, 0x2, 0x4, 0x6]);
  await conn.close();
});

test('the pseudo-header order is configurable, and a missing one is appended not dropped', () => {
  // Order is read by an Akamai-style h2 fingerprint, so a caller matching another client needs it.
  // But RFC 9113 s8.3.1 makes all four pseudo-headers mandatory for a request, so an order that
  // omits one must not produce a malformed request — that is not a fingerprint choice anyone
  // should be able to make by accident.
  const req = { method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [] };

  const reordered = buildRequestFields(req, {
    pseudoHeaderOrder: [':method', ':path', ':authority', ':scheme'],
  });
  assert.deepEqual(
    reordered.map((f) => f.name),
    [':method', ':path', ':authority', ':scheme'],
  );

  const partial = buildRequestFields(req, { pseudoHeaderOrder: [':path', ':method'] });
  assert.deepEqual(
    partial.map((f) => f.name),
    [':path', ':method', ':scheme', ':authority'],
    'a pseudo-header left out of the order was dropped instead of appended',
  );
});

test('HPACK indexing is configurable, and defaults to curl\'s', () => {
  // Which fields enter the dynamic table is part of the fingerprint. curl indexes everything
  // except :path.
  const req = { method: 'GET', scheme: 'https', authority: 'h', path: '/', headers: [['a', 'b']] };
  const dflt = buildRequestFields(req);
  assert.equal(dflt.find((f) => f.name === ':path').indexing, 'without');
  assert.equal(dflt.find((f) => f.name === ':method').indexing, 'incremental');

  const custom = buildRequestFields(req, {
    hpackIndexing: { ':path': 'incremental', a: 'never' },
  });
  assert.equal(custom.find((f) => f.name === ':path').indexing, 'incremental');
  assert.equal(custom.find((f) => f.name === 'a').indexing, 'never');
  assert.equal(custom.find((f) => f.name === ':scheme').indexing, 'incremental', 'unlisted fields moved');
});

// The Chrome identity's h2 half, asserted through `applyProfile` rather than by hand.
//
// Nothing in this repository pinned a single Chrome h2 value before, and that is exactly how the
// connection window came to be dead config: `profiles.chrome` declared Chromium's ~15 MiB window,
// `applyProfile` did not copy it, the client never passed it, and the connection reads an option
// spelled differently — so every Chrome-profile connection sent curl's 1000 MiB increment under a
// Chromium ClientHello. Four places had to agree and nothing checked that they did.
//
// These drive the profile through the same folding the Client uses, so a field that stops being
// propagated fails here rather than on someone's wire.
test('the chrome profile reaches the connection: its SETTINGS and its window, not curl\'s', async () => {
  const folded = applyProfile({ profile: chromeProfile, http2: true });
  const { conn, settings, windowUpdate } = await capturePreface({
    settings: folded.http2Settings,
    connectionWindow: folded.http2ConnectionWindow,
  });

  // Captured off the wire from Chrome 150: HEADER_TABLE_SIZE, ENABLE_PUSH, INITIAL_WINDOW_SIZE,
  // MAX_HEADER_LIST_SIZE — ids and order both, since the order is part of the fingerprint.
  assert.deepEqual(parseSettings(settings.payload), [[0x1, 65536], [0x2, 0], [0x4, 6291456], [0x6, 262144]]);

  // 15663105 + 65535 = 15728640. curl's is 1048576000, so a wrong wiring is not a subtle miss.
  const inc = parseWindowUpdate(windowUpdate.payload);
  assert.equal(inc, 15728640 - 65535, `connection window increment was ${inc}`);
  assert.notEqual(inc, 1048510465, 'the chrome profile sent curl\'s connection window');
  await conn.close();
});

test('chrome and curl do not silently share an h2 preface', async () => {
  // The failure mode a profile exists to prevent is a Chromium ClientHello above another client's
  // framing. This asserts the two prefaces differ at all — a regression that made the chrome
  // profile fall back to curl's defaults would collapse them into one.
  const chrome = applyProfile({ profile: chromeProfile, http2: true });
  const a = await capturePreface({ settings: chrome.http2Settings,
                                   connectionWindow: chrome.http2ConnectionWindow });
  const b = await capturePreface(); // curl: the package defaults
  assert.notDeepEqual(parseSettings(a.settings.payload), parseSettings(b.settings.payload));
  assert.notEqual(parseWindowUpdate(a.windowUpdate.payload), parseWindowUpdate(b.windowUpdate.payload));
  await a.conn.close();
  await b.conn.close();
});

// HPACK indexing is the one h2 fingerprint field the chrome capture does NOT cover, and this test
// records that rather than letting it stay invisible. `_hpackIndexing` falls back to curl's
// `:path`-without-indexing inside the connection, so the chrome profile currently presents curl's
// HPACK representation. Closing that needs a capture, not a guess — see the README.
test('the chrome profile has no captured HPACK indexing, and inherits curl\'s', async () => {
  const folded = applyProfile({ profile: chromeProfile, http2: true });
  assert.equal(
    folded.http2HpackIndexing,
    undefined,
    'chrome now declares HPACK indexing — capture it, then assert the captured value here instead',
  );
});
