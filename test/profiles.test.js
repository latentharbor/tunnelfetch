// Fingerprint profiles: one coherent identity, or a refusal that says why.
//
// The problem a profile solves is not configurability — every field was already configurable. It is
// that nothing stopped a caller assembling a Chrome User-Agent on top of curl's TLS and curl's
// HTTP/2, which is a combination no real client produces and a detector reads instantly. Making
// every knob adjustable, as 1.2.0 did, made that easier rather than harder.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../src/client.js';
import { profiles, applyProfile } from '../src/profiles.js';
import { CURL_HEADER_ORDER } from '../src/client/header-order.js';
import { fakeNetwork, sequenceServer, response } from './_fakenet.js';

test('the curl profile supplies every layer at once', () => {
  const c = new Client({ profile: profiles.curl });
  assert.equal(c.options.tls.grease, false, 'curl does not GREASE');
  assert.deepEqual(c.options.headerOrder, CURL_HEADER_ORDER);
  assert.deepEqual(c.options.http2Settings, [[3, 100], [4, 10485760], [2, 0]]);
  assert.deepEqual(c.options.http2PseudoHeaderOrder, [':method', ':scheme', ':authority', ':path']);
});

test('an explicit option wins over the profile', () => {
  // Otherwise a profile could not be adjusted, only accepted whole — and a caller who names a
  // field meant to name it.
  const c = new Client({ profile: profiles.curl, headerOrder: ['host', '*'], tls: { grease: 42 } });
  assert.deepEqual(c.options.headerOrder, ['host', '*']);
  assert.equal(c.options.tls.grease, 42);
  // Fields the caller did not name still come from the profile.
  assert.deepEqual(c.options.tls.alpn, ['h2', 'http/1.1']);
});

test('a profile is REFUSED when it declares what this package cannot perform', () => {
  // Chromium offers ChaCha20 and X25519MLKEM768, and this package implements neither. A
  // ClientHello is an offer: a server may take either, and a client that then cannot complete the
  // handshake has traded a fingerprint mismatch for a dead connection. Silently dropping them
  // would rebuild the split identity the profile exists to prevent.
  let err;
  try {
    new Client({ profile: profiles.chrome });
  } catch (e) {
    err = e;
  }
  assert.ok(err, 'the chrome profile was accepted');
  assert.equal(err.code, 'CONFIG_INVALID');
  for (const need of ['cipher:chacha20', 'group:x25519mlkem768', 'decoder:br', 'http2:captured']) {
    assert.ok(err.message.includes(need), `the refusal does not name ${need}`);
  }
});

test('the refusal clears once the missing pieces are injected', () => {
  const stub = () => {};
  const c = new Client({
    profile: profiles.chrome,
    http2: false, // Chromium's h2 preface was never captured, so h2 must be off
    decoders: { br: stub, zstd: stub },
    ciphers: { chacha20: stub },
    groups: { x25519mlkem768: stub },
  });
  assert.equal(c.options.tls.extensionOrder, 'shuffle', 'Chromium shuffles; the profile must say so');
  assert.equal(c.options.tls.grease, true);
});

test('profile headers are defaults, not overrides', async () => {
  const server = sequenceServer([response({ body: 'ok' }), response({ body: 'ok' })]);
  const net = fakeNetwork(server.handler);
  const client = new Client({ connect: net.connect, forceTunnel: true, profile: profiles.curl });

  await client.fetch('http://origin.example/');
  assert.equal(server.seen[0].headers.get('user-agent'), 'curl/8.21.0');

  await client.fetch('http://origin.example/', { headers: [['User-Agent', 'mine/1']] });
  assert.equal(server.seen[1].headers.get('user-agent'), 'mine/1', 'the profile overrode the caller');
  await client.close();
});

test('a malformed profile is rejected rather than partly applied', () => {
  assert.throws(() => applyProfile({ profile: { tls: {} } }), (e) => e.code === 'CONFIG_INVALID');
  assert.throws(() => applyProfile({ profile: 'curl' }), (e) => e.code === 'CONFIG_INVALID');
  // No profile at all is not an error; it is the default.
  assert.deepEqual(applyProfile({ a: 1 }), { a: 1 });
});
