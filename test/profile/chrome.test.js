// The `tunnelfetch/profile/chrome` subpath: importing it IS the opt-in.
//
// `profiles.chrome` in the main entry is a declaration that refuses to be presented without the
// capabilities it names. That refusal is correct and it leaves the caller to find and wire two WASM
// primitives. This module supplies them — and it is a SEPARATE ENTRY POINT rather than a flag so
// that a bundler only pulls the blobs in for code that imports this path. A caller on the curl
// default pays nothing, which is the entire reason for the shape.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { chrome } from '../../src/profile/chrome.js';
import { profiles } from '../../src/profiles.js';

test('the bundled profile is complete: it constructs with no further options', () => {
  // br and zstd were held back at first, on the grounds that there is no single right
  // implementation. Measurement dissolved that — a decode-only build of the reference C beats the
  // npm alternative by 1.5x at the interface this package actually uses — so the identity is now
  // presentable as shipped. That it constructs at all is the assertion: every entry in `requires`
  // is met by the profile itself.
  const c = new Client({ profile: chrome });
  assert.deepEqual(Object.keys(c.options.decoders).sort(), ['br', 'zstd']);
  assert.equal(typeof c.options.ciphers.chacha20.seal, 'function');
  assert.equal(typeof c.options.groups.x25519mlkem768.keygen, 'function');
  // The declaration in the main entry still names what the identity needs, so a caller who reaches
  // for `profiles.chrome` without this subpath gets told what is missing rather than a broken hello.
  assert.match(profiles.chrome.requires.join(), /cipher:chacha20/);
  assert.match(profiles.chrome.requires.join(), /decoder:br/);
});

test('it advertises exactly what Chrome advertises, and can read all of it', async () => {
  const { acceptEncodingFor } = await import('../../src/client/decode.js');
  const c = new Client({ profile: chrome });
  assert.equal(acceptEncodingFor(c.options.decoders), 'gzip, deflate, br, zstd');
});

test('it carries every layer of the identity', () => {
  const c = new Client({ profile: chrome });
  assert.equal(c.options.tls.grease, true);
  assert.equal(c.options.tls.extensionOrder, 'shuffle', 'Chromium shuffles; the profile must too');
  assert.deepEqual(c.options.http2PseudoHeaderOrder, [':method', ':authority', ':scheme', ':path']);
  assert.equal(typeof c.options.ciphers.chacha20.seal, 'function');
  assert.equal(typeof c.options.groups.x25519mlkem768.keygen, 'function');
});

test('the caller can override what the profile brought', () => {
  const mine = { seal: () => new Uint8Array(0), open: () => null };
  const c = new Client({ profile: chrome, ciphers: { chacha20: mine } });
  assert.equal(c.options.ciphers.chacha20, mine, 'the profile overrode the caller');
});

test('the bundled primitives are the real ones, not stubs', async () => {
  // Cheap end-to-end sanity: ML-KEM round-trips its own encapsulation, and ChaCha20 round-trips a
  // sealed message. A profile that wired in something inert would pass every assertion above.
  const { chacha20poly1305, mlkem768 } = await import('../../src/profile/chrome.js');
  const kp = mlkem768.keygen(new Uint8Array(64).fill(5));
  const { cipherText, sharedSecret } = mlkem768.encapsulate(kp.publicKey);
  assert.deepEqual(mlkem768.decapsulate(cipherText, kp.secretKey), sharedSecret);
  assert.equal(kp.publicKey.length, 1184);

  const key = new Uint8Array(32).fill(1);
  const nonce = new Uint8Array(12).fill(2);
  const msg = new TextEncoder().encode('real, not inert');
  const sealed = chacha20poly1305.seal(key, nonce, msg, new Uint8Array(5));
  assert.deepEqual(chacha20poly1305.open(key, nonce, sealed, new Uint8Array(5)), msg);
  const tampered = Uint8Array.from(sealed);
  tampered[0] ^= 1;
  // The vendored implementation THROWS on authentication failure rather than returning null.
  // aead.js accepts either — it catches and turns both into the same TLS_RECORD — so the contract
  // asserted here is the one that matters: a tampered message never comes back as plaintext.
  let opened = null;
  try { opened = chacha20poly1305.open(key, nonce, tampered, new Uint8Array(5)); } catch { opened = null; }
  assert.equal(opened, null, 'a tampered message was accepted');
});
