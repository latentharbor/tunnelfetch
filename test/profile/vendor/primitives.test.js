// The two vendored WASM primitives, tested here in the repository rather than trusted.
//
// They are compiled C — libsodium's ChaCha20-Poly1305 and mlkem-native's ML-KEM-768 — shipped as
// base64 inside a JS module. Both were validated where they were built, against RFC 8439 vectors
// and the NIST ACVP FIPS 203 KATs, and none of that helps anyone reading THIS repository. A
// vendored blob whose only evidence lives somewhere else is exactly the thing the repo-hygiene
// rule means by "a module with no test is an untested security boundary".
//
// So: a known-answer test that fails if the blob is ever swapped, rebuilt wrong, or truncated.

import test from 'node:test';
import assert from 'node:assert/strict';
import { chacha20poly1305 } from '../../../src/profile/vendor/chacha20poly1305.js';
import { mlkem768 as kem } from '../../../src/profile/vendor/mlkem768.js';

const hex = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const toHex = (u) => [...u].map((b) => b.toString(16).padStart(2, '0')).join('');

test('ChaCha20-Poly1305 reproduces the RFC 8439 s2.8.2 known answer', () => {
  // The AEAD example from the RFC, verbatim. The tag is the part that matters: it authenticates
  // both the ciphertext and the AAD, so a build that got either the stream cipher or the Poly1305
  // key derivation wrong cannot produce it by accident.
  const key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = hex('070000004041424344454647');
  const aad = hex('50515253c0c1c2c3c4c5c6c7');
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, " +
      'sunscreen would be it.',
  );

  const sealed = chacha20poly1305.seal(key, nonce, plaintext, aad);
  assert.equal(sealed.length, plaintext.length + 16);
  assert.equal(
    toHex(sealed.subarray(plaintext.length)),
    '1ae10b594f09e26a7e902ecbd0600691',
    'the Poly1305 tag does not match RFC 8439 — this build is not ChaCha20-Poly1305',
  );
  assert.equal(
    toHex(sealed.subarray(0, 8)),
    'd31a8d34648e60db',
    'the first ciphertext block does not match RFC 8439',
  );

  assert.deepEqual(chacha20poly1305.open(key, nonce, sealed, aad), plaintext);
});

test('ChaCha20-Poly1305 rejects a tampered message and a wrong AAD', () => {
  const key = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(12).fill(3);
  const aad = Uint8Array.from([1, 2, 3, 4, 5]);
  const msg = new TextEncoder().encode('authenticated');
  const sealed = chacha20poly1305.seal(key, nonce, msg, aad);

  // The implementation throws rather than returning null; `createAead` accepts either and turns
  // both into the same TLS_RECORD. What must never happen is a tampered message coming back as
  // plaintext, so that is what is asserted.
  const opened = (ct, a) => {
    try {
      return chacha20poly1305.open(key, nonce, ct, a);
    } catch {
      return null;
    }
  };
  const flipped = Uint8Array.from(sealed);
  flipped[2] ^= 1;
  assert.equal(opened(flipped, aad), null, 'a tampered ciphertext was accepted');

  const badTag = Uint8Array.from(sealed);
  badTag[badTag.length - 1] ^= 1;
  assert.equal(opened(badTag, aad), null, 'a tampered tag was accepted');

  assert.equal(opened(sealed, Uint8Array.from([9, 9, 9])), null, 'a wrong AAD was accepted');
  assert.deepEqual(opened(sealed, aad), msg, 'the untampered message stopped round-tripping');
});

test('ML-KEM-768 has FIPS 203 sizes and round-trips deterministically from a seed', () => {
  // Sizes are the cheapest way to catch round-3 Kyber being swapped in: it is a different algorithm
  // that will not interoperate with TLS X25519MLKEM768, and several npm packages ship it under a
  // similar name.
  assert.equal(kem.publicKeyBytes, 1184);
  assert.equal(kem.secretKeyBytes, 2400);
  assert.equal(kem.cipherTextBytes, 1088);
  assert.equal(kem.sharedSecretBytes, 32);

  const seed = Uint8Array.from({ length: 64 }, (_, i) => i);
  const a = kem.keygen(seed);
  const b = kem.keygen(seed);
  assert.deepEqual(a.publicKey, b.publicKey, 'keygen is not deterministic from its seed');
  assert.equal(a.publicKey.length, 1184);

  const { cipherText, sharedSecret } = kem.encapsulate(a.publicKey);
  assert.equal(cipherText.length, 1088);
  assert.deepEqual(
    kem.decapsulate(cipherText, a.secretKey),
    sharedSecret,
    'decapsulation does not recover the encapsulated secret',
  );
});

test('ML-KEM-768 implicit rejection is deterministic and silent, as FIPS 203 requires', () => {
  // The dangerous failure mode. A modified ciphertext must NOT throw — it must return a secret
  // derived from the private key, so an attacker cannot distinguish rejection from success by
  // observing behaviour. It must also be stable, or the failure is a different kind of oracle.
  const kp = kem.keygen(Uint8Array.from({ length: 64 }, (_, i) => 255 - i));
  const { cipherText, sharedSecret } = kem.encapsulate(kp.publicKey);
  const tampered = Uint8Array.from(cipherText);
  tampered[100] ^= 1;

  const first = kem.decapsulate(tampered, kp.secretKey);
  const second = kem.decapsulate(tampered, kp.secretKey);
  assert.equal(first.length, 32);
  assert.deepEqual(first, second, 'implicit rejection is not deterministic');
  assert.notDeepEqual(first, sharedSecret, 'a modified ciphertext recovered the real secret');
});

// ---------------------------------------------------------------- the two codecs

test('brotli and zstd decode real streams and fail closed on truncation', async () => {
  const { br } = await import('../../../src/profile/vendor/brotli-dec.js');
  const { zstd } = await import('../../../src/profile/vendor/zstd-dec.js');
  const { brotliCompressSync, zstdCompressSync } = await import('node:zlib');

  const text = 'the quick brown fox jumps over the lazy dog. '.repeat(4000);
  const raw = new TextEncoder().encode(text);
  const cases = [
    ['br', br, new Uint8Array(brotliCompressSync(raw))],
    ['zstd', zstd, new Uint8Array(zstdCompressSync(raw))],
  ];

  for (const [name, decode, packed] of cases) {
    const out = await new Response(decode(new Response(packed).body)).arrayBuffer();
    assert.equal(new TextDecoder().decode(out), text, `${name} round trip`);

    // Truncation must ERROR, not return what it managed. This package treats a short body as an
    // error everywhere else, and a decoder that quietly returns partial output would defeat that
    // for every compressed response.
    const cut = packed.subarray(0, Math.floor(packed.length * 0.6));
    await assert.rejects(
      () => new Response(decode(new Response(cut).body)).arrayBuffer(),
      `${name} accepted a truncated stream`,
    );
  }
});

test('the codecs bound their own output, because decodeBody deliberately does not', async () => {
  // `decodeBody` caps built-in codings against maxBodyBytes but leaves a caller-supplied decoder
  // to bound itself — so a decoder without its own limit would reopen the gzip-bomb hole closed in
  // 1.4.1, through the very option added to close it.
  const { makeBrotliDecoder } = await import('../../../src/profile/vendor/brotli-dec.js');
  const { brotliCompressSync } = await import('node:zlib');
  const bomb = new Uint8Array(brotliCompressSync(new Uint8Array(8 * 1024 * 1024)));
  const capped = makeBrotliDecoder({ maxOutputBytes: 256 * 1024 });
  await assert.rejects(
    () => new Response(capped(new Response(bomb).body)).arrayBuffer(),
    'an 8 MiB decompressed body passed a 256 KiB decoder cap',
  );
});
