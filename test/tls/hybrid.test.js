// X25519MLKEM768 combiner (src/tls/hybrid.js), against the synchronous fake ML-KEM.
//
// These tests prove the WIRING and the byte layout: the client share is ML-KEM encapsulation key
// then X25519 public key (1184 + 32 = 1216), the server share is ML-KEM ciphertext then X25519
// public key (1088 + 32 = 1120), and the shared secret is ML-KEM secret then X25519 secret
// (32 + 32 = 64). They CANNOT prove the ordering is the one the internet expects — a self-written
// server agrees with a self-written client whatever order both use — so the order-sensitivity
// tests below only prove a reversal does not silently pass, and the live test against a real
// X25519MLKEM768 server is what fixes the order to the real one.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  HYBRID_GROUP, deriveHybridSecret, generateHybridKeyShare,
} from '../../src/tls/hybrid.js';
import { concat, toHex } from '../../src/util/bytes.js';
import { fakeMlKem768 } from './_mlkem.js';

const EK = 1184, CT = 1088, X = 32;

/** A kem wrapper that remembers the keypair keygen() produced, so a test can inspect the ek. */
function capturingKem() {
  const inner = fakeMlKem768();
  let last = null;
  return {
    ...inner,
    keygen(seed) {
      last = inner.keygen(seed);
      return last;
    },
    get lastKeypair() {
      return last;
    },
  };
}

/**
 * The SERVER half, written here by hand — independent of src/tls/hybrid.js — so a concatenation
 * bug on the client side cannot be cancelled out by the same bug on the server side. Splits the
 * client share as ML-KEM ek || X25519 pub, encapsulates, and returns the server share and secret
 * with ML-KEM first in each.
 */
async function serverSide(kem, clientShare) {
  const ek = clientShare.subarray(0, EK);
  const clientX = clientShare.subarray(EK, EK + X);
  const { cipherText, sharedSecret: mlkemSs } = kem.encapsulate(ek);
  const pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const serverX = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const peer = await crypto.subtle.importKey('raw', clientX, { name: 'X25519' }, false, []);
  const x25519Ss = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, pair.privateKey, X * 8));
  return {
    serverShare: concat([cipherText, serverX]), // ML-KEM ciphertext, then X25519 public
    sharedSecret: concat([mlkemSs, x25519Ss]), // ML-KEM secret, then X25519 secret
  };
}

test('the client key_share is ML-KEM ek (1184) then X25519 public (32) = 1216 bytes', async () => {
  const kem = capturingKem();
  const share = await generateHybridKeyShare(kem, {});
  assert.equal(share.group, HYBRID_GROUP);
  assert.equal(share.keyExchange.byteLength, 1216);
  // ML-KEM comes FIRST: the leading 1184 bytes are exactly the encapsulation key keygen produced.
  assert.equal(
    toHex(share.keyExchange.subarray(0, EK)),
    toHex(kem.lastKeypair.publicKey),
    'the ML-KEM encapsulation key must be the leading 1184 bytes of the client share',
  );
  // The trailing 32 bytes are the X25519 public key — a real one, so importKey accepts it.
  await assert.doesNotReject(() =>
    crypto.subtle.importKey('raw', share.keyExchange.subarray(EK), { name: 'X25519' }, false, []));
});

test('a full exchange agrees, and the secret is ML-KEM (32) then X25519 (32) = 64 bytes', async () => {
  const kem = fakeMlKem768();
  const share = await generateHybridKeyShare(kem, {});
  const server = await serverSide(kem, share.keyExchange);
  assert.equal(server.serverShare.byteLength, 1120, 'server share is ct(1088) + X25519(32)');

  const clientSecret = await deriveHybridSecret(kem, share.privateKey, server.serverShare);
  assert.equal(clientSecret.byteLength, 64);
  assert.equal(
    toHex(clientSecret), toHex(server.sharedSecret),
    'client and server must derive the same 64-byte hybrid secret',
  );
  // And the halves are in the ML-KEM-then-X25519 order: decapsulating the ciphertext directly
  // gives the FIRST 32 bytes, never the last.
  const mlkemHalf = kem.decapsulate(server.serverShare.subarray(0, CT), share.privateKey.mlkemSecretKey);
  assert.equal(toHex(clientSecret.subarray(0, X)), toHex(mlkemHalf),
    'the ML-KEM shared secret must be the FIRST 32 bytes of the hybrid secret');
});

test('reversing the server share halves changes the secret — a swap cannot pass silently', async () => {
  const kem = fakeMlKem768();
  const share = await generateHybridKeyShare(kem, {});
  const server = await serverSide(kem, share.keyExchange);

  const correct = await deriveHybridSecret(kem, share.privateKey, server.serverShare);
  // Swap the halves: X25519 public (32) first, then ciphertext (1088). Same bytes, wrong order.
  const swapped = concat([server.serverShare.subarray(CT), server.serverShare.subarray(0, CT)]);
  // Wrong length now (32 + 1088 = 1120 still), but the ct/x25519 boundary is at the wrong offset.
  const wrong = await deriveHybridSecret(kem, share.privateKey, swapped).catch((e) => e);
  // Either it derived a DIFFERENT secret, or it refused — never the same secret.
  if (wrong instanceof Uint8Array) {
    assert.notEqual(toHex(wrong), toHex(correct), 'a reversed server share must not derive the same secret');
  } else {
    assert.equal(wrong.code, 'TLS_HANDSHAKE');
  }
});

test('a server share of the wrong length is a typed handshake error, not a slice past the end', async () => {
  const kem = fakeMlKem768();
  const share = await generateHybridKeyShare(kem, {});
  for (const len of [0, 1119, 1121, 1216]) {
    const err = await deriveHybridSecret(kem, share.privateKey, new Uint8Array(len)).catch((e) => e);
    assert.equal(err.code, 'TLS_HANDSHAKE', `length ${len} must be refused`);
    assert.match(err.message, /1120/);
  }
});

test('no ML-KEM implementation is a typed configuration error, at both keygen and derive', async () => {
  const genErr = await generateHybridKeyShare(undefined, {}).catch((e) => e);
  assert.equal(genErr.code, 'CONFIG_INVALID');
  assert.match(genErr.message, /x25519mlkem768|ML-KEM/);

  const kem = fakeMlKem768();
  const share = await generateHybridKeyShare(kem, {});
  const server = await serverSide(kem, share.keyExchange);
  const derErr = await deriveHybridSecret(undefined, share.privateKey, server.serverShare).catch((e) => e);
  assert.equal(derErr.code, 'CONFIG_INVALID');
});

test('a tampered ML-KEM ciphertext derives a different secret (implicit rejection surfaces late)', async () => {
  const kem = fakeMlKem768();
  const share = await generateHybridKeyShare(kem, {});
  const server = await serverSide(kem, share.keyExchange);
  const correct = await deriveHybridSecret(kem, share.privateKey, server.serverShare);

  const tampered = server.serverShare.slice();
  tampered[10] ^= 0xff; // flip a byte inside the ML-KEM ciphertext
  const got = await deriveHybridSecret(kem, share.privateKey, tampered);
  // FIPS 203 implicit rejection: no throw, but the ML-KEM half is now pseudorandom, so the whole
  // secret differs — which is exactly why a hybrid mistake surfaces only at Finished.
  assert.notEqual(toHex(got), toHex(correct));
  assert.equal(got.byteLength, 64);
});

test('the injected X25519 keypair generator is honoured, for replayable handshakes', async () => {
  const kem = fakeMlKem768();
  const fixed = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  let calls = 0;
  const deps = { generateKeyPair: async () => { calls++; return fixed; } };
  const a = await generateHybridKeyShare(kem, deps);
  const b = await generateHybridKeyShare(kem, deps);
  assert.equal(calls, 2);
  // Same X25519 key both times; the trailing 32 bytes of the share are identical.
  assert.equal(toHex(a.keyExchange.subarray(EK)), toHex(b.keyExchange.subarray(EK)));
});
