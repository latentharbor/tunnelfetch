// A deterministic, SYNCHRONOUS stand-in for ML-KEM-768, for hermetic offline tests only.
//
// It is NOT cryptography — it is a placeholder with the exact wire sizes of FIPS 203 ML-KEM-768
// (ek 1184, dk 2400, ct 1088, ss 32) and just enough structure to be internally consistent:
// decapsulate(encapsulate(ek).cipherText, dk) recovers encapsulate's sharedSecret when dk matches
// ek, and a tampered ciphertext triggers FIPS 203 implicit rejection (a pseudorandom secret, never
// an error). That is all the offer/concatenation WIRING needs to be exercised end to end without a
// megabyte of real lattice code. The real wasmcrypto/mlkem768 is what the live test uses to prove
// the concatenation ORDER against a real server — this fake can only ever agree with itself.
//
// The interface (keygen/encapsulate/decapsulate, returning plain objects and Uint8Arrays
// synchronously) is byte-for-byte the shape `wasmcrypto`'s `mlkem768` exports, so code under test
// cannot tell the two apart.

import { createHash, randomBytes } from 'node:crypto';

const EK_LEN = 1184;
const DK_LEN = 2400;
const CT_LEN = 1088;
const SS_LEN = 32;

const h = (tag, ...parts) => {
  const hash = createHash('sha256');
  hash.update(Uint8Array.of(tag));
  for (const p of parts) hash.update(p);
  return new Uint8Array(hash.digest()); // 32 bytes
};

/** Pad `head` out to `len` bytes with a deterministic-from-head filler, so sizes are exact. */
function pad(head, len) {
  const out = new Uint8Array(len);
  out.set(head.subarray(0, Math.min(head.byteLength, len)));
  for (let o = head.byteLength; o < len; o += SS_LEN) {
    out.set(h(0xee, out.subarray(0, o)).subarray(0, Math.min(SS_LEN, len - o)), o);
  }
  return out;
}

/**
 * A fresh fake ML-KEM-768. Each instance's keys are independent; encapsulate uses fresh randomness
 * unless a 32-byte `msg` is passed, matching wasmcrypto's optional-message form.
 */
export function fakeMlKem768() {
  return {
    publicKeyBytes: EK_LEN,
    secretKeyBytes: DK_LEN,
    cipherTextBytes: CT_LEN,
    sharedSecretBytes: SS_LEN,

    keygen(seed) {
      const s = seed ?? randomBytes(64);
      const id = h(0x10, s); // the "public identity" that binds ek and dk
      const z = h(0x11, s); // implicit-rejection secret
      const publicKey = pad(id, EK_LEN); // ek carries id in its first 32 bytes
      const secretKey = pad(concatBytes(id, z), DK_LEN); // dk carries id then z
      return { publicKey, secretKey };
    },

    encapsulate(publicKey, msg) {
      if (publicKey.byteLength !== EK_LEN) throw new RangeError('bad public key length');
      const id = publicKey.subarray(0, SS_LEN);
      const m = msg ?? randomBytes(SS_LEN);
      const sharedSecret = h(0x20, id, m); // the secret both sides must agree on
      const tag = h(0x21, id, m); // binds the ciphertext to (id, m) for the rejection check
      const cipherText = pad(concatBytes(m, tag), CT_LEN);
      return { cipherText, sharedSecret };
    },

    decapsulate(cipherText, secretKey) {
      if (cipherText.byteLength !== CT_LEN) throw new RangeError('bad ciphertext length');
      if (secretKey.byteLength !== DK_LEN) throw new RangeError('bad secret key length');
      const id = secretKey.subarray(0, SS_LEN);
      const z = secretKey.subarray(SS_LEN, 2 * SS_LEN);
      const m = cipherText.subarray(0, SS_LEN);
      const tag = cipherText.subarray(SS_LEN, 2 * SS_LEN);
      const expectTag = h(0x21, id, m);
      // FIPS 203 implicit rejection: a ciphertext that does not decrypt to a matching (id, m)
      // yields a pseudorandom secret derived from z, never an error.
      if (!equalBytes(tag, expectTag)) return h(0x30, z, cipherText);
      return h(0x20, id, m);
    },
  };
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

function equalBytes(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
