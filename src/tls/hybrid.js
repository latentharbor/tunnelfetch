// X25519MLKEM768 (group 0x11EC): the post-quantum hybrid key exchange of
// draft-kwiatkowski-tls-ecdhe-mlkem.
//
// This is a HYBRID: two independent key agreements run side by side and their secrets are
// concatenated, so the session is safe as long as EITHER holds — X25519 against a classical
// attacker, ML-KEM-768 against a future quantum one. ML-KEM is not a WebCrypto primitive on this
// runtime, so its keygen/encapsulate/decapsulate are INJECTED (the same discipline ChaCha20 gets
// in aead.js): without an implementation the group is never offered, and a ClientHello is an offer
// a server may take. The X25519 half is plain WebCrypto, exactly as x25519 alone is elsewhere.
//
// The three orderings below are the whole subtlety of this file, and each is a silent trap: a
// reversed concatenation does not throw, it produces a shared secret that merely DIFFERS, so the
// handshake fails only later, at a Finished that will not verify — indistinguishable from a server
// bug. draft-kwiatkowski-tls-ecdhe-mlkem fixes them, and they were confirmed against a real
// X25519MLKEM768 server (Cloudflare) by completing a handshake, not read off the page:
//
//   * client key_share  = ML-KEM-768 encapsulation key (1184) || X25519 public key (32)  = 1216
//   * server key_share   = ML-KEM-768 ciphertext        (1088) || X25519 public key (32)  = 1120
//   * shared secret      = ML-KEM-768 shared secret       (32) || X25519 shared secret (32) =  64
//
// ML-KEM comes FIRST in all three. (This is the opposite of the NIST-curve hybrids such as
// SecP256r1MLKEM768, where the classical share leads — which is exactly why it must be verified
// per group rather than assumed.) ML-KEM decapsulation uses FIPS 203 implicit rejection: a bad
// ciphertext yields a pseudorandom secret rather than an error, so a mismatch here can ONLY show
// up as a bad Finished, never as an exception. That is by design and is why offline agreement is
// necessary but not sufficient — see the live test.

import { TlsError, codes, hex16 } from '../errors.js';
import { concat } from '../util/bytes.js';
import { GROUP, GROUP_PARAMS } from './constants.js';

export const HYBRID_GROUP = GROUP.x25519mlkem768;
const P = GROUP_PARAMS[HYBRID_GROUP];

const X25519_ALG = { name: 'X25519' };

/**
 * An injected ML-KEM-768 implementation (FIPS 203). Shapes match `wasmcrypto`'s `mlkem768`:
 * @typedef {object} MlKem768
 * @property {(seed?: Uint8Array) => { publicKey: Uint8Array, secretKey: Uint8Array }} keygen
 *   ML-KEM.KeyGen; `publicKey` is the 1184-byte encapsulation key, `secretKey` the 2400-byte
 *   decapsulation key.
 * @property {(publicKey: Uint8Array) => { cipherText: Uint8Array, sharedSecret: Uint8Array }}
 *   encapsulate ML-KEM.Encaps; used by a server, exercised by the offline test server.
 * @property {(cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array} decapsulate
 *   ML-KEM.Decaps; returns the 32-byte shared secret (implicit rejection on a bad ciphertext).
 */

/**
 * The private half kept between generateHybridKeyShare and deriveHybridSecret: the ML-KEM
 * decapsulation key and the X25519 private key. Not a CryptoKey, so callers treat KeyShare's
 * private component opaquely (they already do — it only ever flows back into derivation).
 * @typedef {object} HybridPrivate
 * @property {Uint8Array} mlkemSecretKey the ML-KEM decapsulation key
 * @property {CryptoKey} classicalPrivateKey the X25519 private key
 */

function checkLen(actual, want, what) {
  if (actual !== want) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `X25519MLKEM768 ${what} is ${actual} bytes, expected ${want}`,
      { group: HYBRID_GROUP, got: actual, expected: want },
    );
  }
}

/**
 * Generate a client key share for X25519MLKEM768.
 *
 * @param {MlKem768} kem the injected ML-KEM-768 implementation
 * @param {import('./connect.js').TlsDeps} [deps] `generateKeyPair` is honoured for the X25519
 *   half so a recorded handshake can be replayed with a fixed classical key
 * @returns {Promise<{ group: number, keyExchange: Uint8Array, privateKey: HybridPrivate }>}
 *   `keyExchange` is the 1216-byte wire share (ML-KEM encapsulation key || X25519 public key)
 */
export async function generateHybridKeyShare(kem, { generateKeyPair } = {}) {
  requireKem(kem);
  // ML-KEM keypair. The encapsulation key goes on the wire; the decapsulation key is kept.
  const mlkem = kem.keygen();
  checkLen(mlkem.publicKey?.byteLength, P.mlkemPublicLen, 'ML-KEM encapsulation key');
  checkLen(mlkem.secretKey?.byteLength, P.mlkemSecretKeyLen, 'ML-KEM decapsulation key');

  // X25519 keypair, via WebCrypto exactly as the standalone x25519 group does.
  const gen =
    generateKeyPair ??
    ((algorithm) => crypto.subtle.generateKey(algorithm, false, ['deriveBits']));
  const pair = await gen(X25519_ALG, GROUP.x25519);
  const classicalPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  checkLen(classicalPublic.byteLength, P.classicalPublicLen, 'X25519 public key');

  // ML-KEM FIRST, then X25519 — the client-share ordering. 1184 + 32 = 1216.
  const keyExchange = concat([mlkem.publicKey, classicalPublic]);
  return {
    group: HYBRID_GROUP,
    keyExchange,
    privateKey: { mlkemSecretKey: mlkem.secretKey, classicalPrivateKey: pair.privateKey },
  };
}

/**
 * Derive the 64-byte hybrid shared secret from the server's X25519MLKEM768 key share.
 *
 * @param {MlKem768} kem the injected ML-KEM-768 implementation
 * @param {HybridPrivate} privateKey what generateHybridKeyShare kept
 * @param {Uint8Array} serverShare the server's 1120-byte key_exchange (ciphertext || X25519 pub)
 * @returns {Promise<Uint8Array>} ML-KEM shared secret (32) || X25519 shared secret (32) = 64
 */
export async function deriveHybridSecret(kem, privateKey, serverShare) {
  requireKem(kem);
  if (!privateKey || !privateKey.mlkemSecretKey || !privateKey.classicalPrivateKey) {
    throw new TlsError(codes.CONFIG_INVALID,
      'X25519MLKEM768 derivation needs the ML-KEM decapsulation key and the X25519 private key');
  }
  // The server share is ML-KEM ciphertext (1088) then X25519 public key (32). A wrong length here
  // is the server contradicting the group it selected; fail closed rather than slice past the end.
  checkLen(serverShare.byteLength, P.serverShareLen, 'server key_share');
  const ciphertext = serverShare.subarray(0, P.mlkemCiphertextLen);
  const classicalPublic = serverShare.subarray(P.mlkemCiphertextLen);

  // ML-KEM decapsulation. Implicit rejection (FIPS 203) means a tampered ciphertext yields a
  // pseudorandom secret, not an error — the mismatch can only surface at Finished, by design.
  const mlkemSecret = kem.decapsulate(ciphertext, privateKey.mlkemSecretKey);
  checkLen(mlkemSecret?.byteLength, P.classicalSecretLen, 'ML-KEM shared secret');

  // X25519 agreement, with the same small-order guard the standalone x25519 path applies.
  let classicalPeer;
  try {
    classicalPeer = await crypto.subtle.importKey('raw', classicalPublic, X25519_ALG, false, []);
  } catch (cause) {
    throw new TlsError(codes.TLS_HANDSHAKE,
      `X25519MLKEM768 server X25519 share is not a valid public key: ${cause?.message}`,
      { group: HYBRID_GROUP });
  }
  let classicalSecret;
  try {
    classicalSecret = new Uint8Array(
      await crypto.subtle.deriveBits({ ...X25519_ALG, public: classicalPeer },
        privateKey.classicalPrivateKey, P.classicalSecretLen * 8));
  } catch (cause) {
    throw new TlsError(codes.TLS_HANDSHAKE,
      `X25519MLKEM768 X25519 agreement failed: ${cause?.message ?? cause}. This usually means a ` +
        'degenerate or small-order server key.', { group: HYBRID_GROUP });
  }
  // RFC 7748 s6.1: an all-zero X25519 output is a small-order peer key. Reject, as x25519 does.
  if (classicalSecret.every((b) => b === 0)) {
    throw new TlsError(codes.TLS_HANDSHAKE,
      'X25519MLKEM768 X25519 shared secret is all zeroes, indicating a small-order server key');
  }

  // ML-KEM FIRST, then X25519 — the shared-secret ordering. 32 + 32 = 64.
  return concat([mlkemSecret, classicalSecret]);
}

/** @param {MlKem768} kem */
function requireKem(kem) {
  if (typeof kem?.keygen !== 'function' || typeof kem?.decapsulate !== 'function') {
    throw new TlsError(
      codes.CONFIG_INVALID,
      `${hex16(HYBRID_GROUP)} (x25519mlkem768) was reached but no ML-KEM-768 implementation was ` +
        'supplied; pass one as `groups: { x25519mlkem768: impl }` with keygen()/encapsulate()/' +
        'decapsulate()',
      { group: HYBRID_GROUP },
    );
  }
}
