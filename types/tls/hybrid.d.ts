/**
 * Generate a client key share for X25519MLKEM768.
 *
 * @param {MlKem768} kem the injected ML-KEM-768 implementation
 * @param {import('./connect.js').TlsDeps} [deps] `generateKeyPair` is honoured for the X25519
 *   half so a recorded handshake can be replayed with a fixed classical key
 * @returns {Promise<{ group: number, keyExchange: Uint8Array, privateKey: HybridPrivate }>}
 *   `keyExchange` is the 1216-byte wire share (ML-KEM encapsulation key || X25519 public key)
 */
export function generateHybridKeyShare(kem: MlKem768, { generateKeyPair }?: import("./connect.js").TlsDeps): Promise<{
    group: number;
    keyExchange: Uint8Array;
    privateKey: HybridPrivate;
}>;
/**
 * Derive the 64-byte hybrid shared secret from the server's X25519MLKEM768 key share.
 *
 * @param {MlKem768} kem the injected ML-KEM-768 implementation
 * @param {HybridPrivate} privateKey what generateHybridKeyShare kept
 * @param {Uint8Array} serverShare the server's 1120-byte key_exchange (ciphertext || X25519 pub)
 * @returns {Promise<Uint8Array>} ML-KEM shared secret (32) || X25519 shared secret (32) = 64
 */
export function deriveHybridSecret(kem: MlKem768, privateKey: HybridPrivate, serverShare: Uint8Array): Promise<Uint8Array>;
export const HYBRID_GROUP: number;
/**
 * An injected ML-KEM-768 implementation (FIPS 203). Shapes match `wasmcrypto`'s `mlkem768`:
 */
export type MlKem768 = {
    /**
     *   ML-KEM.KeyGen; `publicKey` is the 1184-byte encapsulation key, `secretKey` the 2400-byte
     *   decapsulation key.
     */
    keygen: (seed?: Uint8Array) => {
        publicKey: Uint8Array;
        secretKey: Uint8Array;
    };
    /**
     * ML-KEM.Encaps; used by a server, exercised by the offline test server.
     */
    encapsulate: (publicKey: Uint8Array) => {
        cipherText: Uint8Array;
        sharedSecret: Uint8Array;
    };
    /**
     *   ML-KEM.Decaps; returns the 32-byte shared secret (implicit rejection on a bad ciphertext).
     */
    decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};
/**
 * The private half kept between generateHybridKeyShare and deriveHybridSecret: the ML-KEM
 * decapsulation key and the X25519 private key. Not a CryptoKey, so callers treat KeyShare's
 * private component opaquely (they already do — it only ever flows back into derivation).
 */
export type HybridPrivate = {
    /**
     * the ML-KEM decapsulation key
     */
    mlkemSecretKey: Uint8Array;
    /**
     * the X25519 private key
     */
    classicalPrivateKey: CryptoKey;
};
