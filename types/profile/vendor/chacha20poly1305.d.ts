export const buildId: "ec15f83a678a";
export namespace chacha20poly1305 {
    /** seal(key32, nonce12, plaintext, aad?) -> ciphertext||tag (RFC 8439 AEAD) */
    function seal(key: any, nonce: any, plaintext: any, aad?: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
    /** open(key32, nonce12, ciphertextAndTag, aad?) -> plaintext; throws on auth failure */
    function open(key: any, nonce: any, ciphertext: any, aad?: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;
}
