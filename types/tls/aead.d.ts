/**
 * TLS 1.3 per-record nonce: the 64-bit sequence number left-padded to the IV length, XORed
 * with the static IV. Exported so the tests can pin the construction independently of a full
 * encrypt round trip.
 * @param {Uint8Array} iv
 * @param {number | bigint} seq
 * @returns {Uint8Array}
 */
export function buildNonce(iv: Uint8Array, seq: number | bigint): Uint8Array;
/**
 * Record protection for one direction under one key. `encrypt` returns the encrypted record
 * body ready for framing; `decrypt` either returns authenticated plaintext (with the inner
 * content type under 1.3, the header type under 1.2) or throws TLS_RECORD — never garbage.
 * @typedef {object} Aead
 * @property {number} version
 * @property {(seq: number | bigint, type: number, plaintext: Uint8Array,
 *   opts?: { padding?: number }) => Promise<Uint8Array>} encrypt
 * @property {(seq: number | bigint, body: Uint8Array, header: Uint8Array)
 *   => Promise<{ type: number, plaintext: Uint8Array }>} decrypt
 */
/**
 * @typedef {object} AeadOptions
 * @property {number} [version] `TLS13` (default) or `TLS12`; picks nonce and AAD construction
 * @property {number} cipher cipher suite id, must have CIPHER_PARAMS
 * @property {Uint8Array} key
 * @property {Uint8Array} iv the 12-byte static IV for TLS 1.3, the 4-byte implicit salt for
 *   TLS 1.2
 */
/**
 * Create record protection for one direction under one key. A new key (handshake -> application,
 * KeyUpdate) means a new instance; sequence numbers restart with it.
 *
 * @param {AeadOptions} opts
 * @returns {Promise<Aead>}
 */
export function createAead({ version, cipher, key, iv }: AeadOptions): Promise<Aead>;
/**
 * Record protection for one direction under one key. `encrypt` returns the encrypted record
 * body ready for framing; `decrypt` either returns authenticated plaintext (with the inner
 * content type under 1.3, the header type under 1.2) or throws TLS_RECORD — never garbage.
 */
export type Aead = {
    version: number;
    encrypt: (seq: number | bigint, type: number, plaintext: Uint8Array, opts?: {
        padding?: number;
    }) => Promise<Uint8Array>;
    decrypt: (seq: number | bigint, body: Uint8Array, header: Uint8Array) => Promise<{
        type: number;
        plaintext: Uint8Array;
    }>;
};
export type AeadOptions = {
    /**
     * `TLS13` (default) or `TLS12`; picks nonce and AAD construction
     */
    version?: number | undefined;
    /**
     * cipher suite id, must have CIPHER_PARAMS
     */
    cipher: number;
    key: Uint8Array;
    /**
     * the 12-byte static IV for TLS 1.3, the 4-byte implicit salt for
     * TLS 1.2
     */
    iv: Uint8Array;
};
