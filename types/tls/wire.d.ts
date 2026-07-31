/**
 * Convenience: build a length-prefixed vector standalone.
 * @param {1 | 2 | 3} lenBytes
 * @param {Uint8Array} body
 * @returns {Uint8Array}
 */
export function vector(lenBytes: 1 | 2 | 3, body: Uint8Array): Uint8Array;
/**
 * Encode a handshake message: 1-byte type, 3-byte length, body.
 * @param {number} type
 * @param {Uint8Array} body
 * @returns {Uint8Array}
 */
export function handshakeMessage(type: number, body: Uint8Array): Uint8Array;
/** Sequential reader over a byte range with hard bounds. */
export class Cursor {
    /**
     * @param {Uint8Array} bytes
     * @param {string} what named in every error so a failure says which structure was malformed
     */
    constructor(bytes: Uint8Array, what?: string);
    bytes: Uint8Array<ArrayBufferLike>;
    pos: number;
    what: string;
    get remaining(): number;
    get done(): boolean;
    /**
     * @param {number} n
     * @param {string} field
     */
    _need(n: number, field: string): void;
    /**
     * @param {string} [field]
     * @returns {number}
     */
    u8(field?: string): number;
    /**
     * @param {string} [field]
     * @returns {number}
     */
    u16(field?: string): number;
    /**
     * @param {string} [field]
     * @returns {number}
     */
    u24(field?: string): number;
    /**
     * @param {string} [field]
     * @returns {number}
     */
    u32(field?: string): number;
    /**
     * Fixed-length opaque bytes. Returns a view into the original buffer, never a copy.
     * @param {number} n
     * @param {string} [field]
     * @returns {Uint8Array}
     */
    take(n: number, field?: string): Uint8Array;
    /**
     * A vector whose length is carried in `lenBytes` (1, 2 or 3) leading octets.
     * @param {1 | 2 | 3} lenBytes
     * @param {string} [field]
     * @returns {Uint8Array}
     */
    vector(lenBytes: 1 | 2 | 3, field?: string): Uint8Array;
    /**
     * Like `vector`, but hands back a Cursor so nested structures inherit the bound.
     * @param {1 | 2 | 3} lenBytes
     * @param {string} [field]
     * @returns {Cursor}
     */
    sub(lenBytes: 1 | 2 | 3, field?: string): Cursor;
    /**
     * Assert nothing is left. Trailing data inside a length-delimited structure means our idea of
     * the structure and the peer's disagree, which is exactly when to stop rather than guess.
     * @param {string} [field]
     */
    end(field?: string): void;
}
/** Accumulating writer. Kept dumb: correctness of lengths comes from `vector()` below. */
export class Builder {
    /** @type {Uint8Array[]} */
    parts: Uint8Array[];
    length: number;
    /**
     * @param {Uint8Array} bytes
     * @returns {this}
     */
    push(bytes: Uint8Array): this;
    /** @param {number} n @returns {this} */
    u8(n: number): this;
    /** @param {number} n @returns {this} */
    u16(n: number): this;
    /** @param {number} n @returns {this} */
    u24(n: number): this;
    /**
     * Write `body` prefixed by its length in `lenBytes` octets. Taking the body as bytes rather
     * than back-patching a placeholder means a length can never drift from what follows it.
     * @param {1 | 2 | 3} lenBytes
     * @param {Uint8Array} body
     * @returns {this}
     */
    vector(lenBytes: 1 | 2 | 3, body: Uint8Array): this;
    /** @returns {Uint8Array} */
    build(): Uint8Array;
}
