/**
 * @typedef {object} HpackField
 * @property {string} name already lowercased by the caller — HPACK does not case-fold, and
 *   HTTP/2 forbids uppercase field names on the wire (RFC 9113 s8.2.1)
 * @property {string} value
 * @property {'incremental' | 'without' | 'never'} [indexing] how to represent it when it is not a
 *   full static match. Default 'incremental', which is what curl uses for most fields.
 */
/**
 * Encode an ordered list of header fields into one HPACK block. Order is preserved exactly, which
 * is load-bearing: HTTP/2 requires all pseudo-headers before regular ones, and the pseudo-header
 * ORDER is part of the client fingerprint the caller is matching.
 *
 * @param {HpackField[]} fields
 * @returns {Uint8Array}
 */
export function encodeHeaderBlock(fields: HpackField[]): Uint8Array;
/** Default SETTINGS_HEADER_TABLE_SIZE (RFC 9113 s6.5.2): the size we advertise, so the size the
 *  peer's encoder may fill in our decoder. A size update above this is a COMPRESSION_ERROR. */
export const DEFAULT_HEADER_TABLE_SIZE: 4096;
/**
 * @typedef {object} HpackDecoderOptions
 * @property {number} [maxTableSize] the SETTINGS_HEADER_TABLE_SIZE we advertised; the dynamic
 *   table may not exceed it and a size update above it is fatal. Default 4096.
 * @property {number} [maxHeaderListSize] fail-closed cap on the decoded header list (sum of
 *   name+value+32 per field). Default 262144. We do not advertise this to the peer, so it is a
 *   self-protection bound, not a promise; over it is a LimitError.
 */
/**
 * A stateful HPACK decoder. One per connection per direction: the dynamic table is shared state
 * across every header block on the connection, so a single decoder instance must live as long as
 * the connection does.
 */
export class HpackDecoder {
    /** @param {HpackDecoderOptions} [opts] */
    constructor({ maxTableSize, maxHeaderListSize }?: HpackDecoderOptions);
    /** @type {Array<[string, string, number]>} name, value, entry-size — newest at index 0 */
    _dynamic: Array<[string, string, number]>;
    _size: number;
    _maxSize: number;
    _limit: number;
    _maxHeaderListSize: number;
    /** Current number of entries, exposed for tests that assert eviction. */
    get dynamicLength(): number;
    /**
     * Look up index `i` (RFC 7541 s2.3.3: 1..STATIC_COUNT is static, above that is dynamic,
     * newest first). Fails closed on 0 and on anything past the end of the dynamic table.
     * @param {number} i
     * @returns {[string, string]}
     */
    _lookup(i: number): [string, string];
    /** Insert into the dynamic table, evicting oldest entries until it fits (RFC 7541 s4.4). */
    _insert(name: any, value: any): void;
    /** Apply a dynamic table size update (RFC 7541 s6.3), refusing one above what we advertised. */
    _resize(newSize: any): void;
    /**
     * Decode one header block into an ordered list of [name, value] pairs.
     * @param {Uint8Array} block
     * @returns {Array<[string, string]>}
     */
    decode(block: Uint8Array): Array<[string, string]>;
    /**
     * Shared body of the three literal representations: an optionally indexed name, then a value.
     * @param {(name: string, value: string) => void} add
     * @param {null | ((name: string, value: string) => void)} index insert into the dynamic table, or null
     */
    _literal(block: any, pos: any, prefixBits: any, _fieldIndex: any, add: (name: string, value: string) => void, index: null | ((name: string, value: string) => void)): {
        pos: number;
    };
}
export type HpackField = {
    /**
     * already lowercased by the caller — HPACK does not case-fold, and
     * HTTP/2 forbids uppercase field names on the wire (RFC 9113 s8.2.1)
     */
    name: string;
    value: string;
    /**
     * how to represent it when it is not a
     * full static match. Default 'incremental', which is what curl uses for most fields.
     */
    indexing?: "without" | "incremental" | "never" | undefined;
};
export type HpackDecoderOptions = {
    /**
     * the SETTINGS_HEADER_TABLE_SIZE we advertised; the dynamic
     * table may not exceed it and a size update above it is fatal. Default 4096.
     */
    maxTableSize?: number | undefined;
    /**
     * fail-closed cap on the decoded header list (sum of
     * name+value+32 per field). Default 262144. We do not advertise this to the peer, so it is a
     * self-protection bound, not a promise; over it is a LimitError.
     */
    maxHeaderListSize?: number | undefined;
};
/** RFC 7541 Appendix A. Index 0 is a placeholder so table[i] is the RFC's entry i (1-based). */
export const STATIC_TABLE: string[][];
export const STATIC_COUNT: number;
