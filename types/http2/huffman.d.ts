/**
 * The number of bytes `bytes` would occupy Huffman-encoded, so a caller can choose the shorter
 * of literal and Huffman exactly the way nghttp2 does (this is what makes curl leave the accept
 * value un-encoded when its Huffman form is not shorter).
 * @param {Uint8Array} bytes
 * @returns {number}
 */
export function huffmanEncodedLength(bytes: Uint8Array): number;
/**
 * Huffman-encode octets, padding the final byte with the most-significant bits of EOS (all ones)
 * per RFC 7541 s5.2.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function huffmanEncode(bytes: Uint8Array): Uint8Array;
/**
 * Huffman-decode octets, failing closed on every error RFC 7541 s5.2 names.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function huffmanDecode(bytes: Uint8Array): Uint8Array;
