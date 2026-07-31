// HPACK Huffman coding (RFC 7541 s5.2 and Appendix B).
//
// The code table is the RFC's verbatim — 256 symbols plus EOS at index 256 — and the decoder is
// deliberately the paranoid kind, because a Huffman string is attacker-controlled input inside a
// header block. RFC 7541 s5.2 names three decoding errors and this decoder raises every one:
//
//   * a decoded EOS symbol (256) is illegal in a string literal,
//   * padding longer than 7 bits is illegal (that many bits could have started another symbol),
//   * padding that is not the most-significant bits of EOS — i.e. not all ones — is illegal.
//
// A decoder that shrugged any of those off would let two peers disagree on what a header said,
// which in HPACK is the same class of ambiguity that request smuggling is in HTTP/1.1.

import { Http2Error, codes } from '../errors.js';

// RFC 7541 Appendix B. HUFFMAN_CODE[sym] is the code right-aligned in an integer of HUFFMAN_LEN[sym]
// bits; index 256 is EOS. Every code fits in 30 bits, so plain numbers suffice (no BigInt).
const HUFFMAN_CODE = [
  0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
  0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
  0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
  0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
  0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
  0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
  0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
  0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
  0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
  0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
  0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
  0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
  0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
  0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
  0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
  0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
  0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
  0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
  0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
  0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
  0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
  0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
  0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
  0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
  0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
  0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
  0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
  0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
  0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
  0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
  0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
  0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
  0x3fffffff,
];

const HUFFMAN_LEN = [
  13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
  28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
  5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
  13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
  15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
  6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
  20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
  24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
  22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
  21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
  26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
  19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
  20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
  26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
  30,
];

const EOS = 256;

/**
 * Bit trie, flat so decoding allocates nothing. Two child arrays index into themselves; a
 * non-negative `sym[node]` marks a leaf. Built once from the code table at module load.
 */
const trie = buildTrie();

function buildTrie() {
  const left = [-1]; // child on bit 0
  const right = [-1]; // child on bit 1
  const sym = [-1];
  let next = 1;
  for (let s = 0; s < HUFFMAN_CODE.length; s++) {
    const code = HUFFMAN_CODE[s];
    const len = HUFFMAN_LEN[s];
    let node = 0;
    for (let i = len - 1; i >= 0; i--) {
      const bit = (code >>> i) & 1;
      const arr = bit ? right : left;
      if (arr[node] === -1) {
        arr[node] = next;
        left[next] = -1;
        right[next] = -1;
        sym[next] = -1;
        next++;
      }
      node = arr[node];
    }
    sym[node] = s;
  }
  return { left, right, sym };
}

/**
 * The number of bytes `bytes` would occupy Huffman-encoded, so a caller can choose the shorter
 * of literal and Huffman exactly the way nghttp2 does (this is what makes curl leave the accept
 * value un-encoded when its Huffman form is not shorter).
 * @param {Uint8Array} bytes
 * @returns {number}
 */
export function huffmanEncodedLength(bytes) {
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) bits += HUFFMAN_LEN[bytes[i]];
  return (bits + 7) >> 3;
}

/**
 * Huffman-encode octets, padding the final byte with the most-significant bits of EOS (all ones)
 * per RFC 7541 s5.2.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function huffmanEncode(bytes) {
  const out = new Uint8Array(huffmanEncodedLength(bytes));
  let o = 0;
  // Bit accumulator holding `nbits` pending bits (nbits stays < 8 between symbols, so the widest
  // intermediate is < 8 + 30 = 38 bits — comfortably inside a double, no 32-bit shift, no BigInt).
  let acc = 0;
  let nbits = 0;
  for (let i = 0; i < bytes.length; i++) {
    const sym = bytes[i];
    acc = acc * 2 ** HUFFMAN_LEN[sym] + HUFFMAN_CODE[sym];
    nbits += HUFFMAN_LEN[sym];
    while (nbits >= 8) {
      nbits -= 8;
      out[o++] = Math.floor(acc / 2 ** nbits) & 0xff;
      acc %= 2 ** nbits; // drop the bits just emitted so acc always holds exactly `nbits` bits
    }
  }
  if (nbits > 0) {
    // Pad the last byte with EOS's leading bits, which are all ones (RFC 7541 s5.2).
    const pad = 8 - nbits;
    out[o++] = (acc * 2 ** pad + (2 ** pad - 1)) & 0xff;
  }
  return out;
}

/**
 * Huffman-decode octets, failing closed on every error RFC 7541 s5.2 names.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function huffmanDecode(bytes) {
  const { left, right, sym } = trie;
  const out = [];
  let node = 0;
  let depth = 0; // bits consumed in the current, still-incomplete symbol
  let allOnes = true; // whether every bit of the current partial symbol has been 1
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    for (let b = 7; b >= 0; b--) {
      const bit = (byte >>> b) & 1;
      node = bit ? right[node] : left[node];
      depth++;
      if (bit === 0) allOnes = false;
      // The trie is a full prefix code, so a walk can never fall off it; node is always valid.
      const s = sym[node];
      if (s !== -1) {
        if (s === EOS) {
          throw new Http2Error(
            codes.HTTP2_COMPRESSION,
            'Huffman string contains the EOS symbol, which RFC 7541 s5.2 forbids in a literal',
          );
        }
        out.push(s);
        node = 0;
        depth = 0;
        allOnes = true;
      }
    }
  }
  if (depth > 0) {
    // Whatever is left must be valid padding: at most 7 bits, and all ones (the EOS prefix).
    if (depth > 7) {
      throw new Http2Error(
        codes.HTTP2_COMPRESSION,
        `Huffman padding is ${depth} bits, over the 7-bit maximum RFC 7541 s5.2 allows`,
        { padBits: depth },
      );
    }
    if (!allOnes) {
      throw new Http2Error(
        codes.HTTP2_COMPRESSION,
        'Huffman padding is not the most-significant bits of EOS (a non-one bit appears in it)',
      );
    }
  }
  return Uint8Array.from(out);
}
