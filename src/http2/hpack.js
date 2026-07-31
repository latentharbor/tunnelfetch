// HPACK (RFC 7541): header compression for HTTP/2.
//
// HPACK is a hostile-input parser and is treated as one throughout. The dynamic table is a
// documented denial-of-service surface (RFC 7541 s7.1, s7.3): a peer can try to make a decoder
// allocate unbounded memory, reference a table slot that does not exist, or blow up a small
// header block into a huge header list. Every one of those is refused here rather than absorbed:
//
//   * the dynamic table is bounded by the size we advertised in SETTINGS (never the peer's wish),
//     and an index outside the valid range is a typed error naming the index and the bound;
//   * the decoded header LIST is bounded independently, because a bounded table still permits a
//     bomb built from references, and a length that disagrees with the buffer is fatal;
//   * a decoded integer is bounded so a run of continuation bytes cannot spin or overflow;
//   * Huffman decoding (huffman.js) rejects invalid padding, so a "valid" block with junk tail
//     bits does not decode to something a stricter peer would read differently.
//
// The encoder is deliberately STATELESS: it references the static table and emits everything else
// as a literal. It never reads its own dynamic table, so its output does not depend on request
// history and is trivially reproducible — which is what lets the offline suite pin it byte for
// byte, and what lets it match curl's first-request encoding exactly. It still emits the
// incremental-indexing opcode where curl does (so the peer's table state, and thus the wire
// fingerprint, matches), it simply never depends on the entries that creates.

import { Http2Error, LimitError, codes } from '../errors.js';
import { concat, utf8 } from '../util/bytes.js';
import { huffmanDecode, huffmanEncode, huffmanEncodedLength } from './huffman.js';

const decoder = new TextDecoder('utf-8', { fatal: false });

/** RFC 7541 Appendix A. Index 0 is a placeholder so table[i] is the RFC's entry i (1-based). */
const STATIC_TABLE = [
  ['', ''],
  [':authority', ''],
  [':method', 'GET'],
  [':method', 'POST'],
  [':path', '/'],
  [':path', '/index.html'],
  [':scheme', 'http'],
  [':scheme', 'https'],
  [':status', '200'],
  [':status', '204'],
  [':status', '206'],
  [':status', '304'],
  [':status', '400'],
  [':status', '404'],
  [':status', '500'],
  ['accept-charset', ''],
  ['accept-encoding', 'gzip, deflate'],
  ['accept-language', ''],
  ['accept-ranges', ''],
  ['accept', ''],
  ['access-control-allow-origin', ''],
  ['age', ''],
  ['allow', ''],
  ['authorization', ''],
  ['cache-control', ''],
  ['content-disposition', ''],
  ['content-encoding', ''],
  ['content-language', ''],
  ['content-length', ''],
  ['content-location', ''],
  ['content-range', ''],
  ['content-type', ''],
  ['cookie', ''],
  ['date', ''],
  ['etag', ''],
  ['expect', ''],
  ['expires', ''],
  ['from', ''],
  ['host', ''],
  ['if-match', ''],
  ['if-modified-since', ''],
  ['if-none-match', ''],
  ['if-range', ''],
  ['if-unmodified-since', ''],
  ['last-modified', ''],
  ['link', ''],
  ['location', ''],
  ['max-forwards', ''],
  ['proxy-authenticate', ''],
  ['proxy-authorization', ''],
  ['range', ''],
  ['referer', ''],
  ['refresh', ''],
  ['retry-after', ''],
  ['server', ''],
  ['set-cookie', ''],
  ['strict-transport-security', ''],
  ['transfer-encoding', ''],
  ['user-agent', ''],
  ['vary', ''],
  ['via', ''],
  ['www-authenticate', ''],
];
const STATIC_COUNT = STATIC_TABLE.length - 1; // 61

/** The overhead RFC 7541 s4.1 charges every dynamic entry, on top of its name and value octets. */
const ENTRY_OVERHEAD = 32;

/** Default SETTINGS_HEADER_TABLE_SIZE (RFC 9113 s6.5.2): the size we advertise, so the size the
 *  peer's encoder may fill in our decoder. A size update above this is a COMPRESSION_ERROR. */
export const DEFAULT_HEADER_TABLE_SIZE = 4096;

// A single integer with many continuation bytes is a spin/overflow attempt; 6 bytes past the
// prefix already covers any length this client will ever see (2^35), so more is refused.
const MAX_INTEGER_CONTINUATION_BYTES = 6;

// ---------------------------------------------------------------------- integer / string coding

/**
 * Decode an HPACK variable-length integer (RFC 7541 s5.1) with an `n`-bit prefix.
 * @param {Uint8Array} buf
 * @param {number} pos index of the prefix byte
 * @param {number} n prefix bit width (1..8)
 * @returns {{ value: number, pos: number }}
 */
function decodeInteger(buf, pos, n) {
  const max = (1 << n) - 1;
  if (pos >= buf.length) {
    throw new Http2Error(codes.HTTP2_COMPRESSION, 'truncated HPACK integer prefix');
  }
  let value = buf[pos] & max;
  pos++;
  if (value < max) return { value, pos };
  let m = 0;
  let bytes = 0;
  for (;;) {
    if (pos >= buf.length) {
      throw new Http2Error(codes.HTTP2_COMPRESSION, 'truncated HPACK integer continuation');
    }
    if (++bytes > MAX_INTEGER_CONTINUATION_BYTES) {
      throw new Http2Error(
        codes.HTTP2_COMPRESSION,
        `HPACK integer has more than ${MAX_INTEGER_CONTINUATION_BYTES} continuation bytes`,
      );
    }
    const b = buf[pos++];
    value += (b & 0x7f) * 2 ** m;
    if (!Number.isSafeInteger(value)) {
      throw new Http2Error(codes.HTTP2_COMPRESSION, 'HPACK integer overflows a safe integer');
    }
    if ((b & 0x80) === 0) break;
    m += 7;
  }
  return { value, pos };
}

/**
 * Decode an HPACK string literal (RFC 7541 s5.2): a Huffman flag, a length, then the octets.
 * @param {Uint8Array} buf
 * @param {number} pos
 * @returns {{ bytes: Uint8Array, pos: number }}
 */
function decodeString(buf, pos) {
  if (pos >= buf.length) {
    throw new Http2Error(codes.HTTP2_COMPRESSION, 'truncated HPACK string');
  }
  const huffman = (buf[pos] & 0x80) !== 0;
  const { value: len, pos: p } = decodeInteger(buf, pos, 7);
  if (p + len > buf.length) {
    throw new Http2Error(
      codes.HTTP2_COMPRESSION,
      `HPACK string length ${len} runs past the end of the header block`,
      { length: len, available: buf.length - p },
    );
  }
  const raw = buf.subarray(p, p + len);
  return { bytes: huffman ? huffmanDecode(raw) : raw.slice(), pos: p + len };
}

/** Encode an HPACK integer with an `n`-bit prefix; `prefixBits` are the high bits of the first byte. */
function encodeInteger(value, n, prefixBits) {
  const max = (1 << n) - 1;
  if (value < max) return Uint8Array.of(prefixBits | value);
  const out = [prefixBits | max];
  let v = value - max;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return Uint8Array.from(out);
}

/** Encode an HPACK string literal, Huffman-coding it only when that is strictly shorter. */
function encodeString(bytes) {
  if (huffmanEncodedLength(bytes) < bytes.length) {
    const packed = huffmanEncode(bytes);
    return concat([encodeInteger(packed.length, 7, 0x80), packed]);
  }
  return concat([encodeInteger(bytes.length, 7, 0x00), bytes]);
}

// ---------------------------------------------------------------------- decoder

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
  constructor({ maxTableSize = DEFAULT_HEADER_TABLE_SIZE, maxHeaderListSize = 262144 } = {}) {
    /** @type {Array<[string, string, number]>} name, value, entry-size — newest at index 0 */
    this._dynamic = [];
    this._size = 0;
    this._maxSize = maxTableSize;
    this._limit = maxTableSize; // the hard ceiling a size update may not exceed
    this._maxHeaderListSize = maxHeaderListSize;
  }

  /** Current number of entries, exposed for tests that assert eviction. */
  get dynamicLength() {
    return this._dynamic.length;
  }

  /**
   * Look up index `i` (RFC 7541 s2.3.3: 1..STATIC_COUNT is static, above that is dynamic,
   * newest first). Fails closed on 0 and on anything past the end of the dynamic table.
   * @param {number} i
   * @returns {[string, string]}
   */
  _lookup(i) {
    if (i === 0) {
      throw new Http2Error(codes.HTTP2_COMPRESSION, 'HPACK index 0 is not a valid table entry');
    }
    if (i <= STATIC_COUNT) return STATIC_TABLE[i];
    const d = i - STATIC_COUNT - 1;
    if (d >= this._dynamic.length) {
      throw new Http2Error(
        codes.HTTP2_COMPRESSION,
        `HPACK index ${i} is out of range (static 1..${STATIC_COUNT}, ` +
          `dynamic holds ${this._dynamic.length})`,
        { index: i, staticCount: STATIC_COUNT, dynamicLength: this._dynamic.length },
      );
    }
    const [name, value] = this._dynamic[d];
    return [name, value];
  }

  /** Insert into the dynamic table, evicting oldest entries until it fits (RFC 7541 s4.4). */
  _insert(name, value) {
    const entrySize = name.length + value.length + ENTRY_OVERHEAD;
    // Adding an entry larger than the whole table empties the table and stores nothing.
    while (this._size + entrySize > this._maxSize && this._dynamic.length > 0) {
      this._size -= this._dynamic.pop()[2];
    }
    if (entrySize <= this._maxSize) {
      this._dynamic.unshift([name, value, entrySize]);
      this._size += entrySize;
    }
  }

  /** Apply a dynamic table size update (RFC 7541 s6.3), refusing one above what we advertised. */
  _resize(newSize) {
    if (newSize > this._limit) {
      throw new Http2Error(
        codes.HTTP2_COMPRESSION,
        `dynamic table size update to ${newSize} exceeds the advertised limit ${this._limit}`,
        { requested: newSize, limit: this._limit },
      );
    }
    this._maxSize = newSize;
    while (this._size > this._maxSize && this._dynamic.length > 0) {
      this._size -= this._dynamic.pop()[2];
    }
  }

  /**
   * Decode one header block into an ordered list of [name, value] pairs.
   * @param {Uint8Array} block
   * @returns {Array<[string, string]>}
   */
  decode(block) {
    const out = [];
    let listSize = 0;
    let pos = 0;
    // A dynamic table size update is only legal before any header field in the block (s4.2).
    let sawField = false;
    const add = (name, value) => {
      listSize += name.length + value.length + ENTRY_OVERHEAD;
      if (listSize > this._maxHeaderListSize) {
        throw new LimitError(
          codes.HTTP2_HEADER,
          `decoded header list reached ${listSize} bytes, over the ` +
            `${this._maxHeaderListSize} byte limit`,
          { limit: this._maxHeaderListSize },
        );
      }
      out.push([name, value]);
    };

    while (pos < block.length) {
      const first = block[pos];
      if (first & 0x80) {
        // 6.1 Indexed Header Field.
        const { value: idx, pos: p } = decodeInteger(block, pos, 7);
        pos = p;
        const [name, value] = this._lookup(idx);
        add(name, value);
        sawField = true;
      } else if (first & 0x40) {
        // 6.2.1 Literal with Incremental Indexing.
        ({ pos } = this._literal(block, pos, 6, out.length, add, (n, v) => this._insert(n, v)));
        sawField = true;
      } else if (first & 0x20) {
        // 6.3 Dynamic Table Size Update.
        if (sawField) {
          throw new Http2Error(
            codes.HTTP2_COMPRESSION,
            'dynamic table size update must precede every header field in the block (RFC 7541 s4.2)',
          );
        }
        const { value: newSize, pos: p } = decodeInteger(block, pos, 5);
        pos = p;
        this._resize(newSize);
      } else {
        // 6.2.2 Literal without Indexing (0x00) and 6.2.3 Literal Never Indexed (0x10) — both
        // 4-bit prefix, neither touches the dynamic table.
        ({ pos } = this._literal(block, pos, 4, out.length, add, null));
        sawField = true;
      }
    }
    return out;
  }

  /**
   * Shared body of the three literal representations: an optionally indexed name, then a value.
   * @param {(name: string, value: string) => void} add
   * @param {null | ((name: string, value: string) => void)} index insert into the dynamic table, or null
   */
  _literal(block, pos, prefixBits, _fieldIndex, add, index) {
    const { value: nameIdx, pos: p1 } = decodeInteger(block, pos, prefixBits);
    let name;
    let p = p1;
    if (nameIdx === 0) {
      const s = decodeString(block, p);
      name = decoder.decode(s.bytes);
      p = s.pos;
    } else {
      name = this._lookup(nameIdx)[0];
    }
    const vs = decodeString(block, p);
    const value = decoder.decode(vs.bytes);
    add(name, value);
    if (index) index(name, value);
    return { pos: vs.pos };
  }
}

// ---------------------------------------------------------------------- encoder

/**
 * Find a static-table entry. Returns `{ index }` for a full name+value match, `{ nameIndex }`
 * for a name-only match, or null. The dynamic table is intentionally not consulted; see the
 * module header for why a stateless encoder is the right trade here.
 */
function staticLookup(name, value) {
  let nameIndex = 0;
  for (let i = 1; i <= STATIC_COUNT; i++) {
    if (STATIC_TABLE[i][0] === name) {
      if (STATIC_TABLE[i][1] === value) return { index: i };
      if (nameIndex === 0) nameIndex = i;
    }
  }
  return nameIndex ? { nameIndex } : null;
}

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
export function encodeHeaderBlock(fields) {
  const parts = [];
  for (const f of fields) {
    const name = f.name;
    const valueBytes = utf8(f.value);
    const found = staticLookup(name, f.value);
    if (found && found.index !== undefined) {
      // A full match is the same one byte for everyone; curl uses it for :method and :scheme.
      parts.push(encodeInteger(found.index, 7, 0x80));
      continue;
    }
    const indexing = f.indexing ?? 'incremental';
    // prefix pattern and width per representation (RFC 7541 s6.2).
    const [prefixBits, prefixWidth] =
      indexing === 'incremental' ? [0x40, 6] : indexing === 'never' ? [0x10, 4] : [0x00, 4];
    const nameIndex = found ? found.nameIndex : 0;
    if (nameIndex) {
      parts.push(encodeInteger(nameIndex, prefixWidth, prefixBits));
    } else {
      parts.push(encodeInteger(0, prefixWidth, prefixBits), encodeString(utf8(name)));
    }
    parts.push(encodeString(valueBytes));
  }
  return concat(parts);
}

export { STATIC_TABLE, STATIC_COUNT };
