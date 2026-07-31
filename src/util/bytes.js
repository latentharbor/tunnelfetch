// Byte plumbing shared by every layer.
//
// The one invariant that matters: nothing here may depend on how the underlying stream happens
// to chunk its data. A parser built on ByteReader must produce identical results when fed one
// byte at a time and when fed the whole message at once — the offline suite asserts exactly that,
// because network fragmentation is adversarial and untestable if the parser can see it.

import { TunnelFetchError, LimitError, codes } from '../errors.js';

const EMPTY = new Uint8Array(0);

/** Raised when the peer stops sending in the middle of a structure we must read whole. */
export class UnexpectedEofError extends TunnelFetchError {
  constructor(wanted, got, what) {
    super('UNEXPECTED_EOF', `stream ended after ${got} of ${wanted} bytes while reading ${what}`, {
      wanted,
      got,
      what,
    });
  }
}

/**
 * Buffered reader over a ReadableStream<Uint8Array>.
 *
 * Returned slices may alias the stream's own chunks; they are never written to by this class and
 * must not be retained beyond the caller's immediate use if memory matters.
 */
export class ByteReader {
  /** @param {ReadableStream<Uint8Array>} readable */
  constructor(readable) {
    this._reader = readable.getReader();
    /** @type {Uint8Array[]} */
    this._chunks = [];
    this._head = 0; // offset into _chunks[0]
    this._len = 0; // total buffered bytes
    this._eof = false;
    this._done = false;
  }

  get buffered() {
    return this._len;
  }

  get atEof() {
    return this._eof && this._len === 0;
  }

  /** Push bytes back to the front. Used when a layer over-reads (e.g. proxy replies with data). */
  unshift(bytes) {
    if (bytes.byteLength === 0) return;
    if (this._head > 0) {
      this._chunks[0] = this._chunks[0].subarray(this._head);
      this._head = 0;
    }
    this._chunks.unshift(bytes);
    this._len += bytes.byteLength;
  }

  /** Pull one more chunk from the source. Returns false at EOF. */
  async _pull() {
    if (this._eof) return false;
    const { value, done } = await this._reader.read();
    if (done) {
      this._eof = true;
      return false;
    }
    if (value && value.byteLength > 0) {
      this._chunks.push(value);
      this._len += value.byteLength;
      return true;
    }
    // A zero-length chunk is legal and carries no data; keep pulling.
    return this._pull();
  }

  /** Take exactly n bytes from the buffer. Caller guarantees _len >= n. */
  _take(n) {
    if (n === 0) return EMPTY;
    const first = this._chunks[0];
    const avail = first.byteLength - this._head;
    if (avail >= n) {
      const out = first.subarray(this._head, this._head + n);
      this._head += n;
      this._len -= n;
      if (this._head === first.byteLength) {
        this._chunks.shift();
        this._head = 0;
      }
      return out;
    }
    const out = new Uint8Array(n);
    let o = 0;
    while (o < n) {
      const c = this._chunks[0];
      const from = this._head;
      const take = Math.min(c.byteLength - from, n - o);
      out.set(c.subarray(from, from + take), o);
      o += take;
      this._head += take;
      this._len -= take;
      if (this._head === c.byteLength) {
        this._chunks.shift();
        this._head = 0;
      }
    }
    return out;
  }

  /**
   * Read exactly n bytes, or throw. This is the workhorse for length-prefixed formats
   * (TLS records, chunked bodies, SOCKS5 replies).
   * @param {number} n
   * @param {string} what described in the error if the stream ends early
   */
  async readExactly(n, what = 'data') {
    if (n < 0 || !Number.isSafeInteger(n)) {
      throw new TunnelFetchError(codes.CONFIG_INVALID, `readExactly(${n}) is not a valid length`);
    }
    while (this._len < n) {
      if (!(await this._pull())) throw new UnexpectedEofError(n, this._len, what);
    }
    return this._take(n);
  }

  /** Read at least 1 and at most n bytes. Returns null at clean EOF. */
  async readSome(n = 65536) {
    while (this._len === 0) {
      if (!(await this._pull())) return null;
    }
    return this._take(Math.min(n, this._len));
  }

  /**
   * Read until `needle` is found, returning everything up to and including it.
   * Used for CRLF-delimited HTTP structures. Fails closed past `maxBytes` so a peer cannot
   * make us buffer without bound.
   * @param {Uint8Array} needle
   * @param {number} maxBytes
   * @param {string} what
   */
  async readUntil(needle, maxBytes, what = 'delimited data') {
    const nl = needle.byteLength;
    if (nl === 0) throw new TunnelFetchError(codes.CONFIG_INVALID, 'readUntil needs a needle');
    let scanned = 0;
    for (;;) {
      // Compact so the scan is over one contiguous view. Delimited structures are small
      // (status lines, header blocks, chunk sizes) and bounded by maxBytes.
      if (this._chunks.length > 1 || this._head > 0) {
        const all = this._take(this._len);
        this._chunks = all.byteLength ? [all] : [];
        this._head = 0;
        this._len = all.byteLength;
      }
      const buf = this._len ? this._chunks[0] : EMPTY;
      const from = Math.max(0, scanned - nl + 1);
      const idx = indexOf(buf, needle, from);
      if (idx >= 0) {
        const end = idx + nl;
        if (end > maxBytes) {
          throw new LimitError(
            codes.LIMIT_HEADER,
            `${what} is ${end} bytes, over the ${maxBytes} byte limit`,
            { bytes: end, limit: maxBytes },
          );
        }
        return this._take(end);
      }
      scanned = buf.byteLength;
      if (scanned > maxBytes) {
        throw new LimitError(
          codes.LIMIT_HEADER,
          `${what} exceeded ${maxBytes} bytes with no delimiter found`,
          { bytes: scanned, limit: maxBytes },
        );
      }
      if (!(await this._pull())) throw new UnexpectedEofError(-1, scanned, what);
    }
  }

  /** Drain everything remaining, up to maxBytes. */
  async readToEnd(maxBytes = Infinity) {
    const parts = [];
    let total = 0;
    for (;;) {
      const c = await this.readSome();
      if (c === null) break;
      total += c.byteLength;
      if (total > maxBytes) {
        throw new LimitError(codes.LIMIT_BODY, `body exceeded ${maxBytes} bytes`, {
          limit: maxBytes,
        });
      }
      parts.push(c);
    }
    return concat(parts, total);
  }

  releaseLock() {
    if (this._done) return;
    this._done = true;
    try {
      this._reader.releaseLock();
    } catch {
      /* already errored or locked elsewhere; nothing useful to do */
    }
  }

  async cancel(reason) {
    if (this._done) return;
    this._done = true;
    try {
      await this._reader.cancel(reason);
    } catch {
      /* the stream may already be errored */
    }
  }
}

/** Buffered writer over a WritableStream<Uint8Array>. */
export class ByteWriter {
  /** @param {WritableStream<Uint8Array>} writable */
  constructor(writable) {
    this._writer = writable.getWriter();
    this._done = false;
  }

  /** @param {Uint8Array} bytes */
  write(bytes) {
    return this._writer.write(bytes);
  }

  /** Write several buffers as one, avoiding per-piece stream overhead. */
  writeAll(parts) {
    let total = 0;
    for (const p of parts) total += p.byteLength;
    return this._writer.write(concat(parts, total));
  }

  releaseLock() {
    if (this._done) return;
    this._done = true;
    try {
      this._writer.releaseLock();
    } catch {
      /* already released */
    }
  }

  async close() {
    if (this._done) return;
    this._done = true;
    try {
      await this._writer.close();
    } catch {
      /* peer may have closed first */
    }
  }

  async abort(reason) {
    if (this._done) return;
    this._done = true;
    try {
      await this._writer.abort(reason);
    } catch {
      /* already errored */
    }
  }
}

// ------------------------------------------------------------------ pure helpers

/** @param {Uint8Array[]} parts */
export function concat(parts, total) {
  if (total === undefined) {
    total = 0;
    for (const p of parts) total += p.byteLength;
  }
  if (parts.length === 1 && parts[0].byteLength === total) return parts[0];
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.byteLength;
  }
  return out;
}

/** Boyer-Moore is not worth it for 1-4 byte needles over small buffers. */
export function indexOf(haystack, needle, from = 0) {
  const n = needle.byteLength;
  const limit = haystack.byteLength - n;
  const first = needle[0];
  outer: for (let i = Math.max(0, from); i <= limit; i++) {
    if (haystack[i] !== first) continue;
    for (let j = 1; j < n; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export function equal(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Comparison whose running time does not depend on where the first difference is.
 * JS cannot truly guarantee constant time (JIT tiering, GC), which is precisely why this package
 * refuses MAC-then-encrypt cipher suites. It is used only where a timing leak would be a
 * nice-to-have for an attacker rather than a decryption oracle: certificate pins and Finished
 * verification, where the compared value is already authenticated or public.
 */
export function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const HEX = '0123456789abcdef';
export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15];
  return s;
}

export function fromHex(hex) {
  const clean = hex.replace(/[\s:]/g, '');
  if (clean.length % 2) throw new TunnelFetchError(codes.CONFIG_INVALID, 'odd-length hex string');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const encoder = new TextEncoder();
export const utf8 = (s) => encoder.encode(s);
/** Latin-1 decode: HTTP header field values are opaque octets, not UTF-8. */
export function latin1(bytes) {
  let s = '';
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/** Big-endian integer writers, the byte order of every protocol in this package. */
export function u8(n) {
  return new Uint8Array([n & 0xff]);
}
export function u16(n) {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}
export function u24(n) {
  return new Uint8Array([(n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export function u32(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
export const readU16 = (b, o = 0) => (b[o] << 8) | b[o + 1];
export const readU24 = (b, o = 0) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];
export const readU32 = (b, o = 0) =>
  ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
