// Byte plumbing shared by every layer.
//
// The one invariant that matters: nothing here may depend on how the underlying stream happens
// to chunk its data. A parser built on ByteReader must produce identical results when fed one
// byte at a time and when fed the whole message at once — the offline suite asserts exactly that,
// because network fragmentation is adversarial and untestable if the parser can see it.

import { TunnelFetchError, LimitError, codes } from '../errors.js';

const EMPTY = new Uint8Array(0);

/**
 * View size for BYOB pulls. A BYOB read resolves as soon as at least one byte is available —
 * measured on the target runtime's sockets filling anywhere from 19 bytes to the full view —
 * so a large view never delays delivery; it only lets bytes the transport has already buffered
 * arrive in one crossing instead of many.
 */
// Swept on the edge, ms of CPU for a 1 MB body at the record layer, p50 of n>=7 in one isolate,
// each column an independent path against the same origin:
//
//                    8 KiB   16 KiB   32 KiB   64 KiB   256 KiB
//     direct           21      20       18       22        40
//     proxy A          51      61       61       89       152
//     proxy B          68      74        -      102         -
//
// Monotonic on both proxies, and shallow on the direct path: too LARGE is what costs, because a
// BYOB read resolves the instant any byte exists and never waits to fill, so a view bigger than
// what the transport hands over per read is allocation that is never used. Average fill measured
// over a 4 MB body: 37 KB direct, 8 KB through a proxy — which is why the two paths want different
// numbers and why the proxied one wants a small one.
//
// 16 KiB is within ~20% of the best figure on all three paths; the 64 KiB that used to sit here is
// up to 45% off. It is also exactly one TLS record, which is the unit the caller above asks for.
//
// The previous value came from a sweep captioned "against a real proxied socket" that reported a
// clean U with its floor at 64 KiB. That sweep measured nothing: openTunnel wrapped the socket in a
// plain ReadableStream, so the record layer could not take a BYOB reader on any proxied connection
// and this constant was never read on that path. The four numbers were four samples of one
// configuration. See proxy/tunnel.js, which is where that was fixed.
const BYOB_PULL_BYTES = 16384;

/** Raised when the peer stops sending in the middle of a structure we must read whole. */
export class UnexpectedEofError extends TunnelFetchError {
  /**
   * @param {number} wanted bytes the structure needed (-1 when scanning for a delimiter)
   * @param {number} got bytes actually buffered when the stream ended
   * @param {string} what the structure being read, named in the message
   */
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
 * Returned slices may alias the stream's own chunks (or, on the BYOB path, buffers this class
 * allocated and will never touch again); they are never written to by this class and must not
 * be retained beyond the caller's immediate use if memory matters.
 *
 * When the source is a byte stream — on the target runtime, a socket's readable is one — the
 * reader pulls with BYOB reads instead of taking the source's own chunking. This is measured, not
 * stylistic: the runtime delivers socket data in chunks of at most 4096 bytes, ~1200 of them for a
 * 4 MB body, and every chunk is a runtime/JS boundary crossing; a BYOB read collects several of
 * them into one.
 *
 * How MANY it collects is the transport's decision, not the view's. A BYOB read resolves the
 * instant any byte is available and never waits to fill, so the view is a ceiling that is normally
 * not reached: measured over a 4 MB body, 37 KB average fill on a direct socket and 8 KB through a
 * proxy, whatever the view size. Sizing the view far above that buys nothing and costs the
 * allocation — see BYOB_PULL_BYTES. Sources that are not byte streams (every in-process
 * ReadableStream in this package and its tests) take the default-reader path unchanged.
 */
export class ByteReader {
  /**
   * @param {ReadableStream<Uint8Array>} readable
   * @param {number} [pullBytes] size of each BYOB view pulled from the source. Tunable because the
   *   right value depends on how much the transport hands over per read, and that differs by a
   *   factor of four between a direct socket and a proxied one — see BYOB_PULL_BYTES for the sweep.
   *   Ignored on sources that are not byte streams, which take the default-reader path.
   */
  constructor(readable, pullBytes = BYOB_PULL_BYTES) {
    this._pullBytes = pullBytes > 0 ? pullBytes : BYOB_PULL_BYTES;
    /** @type {ReadableStreamBYOBReader | null} */
    this._byob = null;
    try {
      this._byob = /** @type {any} */ (readable).getReader({ mode: 'byob' });
      this._reader = this._byob;
    } catch {
      this._reader = readable.getReader();
    }
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

  /**
   * Push bytes back to the front. Used when a layer over-reads (e.g. proxy replies with data).
   * @param {Uint8Array} bytes
   */
  unshift(bytes) {
    if (bytes.byteLength === 0) return;
    if (this._head > 0) {
      this._chunks[0] = this._chunks[0].subarray(this._head);
      this._head = 0;
    }
    this._chunks.unshift(bytes);
    this._len += bytes.byteLength;
  }

  /**
   * Pull one more chunk from the source. Returns false at EOF.
   * The BYOB view is freshly allocated per read and never reused: _take hands out subarrays of
   * buffered chunks, so recycling a view would rewrite bytes a parser already holds.
   * @returns {Promise<boolean>} annotated because the tail-recursive skip of empty chunks
   *   defeats return-type inference
   */
  async _pull() {
    if (this._eof) return false;
    const { value, done } = this._byob
      ? await this._byob.read(new Uint8Array(this._pullBytes))
      : await this._reader.read();
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

  /**
   * Take exactly n bytes from the buffer. Caller guarantees _len >= n.
   * @param {number} n
   * @returns {Uint8Array}
   */
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
   * @param {string} [what] described in the error if the stream ends early
   * @returns {Promise<Uint8Array>}
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

  /**
   * Read at least 1 and at most n bytes. Returns null at clean EOF.
   * @param {number} [n]
   * @returns {Promise<Uint8Array | null>}
   */
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
   * @param {string} [what]
   * @returns {Promise<Uint8Array>}
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

  /**
   * Drain everything remaining, up to maxBytes.
   * @param {number} [maxBytes]
   * @returns {Promise<Uint8Array>}
   */
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

  /** @param {unknown} [reason] */
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

  /**
   * @param {Uint8Array} bytes
   * @returns {Promise<void>}
   */
  write(bytes) {
    return this._writer.write(bytes);
  }

  /**
   * Write several buffers as one, avoiding per-piece stream overhead.
   * @param {Uint8Array[]} parts
   * @returns {Promise<void>}
   */
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

  /** @param {unknown} [reason] */
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

/**
 * @param {Uint8Array[]} parts
 * @param {number} [total] byte total, when the caller already counted; computed otherwise
 * @returns {Uint8Array}
 */
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

/**
 * Boyer-Moore is not worth it for 1-4 byte needles over small buffers.
 * @param {Uint8Array} haystack
 * @param {Uint8Array} needle
 * @param {number} [from]
 * @returns {number} index of the first occurrence at or after `from`, or -1
 */
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

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
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
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  // Prefer the runtime's own, which is compiled rather than interpreted and therefore actually has
  // the property this function is named for. `crypto.subtle.timingSafeEqual` is a non-standard
  // Cloudflare extension, so it is FEATURE-DETECTED rather than assumed — this package runs on
  // Node, Deno and Bun as well, and inferring a capability from a runtime name is the mistake it
  // refuses to make everywhere else. Detected once, at module load, because doing it per call would
  // put a property lookup on a path whose whole point is uniform timing.
  if (NATIVE_TIMING_SAFE_EQUAL) return NATIVE_TIMING_SAFE_EQUAL(a, b);
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * The runtime's constant-time compare, bound once, or null where there is none.
 *
 * Bound with a probe rather than a typeof check: a property that exists but throws on real input
 * would otherwise be discovered inside a TLS Finished verification, where the failure mode is a
 * dead connection on a path that is supposed to be the careful one.
 */
const NATIVE_TIMING_SAFE_EQUAL = (() => {
  const fn = globalThis.crypto?.subtle?.timingSafeEqual;
  if (typeof fn !== 'function') return null;
  try {
    const one = Uint8Array.of(1, 2, 3);
    const two = Uint8Array.of(1, 2, 4);
    if (fn.call(globalThis.crypto.subtle, one, one) !== true) return null;
    if (fn.call(globalThis.crypto.subtle, one, two) !== false) return null;
  } catch {
    return null;
  }
  return (a, b) => fn.call(globalThis.crypto.subtle, a, b);
})();

const HEX = '0123456789abcdef';
/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15];
  return s;
}

/**
 * @param {string} hex whitespace and ':' separators tolerated
 * @returns {Uint8Array}
 */
export function fromHex(hex) {
  const clean = hex.replace(/[\s:]/g, '');
  if (clean.length % 2) throw new TunnelFetchError(codes.CONFIG_INVALID, 'odd-length hex string');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const encoder = new TextEncoder();
/** @type {(s: string) => Uint8Array} */
export const utf8 = (s) => encoder.encode(s);
/**
 * Latin-1 decode: HTTP header field values are opaque octets, not UTF-8.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function latin1(bytes) {
  let s = '';
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

/**
 * Big-endian integer writers, the byte order of every protocol in this package.
 * @param {number} n
 * @returns {Uint8Array}
 */
export function u8(n) {
  return new Uint8Array([n & 0xff]);
}
/** @param {number} n @returns {Uint8Array} */
export function u16(n) {
  return new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
}
/** @param {number} n @returns {Uint8Array} */
export function u24(n) {
  return new Uint8Array([(n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
/** @param {number} n @returns {Uint8Array} */
export function u32(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
/** Big-endian integer readers over a byte view at offset `o`. */
/** @type {(b: Uint8Array, o?: number) => number} */
export const readU16 = (b, o = 0) => (b[o] << 8) | b[o + 1];
/** @type {(b: Uint8Array, o?: number) => number} */
export const readU24 = (b, o = 0) => (b[o] << 16) | (b[o + 1] << 8) | b[o + 2];
/** @type {(b: Uint8Array, o?: number) => number} */
export const readU32 = (b, o = 0) =>
  ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
