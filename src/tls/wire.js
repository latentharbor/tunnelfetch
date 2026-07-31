// TLS wire primitives: length-prefixed vectors, in both directions.
//
// TLS is almost entirely nested length-prefixed vectors, and nearly every historical parsing CVE
// in TLS stacks comes from trusting one of those lengths. So the reader here has exactly one
// policy: a length that does not fit inside its parent is an error, and a structure with bytes
// left over when it should be exhausted is an error. Never "read what you can".

import { TlsError, codes } from '../errors.js';
import { concat, u8, u16, u24 } from '../util/bytes.js';

/** Sequential reader over a byte range with hard bounds. */
export class Cursor {
  /**
   * @param {Uint8Array} bytes
   * @param {string} what named in every error so a failure says which structure was malformed
   */
  constructor(bytes, what = 'structure') {
    this.bytes = bytes;
    this.pos = 0;
    this.what = what;
  }

  get remaining() {
    return this.bytes.byteLength - this.pos;
  }

  get done() {
    return this.pos >= this.bytes.byteLength;
  }

  _need(n, field) {
    if (n < 0 || this.remaining < n) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `${this.what}: needed ${n} bytes for ${field} but only ${this.remaining} remain ` +
          `at offset ${this.pos} of ${this.bytes.byteLength}`,
        { what: this.what, field, needed: n, remaining: this.remaining, offset: this.pos },
      );
    }
  }

  u8(field = 'uint8') {
    this._need(1, field);
    return this.bytes[this.pos++];
  }

  u16(field = 'uint16') {
    this._need(2, field);
    const v = (this.bytes[this.pos] << 8) | this.bytes[this.pos + 1];
    this.pos += 2;
    return v;
  }

  u24(field = 'uint24') {
    this._need(3, field);
    const v =
      (this.bytes[this.pos] << 16) | (this.bytes[this.pos + 1] << 8) | this.bytes[this.pos + 2];
    this.pos += 3;
    return v;
  }

  u32(field = 'uint32') {
    this._need(4, field);
    const b = this.bytes;
    const v =
      ((b[this.pos] << 24) | (b[this.pos + 1] << 16) | (b[this.pos + 2] << 8) | b[this.pos + 3]) >>>
      0;
    this.pos += 4;
    return v;
  }

  /** Fixed-length opaque bytes. Returns a view into the original buffer, never a copy. */
  take(n, field = 'opaque') {
    this._need(n, field);
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /** A vector whose length is carried in `lenBytes` (1, 2 or 3) leading octets. */
  vector(lenBytes, field = 'vector') {
    const n = lenBytes === 1 ? this.u8(`${field} length`)
      : lenBytes === 2 ? this.u16(`${field} length`)
      : this.u24(`${field} length`);
    return this.take(n, field);
  }

  /** Like `vector`, but hands back a Cursor so nested structures inherit the bound. */
  sub(lenBytes, field = 'vector') {
    return new Cursor(this.vector(lenBytes, field), `${this.what}.${field}`);
  }

  /**
   * Assert nothing is left. Trailing data inside a length-delimited structure means our idea of
   * the structure and the peer's disagree, which is exactly when to stop rather than guess.
   */
  end(field = 'structure') {
    if (!this.done) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `${this.what}: ${this.remaining} trailing bytes after ${field}`,
        { what: this.what, field, trailing: this.remaining },
      );
    }
  }
}

/** Accumulating writer. Kept dumb: correctness of lengths comes from `vector()` below. */
export class Builder {
  constructor() {
    /** @type {Uint8Array[]} */
    this.parts = [];
    this.length = 0;
  }

  push(bytes) {
    if (bytes.byteLength) {
      this.parts.push(bytes);
      this.length += bytes.byteLength;
    }
    return this;
  }

  u8(n) {
    return this.push(u8(n));
  }
  u16(n) {
    return this.push(u16(n));
  }
  u24(n) {
    return this.push(u24(n));
  }

  /**
   * Write `body` prefixed by its length in `lenBytes` octets. Taking the body as bytes rather
   * than back-patching a placeholder means a length can never drift from what follows it.
   */
  vector(lenBytes, body) {
    const n = body.byteLength;
    const max = lenBytes === 1 ? 0xff : lenBytes === 2 ? 0xffff : 0xffffff;
    if (n > max) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `vector of ${n} bytes does not fit in a ${lenBytes}-byte length prefix (max ${max})`,
        { length: n, lenBytes, max },
      );
    }
    if (lenBytes === 1) this.u8(n);
    else if (lenBytes === 2) this.u16(n);
    else this.u24(n);
    return this.push(body);
  }

  build() {
    return concat(this.parts, this.length);
  }
}

/** Convenience: build a length-prefixed vector standalone. */
export function vector(lenBytes, body) {
  return new Builder().vector(lenBytes, body).build();
}

/** Encode a handshake message: 1-byte type, 3-byte length, body. */
export function handshakeMessage(type, body) {
  return new Builder().u8(type).vector(3, body).build();
}
