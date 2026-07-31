// Running handshake transcript hash (RFC 8446 s4.4.1).
//
// WebCrypto has no streaming digest, so the raw handshake messages are buffered and re-digested
// on every hash() call. That tradeoff is deliberate: the transcript covers handshake messages
// only, which a real handshake bounds at a few hundred KB of certificates, and hash() is called
// a handful of times per connection — buffering costs one transcript-sized allocation, while a
// hand-rolled incremental SHA-2 in JS would be a fresh piece of security-critical code to get
// wrong. The buffer is still capped so a peer streaming an absurd certificate chain cannot make
// us hold unbounded memory; the record layer's per-message cap fires first in practice.

import { TlsError, codes } from '../errors.js';
import { concat, u8, u24 } from '../util/bytes.js';
import { HANDSHAKE_TYPE } from './constants.js';
import { hashLength } from './keyschedule.js';

export class Transcript {
  /**
   * @param {import('./keyschedule.js').ScheduleHash} hash fixed once the cipher suite is known
   * @param {{ maxBytes?: number }} [opts] transcript buffer cap, default 1 MiB
   */
  constructor(hash, { maxBytes = 1 << 20 } = {}) {
    hashLength(hash); // validate eagerly: a typo'd hash name must not surface at first hash()
    this._hash = hash;
    /** @type {Uint8Array[]} */
    this._chunks = [];
    this._len = 0;
    this._maxBytes = maxBytes;
    /** @type {Uint8Array | null} digest cache, invalidated by update() */
    this._cached = null;
  }

  get bytesBuffered() {
    return this._len;
  }

  /**
   * Append raw handshake message bytes (including the 4-byte message header — the transcript
   * is over complete Handshake structs, never record framing).
   * @param {Uint8Array} bytes
   */
  update(bytes) {
    if (bytes.byteLength === 0) return;
    if (this._len + bytes.byteLength > this._maxBytes) {
      throw new TlsError(codes.TLS_HANDSHAKE,
        `handshake transcript would exceed ${this._maxBytes} bytes`,
        { buffered: this._len, adding: bytes.byteLength, limit: this._maxBytes });
    }
    // Copy: callers hand us subarrays aliasing record buffers they will reuse.
    this._chunks.push(bytes.slice());
    this._len += bytes.byteLength;
    this._cached = null;
  }

  /**
   * Digest of everything appended so far. Does not consume; call as often as needed.
   * @returns {Promise<Uint8Array>}
   */
  async hash() {
    if (!this._cached) {
      this._cached = new Uint8Array(
        await crypto.subtle.digest(this._hash, concat(this._chunks, this._len)),
      );
    }
    return this._cached;
  }

  /**
   * Digest of everything appended so far PLUS `extra`, without appending it.
   *
   * Exists for exactly one caller: the PSK binder after a HelloRetryRequest, which is an HMAC
   * over Transcript-Hash(message_hash(CH1) || HRR || Truncate(CH2)) (RFC 8446 s4.2.11.2). The
   * truncated ClientHello2 must be hashed as a continuation of the real transcript but must
   * never BECOME part of it — the transcript proper gets the full ClientHello2 with its binder,
   * and folding the truncated form in even transiently would leave a window where the two
   * bookkeepings disagree.
   * @param {Uint8Array} extra
   * @returns {Promise<Uint8Array>}
   */
  async hashWith(extra) {
    return new Uint8Array(
      await crypto.subtle.digest(this._hash, concat([...this._chunks, extra], this._len + extra.byteLength)),
    );
  }

  /**
   * HelloRetryRequest transcript substitution (RFC 8446 s4.4.1): when a ServerHello is an HRR,
   * the transcript restarts as a synthetic handshake message
   *
   *   message_hash(0xFE) || uint24 Hash.length || Hash(ClientHello1)
   *
   * so that a stateless server need only remember the hash of the first ClientHello. Call this
   * after ClientHello1 is the only message in the transcript, before appending the HRR itself.
   * @returns {Promise<void>}
   */
  async replaceWithMessageHash() {
    const digest = await this.hash();
    this._chunks = [concat([u8(HANDSHAKE_TYPE.message_hash), u24(digest.byteLength), digest])];
    this._len = this._chunks[0].byteLength;
    this._cached = null;
  }
}
