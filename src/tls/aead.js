// AEAD record protection: nonce construction, inner-plaintext framing, both TLS versions.
//
// AES-GCM is the only AEAD here (see constants.js for why), driven through WebCrypto. The
// runtime's AES-GCM rejects on tag mismatch rather than returning unauthenticated bytes, which
// is what makes the fail-closed contract below possible: decrypt() either returns authenticated
// plaintext or throws TLS_RECORD, never garbage.
//
// Sequence numbers are the caller's state (per direction, reset to zero on every key change —
// record.js owns the counters), but their interpretation is fixed here:
//
//   TLS 1.3 (RFC 8446 s5.3): nonce = static_iv XOR seq, with seq left-padded to iv length.
//   TLS 1.2 (RFC 5288):      nonce = 4-byte implicit salt || 8-byte explicit nonce; the
//                            explicit part travels on the wire. We send seq as the explicit
//                            nonce (the SHOULD of RFC 5288) but accept whatever the peer sent,
//                            because the AAD — not the nonce — carries the implicit counter.
//
// Sequence numbers are 64-bit. They are handled as BigInt precisely because a Number-based
// counter would silently lose precision past 2^53 and eventually reuse a nonce, which with GCM
// forfeits both confidentiality and integrity. Reaching 2^64-1 throws instead of wrapping.

import { TlsError, TlsUnsupportedError, codes, hex16 } from '../errors.js';
import { concat, u8, u16 } from '../util/bytes.js';
import {
  CIPHER_PARAMS, CIPHER_NAME, MAX_PLAINTEXT, LEGACY_VERSION, TLS12, TLS13,
} from './constants.js';

const SEQ_MAX = (1n << 64n) - 1n; // the value at which the counter must not be used

/** @param {number | bigint} seq */
function checkSeq(seq) {
  const s = typeof seq === 'bigint' ? seq : BigInt(seq);
  if (s < 0n) throw new TlsError(codes.CONFIG_INVALID, `negative sequence number ${s}`);
  if (s >= SEQ_MAX) {
    // One shy of the full space: at 2^64-1 the *next* record would wrap to nonce 0. Refusing
    // the last value makes "increment then check" ordering bugs unable to reuse a nonce.
    throw new TlsError(codes.TLS_RECORD,
      'record sequence number reached 2^64-1; the connection must rekey, not wrap',
      { seq: s.toString() });
  }
  return s;
}

/**
 * TLS 1.3 per-record nonce: the 64-bit sequence number left-padded to the IV length, XORed
 * with the static IV. Exported so the tests can pin the construction independently of a full
 * encrypt round trip.
 * @param {Uint8Array} iv
 * @param {number | bigint} seq
 * @returns {Uint8Array}
 */
export function buildNonce(iv, seq) {
  let s = checkSeq(seq);
  const nonce = iv.slice();
  for (let i = nonce.byteLength - 1; i >= nonce.byteLength - 8 && i >= 0; i--) {
    nonce[i] ^= Number(s & 0xffn);
    s >>= 8n;
  }
  return nonce;
}

/** The 64-bit sequence number as 8 big-endian bytes (TLS 1.2 explicit nonce and AAD). */
function seq64(seq) {
  let s = checkSeq(seq);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return out;
}

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
export async function createAead({ version = TLS13, cipher, key, iv }) {
  const params = CIPHER_PARAMS[cipher];
  if (!params || params.hash === undefined) {
    throw new TlsUnsupportedError(codes.TLS_CIPHER_UNSUPPORTED,
      `cipher suite ${hex16(cipher)} (${CIPHER_NAME[cipher] ?? 'unknown'}) has no AEAD parameters`,
      { cipher });
  }
  if (version !== TLS12 && version !== TLS13) {
    throw new TlsError(codes.CONFIG_INVALID, `AEAD version ${hex16(version)} is not TLS 1.2/1.3`,
      { version });
  }
  const { keyLen, ivLen, tagLen, fixedIvLen } = params;
  const wantIv = version === TLS13 ? ivLen : fixedIvLen;
  if (key.byteLength !== keyLen) {
    throw new TlsError(codes.CONFIG_INVALID,
      `key is ${key.byteLength} bytes; ${CIPHER_NAME[cipher]} needs ${keyLen}`, { cipher });
  }
  if (iv.byteLength !== wantIv) {
    throw new TlsError(codes.CONFIG_INVALID,
      `iv is ${iv.byteLength} bytes; ${CIPHER_NAME[cipher]} needs ${wantIv} for this version`,
      { cipher, version });
  }
  const gcmKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false,
    ['encrypt', 'decrypt']);
  const staticIv = iv.slice(); // defensive copy: the caller may zero or reuse its buffer

  const tagFailure = () => new TlsError(codes.TLS_RECORD,
    'AEAD authentication failed: record tag or additional data did not verify', {});

  if (version === TLS13) {
    return {
      version,
      /**
       * Returns the encrypted record body (ciphertext + tag). The matching wire header is
       * always `17 03 03 <len>`; the AAD here is built from the same rule, so a caller that
       * frames differently will fail to interoperate rather than succeed unauthenticated.
       */
      async encrypt(seq, type, plaintext, { padding = 0 } = {}) {
        if (!Number.isInteger(padding) || padding < 0) {
          throw new TlsError(codes.CONFIG_INVALID,
            `padding ${padding} is not a non-negative integer`);
        }
        if (plaintext.byteLength > MAX_PLAINTEXT) {
          throw new TlsError(codes.CONFIG_INVALID,
            `plaintext of ${plaintext.byteLength} bytes exceeds ${MAX_PLAINTEXT}; fragment first`,
            { length: plaintext.byteLength });
        }
        // TLSInnerPlaintext = content || content_type || zero padding, capped at 2^14 + 1.
        const room = MAX_PLAINTEXT - plaintext.byteLength;
        const pad = Math.min(padding, room);
        const inner = new Uint8Array(plaintext.byteLength + 1 + pad);
        inner.set(plaintext, 0);
        inner[plaintext.byteLength] = type;
        const aad = concat([u8(23), u16(LEGACY_VERSION), u16(inner.byteLength + tagLen)]);
        const nonce = buildNonce(staticIv, seq);
        const ct = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: tagLen * 8 },
          gcmKey, inner);
        return new Uint8Array(ct);
      },

      /**
       * @param {Uint8Array} body ciphertext + tag as read from the wire
       * @param {Uint8Array} header the 5 record-header bytes — they ARE the AAD (RFC 8446 s5.2)
       */
      async decrypt(seq, body, header) {
        if (header.byteLength !== 5) {
          throw new TlsError(codes.CONFIG_INVALID,
            `AAD must be the 5 header bytes, got ${header.byteLength}`);
        }
        // Minimum: tag plus one byte, because a valid inner plaintext holds at least the type.
        if (body.byteLength < tagLen + 1) {
          throw new TlsError(codes.TLS_RECORD,
            `encrypted record body of ${body.byteLength} bytes is shorter than ` +
            `tag+1 (${tagLen + 1})`,
            { length: body.byteLength });
        }
        const nonce = buildNonce(staticIv, seq);
        let inner;
        try {
          inner = new Uint8Array(await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: tagLen * 8 },
            gcmKey, body));
        } catch {
          throw tagFailure();
        }
        // Strip the zero padding to expose the real content type (RFC 8446 s5.4). Scanning
        // from the end is not constant time, but padding length is not secret from an attacker
        // who can measure it anyway via record timing; the RFC imposes no such requirement.
        let i = inner.byteLength - 1;
        while (i >= 0 && inner[i] === 0) i--;
        if (i < 0) {
          throw new TlsError(codes.TLS_RECORD,
            'record plaintext is all padding with no content type byte', {});
        }
        const type = inner[i];
        const plaintext = inner.subarray(0, i);
        if (plaintext.byteLength > MAX_PLAINTEXT) {
          throw new TlsError(codes.TLS_RECORD,
            `record plaintext of ${plaintext.byteLength} bytes exceeds ${MAX_PLAINTEXT}`,
            { length: plaintext.byteLength });
        }
        return { type, plaintext };
      },
    };
  }

  // ------------------------------------------------------------------ TLS 1.2 (RFC 5288)
  return {
    version,
    /** Returns explicit_nonce(8) || ciphertext || tag — the GenericAEADCipher fragment. */
    async encrypt(seq, type, plaintext, { padding = 0 } = {}) {
      if (padding !== 0) {
        // No inner-plaintext padding exists in 1.2; silently dropping the request would let a
        // caller believe it is hiding lengths when it is not.
        throw new TlsError(codes.CONFIG_INVALID, 'record padding is a TLS 1.3 feature', {});
      }
      if (plaintext.byteLength > MAX_PLAINTEXT) {
        throw new TlsError(codes.CONFIG_INVALID,
          `plaintext of ${plaintext.byteLength} bytes exceeds ${MAX_PLAINTEXT}; fragment first`,
          { length: plaintext.byteLength });
      }
      const explicit = seq64(seq);
      const nonce = concat([staticIv, explicit]);
      const aad = concat([explicit, u8(type), u16(TLS12), u16(plaintext.byteLength)]);
      const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: tagLen * 8 },
        gcmKey, plaintext));
      return concat([explicit, ct]);
    },

    /**
     * The AAD is seq || type || version || plaintext-length (RFC 5246 s6.2.3.3). seq is OUR
     * receive counter, not the peer's explicit nonce — that is what makes reordering and
     * replay detectable. type/version are taken from the received header so the AAD binds
     * exactly what the wire claimed.
     */
    async decrypt(seq, body, header) {
      if (header.byteLength !== 5) {
        throw new TlsError(codes.CONFIG_INVALID,
          `header must be 5 bytes, got ${header.byteLength}`);
      }
      if (body.byteLength < 8 + tagLen) {
        throw new TlsError(codes.TLS_RECORD,
          `encrypted record body of ${body.byteLength} bytes is shorter than ` +
          `nonce+tag (${8 + tagLen})`,
          { length: body.byteLength });
      }
      const explicit = body.subarray(0, 8);
      const nonce = concat([staticIv, explicit]);
      const ptLen = body.byteLength - 8 - tagLen;
      const aad = concat([seq64(seq), header.subarray(0, 3), u16(ptLen)]);
      let plaintext;
      try {
        plaintext = new Uint8Array(await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: tagLen * 8 },
          gcmKey, body.subarray(8)));
      } catch {
        throw tagFailure();
      }
      return { type: header[0], plaintext };
    },
  };
}
