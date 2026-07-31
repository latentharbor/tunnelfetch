// ASN.1 DER reader.
//
// This feeds signature verification, so exactness is the whole point: every element carries the
// byte range of its full encoding AND of its content, and callers verify signatures over slices
// of the ORIGINAL buffer. Nothing here re-encodes, ever — a re-encoder that "fixes" anything is a
// forgery laundromat.
//
// DER, not BER. BER's flexibilities (indefinite lengths, non-minimal lengths, constructed
// strings) are exactly the degrees of freedom historical certificate forgeries lived in, so each
// one is rejected by name rather than tolerated. Every rejection says where and why, because a
// parse failure in a certificate is either a broken CA or an attack, and both deserve a precise
// log line.

import { CertificateError, codes } from '../errors.js';

/** Universal tag numbers we name in errors and match on. */
export const TAG = {
  BOOLEAN: 1,
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  UTF8_STRING: 12,
  SEQUENCE: 16,
  SET: 17,
  NUMERIC_STRING: 18,
  PRINTABLE_STRING: 19,
  TELETEX_STRING: 20,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  VISIBLE_STRING: 26,
  BMP_STRING: 30,
};

export const CLS = { UNIVERSAL: 0, APPLICATION: 1, CONTEXT: 2, PRIVATE: 3 };

const TAG_NAME = Object.fromEntries(Object.entries(TAG).map(([k, v]) => [v, k]));

/**
 * One decoded tag-length-value element, as byte ranges into the ORIGINAL buffer. Every reader
 * in the trust layer passes these around instead of slices precisely so that signature checks
 * always run over the peer's own bytes.
 * @typedef {object} Tlv
 * @property {number} cls tag class, per {@link CLS}
 * @property {boolean} constructed
 * @property {number} tag tag number, high-tag-number form already decoded
 * @property {number} start offset of the first header byte
 * @property {number} headerLen tag + length octets
 * @property {number} contentStart
 * @property {number} contentEnd
 * @property {number} end one past the element; equals contentEnd for every legal DER element
 */

/**
 * Describe a tag for error messages: "SEQUENCE", "[0]", "APPLICATION 3".
 * @param {number} cls
 * @param {number} tag
 * @returns {string}
 */
export function tagName(cls, tag) {
  if (cls === CLS.UNIVERSAL) return TAG_NAME[tag] ?? `UNIVERSAL ${tag}`;
  if (cls === CLS.CONTEXT) return `[${tag}]`;
  return `${cls === CLS.APPLICATION ? 'APPLICATION' : 'PRIVATE'} ${tag}`;
}

/**
 * @param {number} offset
 * @param {string} message
 * @returns {CertificateError}
 */
export function parseError(offset, message) {
  return new CertificateError(codes.CERT_PARSE, `DER at offset ${offset}: ${message}`, { offset });
}

/**
 * Read one TLV starting at `offset`. Returns byte ranges only — content is always a subarray of
 * the caller's original buffer, never a copy, so signatures can be verified over the same bytes
 * the peer sent.
 *
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {Tlv}
 */
export function readTlv(bytes, offset) {
  const len = bytes.byteLength;
  if (offset >= len) throw parseError(offset, `element expected but buffer ends at ${len}`);
  const first = bytes[offset];
  const cls = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  let p = offset + 1;
  if (tag === 0x1f) {
    // High tag number form: base-128, minimal, terminated by a byte without the high bit.
    tag = 0;
    if (p < len && bytes[p] === 0x80) {
      throw parseError(p, 'non-minimal multi-byte tag number (leading 0x80)');
    }
    for (let i = 0; ; i++) {
      if (p >= len) throw parseError(p, 'truncated multi-byte tag number');
      if (i >= 4) throw parseError(p, 'tag number wider than 28 bits, refusing');
      const b = bytes[p++];
      tag = tag * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
    if (tag < 0x1f) throw parseError(offset, `tag ${tag} used high-tag-number form unnecessarily`);
  }
  if (p >= len) throw parseError(p, `length byte expected but buffer ends at ${len}`);
  const l0 = bytes[p++];
  let contentLen;
  if (l0 < 0x80) {
    contentLen = l0;
  } else if (l0 === 0x80) {
    // Indefinite length is BER-only. In DER it is illegal, and accepting it would let an attacker
    // move element boundaries around — the classic constructed-string forgery.
    throw parseError(p - 1, 'indefinite length is not allowed in DER');
  } else if (l0 === 0xff) {
    throw parseError(p - 1, 'reserved length byte 0xff');
  } else {
    const n = l0 & 0x7f;
    if (n > 4) throw parseError(p - 1, `length of length ${n} bytes, refusing (> 4)`);
    if (p + n > len) throw parseError(p, 'truncated long-form length');
    if (bytes[p] === 0x00) {
      throw parseError(p, 'non-minimal length encoding (leading zero length byte)');
    }
    contentLen = 0;
    for (let i = 0; i < n; i++) contentLen = contentLen * 256 + bytes[p + i];
    p += n;
    if (contentLen < 0x80) {
      throw parseError(offset, `non-minimal length encoding (long form for length ${contentLen})`);
    }
  }
  const contentStart = p;
  const contentEnd = contentStart + contentLen;
  if (contentEnd > len) {
    throw parseError(
      offset,
      `${tagName(cls, tag)} content of ${contentLen} bytes runs past end of buffer ` +
        `(${contentEnd} > ${len})`,
    );
  }
  return {
    cls,
    constructed,
    tag,
    start: offset,
    headerLen: contentStart - offset,
    contentStart,
    contentEnd,
    end: contentEnd,
  };
}

/** The content bytes of a TLV, as a subarray of the original buffer. */
/** @type {(bytes: Uint8Array, tlv: Tlv) => Uint8Array} */
export const content = (bytes, tlv) => bytes.subarray(tlv.contentStart, tlv.contentEnd);
/** The full element (tag + length + content), as a subarray of the original buffer. */
/** @type {(bytes: Uint8Array, tlv: Tlv) => Uint8Array} */
export const element = (bytes, tlv) => bytes.subarray(tlv.start, tlv.end);

/**
 * Assert a TLV has the given shape, with an error naming expected vs got at the offset.
 * @param {Tlv} tlv
 * @param {{ cls?: number, tag: number, constructed?: boolean }} shape omitted `constructed`
 *   accepts either form
 * @param {string} what
 * @returns {Tlv} the same tlv, for chaining into a reader
 */
export function expectTlv(tlv, { cls = CLS.UNIVERSAL, tag, constructed }, what) {
  const wrongShape = constructed !== undefined && tlv.constructed !== constructed;
  if (tlv.cls !== cls || tlv.tag !== tag || wrongShape) {
    const wanted = constructed === undefined ? '' : constructed ? ' (constructed)' : ' (primitive)';
    throw parseError(
      tlv.start,
      `expected ${tagName(cls, tag)}${wanted} for ${what}, ` +
        `got ${tagName(tlv.cls, tlv.tag)} (${tlv.constructed ? 'constructed' : 'primitive'})`,
    );
  }
  return tlv;
}

/**
 * Read a TLV and require it to be a constructed SEQUENCE.
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {string} [what]
 * @returns {Tlv}
 */
export function readSequence(bytes, offset, what = 'SEQUENCE') {
  return expectTlv(readTlv(bytes, offset), { tag: TAG.SEQUENCE, constructed: true }, what);
}

/**
 * Parse the content of a constructed element into its immediate children, requiring them to fill
 * the content exactly. Trailing bytes inside a container are as suspicious as trailing bytes
 * after the certificate.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {Tlv[]}
 */
export function children(bytes, tlv, what = tagName(tlv.cls, tlv.tag)) {
  if (!tlv.constructed) {
    throw parseError(tlv.start, `${what} must be constructed to have children`);
  }
  const out = [];
  let p = tlv.contentStart;
  while (p < tlv.contentEnd) {
    const child = readTlv(bytes, p);
    if (child.end > tlv.contentEnd) {
      throw parseError(child.start,
        `child overruns enclosing ${what} (ends ${child.end} > ${tlv.contentEnd})`);
    }
    out.push(child);
    p = child.end;
  }
  return out;
}

/**
 * Read the single top-level element and reject trailing bytes after it.
 * @param {Uint8Array} bytes
 * @param {string} [what]
 * @returns {Tlv}
 */
export function readAll(bytes, what = 'top-level element') {
  const tlv = readTlv(bytes, 0);
  if (tlv.end !== bytes.byteLength) {
    throw parseError(tlv.end, `${bytes.byteLength - tlv.end} trailing bytes after ${what}`);
  }
  return tlv;
}

/**
 * INTEGER: returns the raw big-endian content and, when it fits a safe JS number, the value.
 * DER minimality: the first nine bits must not be all-zero or all-one, else a shorter encoding
 * exists. Laxness here would let two different byte strings claim the same serial number.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {{ bytes: Uint8Array, value: number | null, negative: boolean }} `value` is null
 *   when the magnitude does not fit a safe number (serials routinely do not)
 */
export function readInteger(bytes, tlv, what = 'INTEGER') {
  expectTlv(tlv, { tag: TAG.INTEGER, constructed: false }, what);
  const c = content(bytes, tlv);
  if (c.byteLength === 0) throw parseError(tlv.start, `empty ${what}`);
  if (c.byteLength > 1) {
    if (c[0] === 0x00 && c[1] < 0x80) {
      throw parseError(tlv.start, `non-minimal ${what} encoding (leading 0x00)`);
    }
    if (c[0] === 0xff && c[1] >= 0x80) {
      throw parseError(tlv.start, `non-minimal ${what} encoding (leading 0xff)`);
    }
  }
  const negative = (c[0] & 0x80) !== 0;
  let value = null;
  if (!negative && (c.byteLength < 7 || (c.byteLength === 7 && c[0] < 0x20))) {
    value = 0;
    for (const b of c) value = value * 256 + b;
  }
  return { bytes: c, value, negative };
}

/**
 * OBJECT IDENTIFIER to dotted string. Sub-identifiers are base-128 and must be minimal: a leading
 * 0x80 continuation byte is a second spelling of the same OID, and two spellings of one identity
 * is how "unknown critical extension" checks get bypassed.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {string} dotted form, e.g. '2.5.29.15'
 */
export function readOid(bytes, tlv, what = 'OBJECT IDENTIFIER') {
  expectTlv(tlv, { tag: TAG.OID, constructed: false }, what);
  const c = content(bytes, tlv);
  if (c.byteLength === 0) throw parseError(tlv.start, `empty ${what}`);
  const arcs = [];
  let value = 0;
  let inSub = false;
  for (let i = 0; i < c.byteLength; i++) {
    const b = c[i];
    if (!inSub && b === 0x80) {
      throw parseError(tlv.contentStart + i, `non-minimal sub-identifier in ${what} (leading 0x80)`);
    }
    inSub = true;
    if (value > 0x3ffffffffffff) {
      throw parseError(tlv.contentStart + i, `sub-identifier in ${what} too large, refusing`);
    }
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0;
      inSub = false;
    }
  }
  if (inSub) throw parseError(tlv.end, `truncated sub-identifier in ${what}`);
  const first = arcs[0];
  // The first two arcs share one sub-identifier: 40*X+Y, with X capped at 2.
  const x = first < 40 ? 0 : first < 80 ? 1 : 2;
  const y = first - x * 40;
  return [x, y, ...arcs.slice(1)].join('.');
}

/**
 * BIT STRING: unused-bit count + payload. DER additionally requires the unused bits themselves to
 * be zero — a nonzero padding bit is another two-spellings ambiguity.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {{ unusedBits: number, bytes: Uint8Array }}
 */
export function readBitString(bytes, tlv, what = 'BIT STRING') {
  expectTlv(tlv, { tag: TAG.BIT_STRING, constructed: false }, what);
  const c = content(bytes, tlv);
  if (c.byteLength === 0) throw parseError(tlv.start, `empty ${what} (missing unused-bits byte)`);
  const unusedBits = c[0];
  if (unusedBits > 7) {
    throw parseError(tlv.contentStart, `${what} unused-bits ${unusedBits} > 7`);
  }
  if (c.byteLength === 1 && unusedBits !== 0) {
    throw parseError(tlv.contentStart, `${what} with no payload must have 0 unused bits`);
  }
  if (unusedBits > 0 && (c[c.byteLength - 1] & ((1 << unusedBits) - 1)) !== 0) {
    throw parseError(tlv.end - 1, `${what} padding bits are not zero`);
  }
  return { unusedBits, bytes: c.subarray(1) };
}

/**
 * BOOLEAN. DER: content is exactly one byte, 0x00 or 0xff.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {boolean}
 */
export function readBoolean(bytes, tlv, what = 'BOOLEAN') {
  expectTlv(tlv, { tag: TAG.BOOLEAN, constructed: false }, what);
  const c = content(bytes, tlv);
  if (c.byteLength !== 1) throw parseError(tlv.start, `${what} must be 1 byte, got ${c.byteLength}`);
  if (c[0] !== 0x00 && c[0] !== 0xff) {
    throw parseError(tlv.contentStart, `${what} must be 0x00 or 0xff in DER, got 0x${c[0].toString(16)}`);
  }
  return c[0] === 0xff;
}

const isDigit = (b) => b >= 0x30 && b <= 0x39;

function timeError(tlv, kind, text) {
  return parseError(tlv.start, `malformed ${kind} "${text}"`);
}

/** Days per month, with February resolved against the Gregorian leap rule. */
function daysInMonth(y, m) {
  if (m === 2) return y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28;
  return [31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
}

function toEpochMs(tlv, kind, text, y, mo, d, h, mi, s) {
  if (mo < 1 || mo > 12) throw timeError(tlv, kind, text);
  if (d < 1 || d > daysInMonth(y, mo)) throw timeError(tlv, kind, text);
  // 60 would be a leap second; Date.UTC silently rolls it into the next minute, which is a
  // different instant than encoded. RFC 5280 profiles do not emit leap seconds, so reject.
  if (h > 23 || mi > 59 || s > 59) throw timeError(tlv, kind, text);
  return Date.UTC(y, mo - 1, d, h, mi, s);
}

/**
 * UTCTime, RFC 5280 profile: exactly YYMMDDHHMMSSZ. Seconds are mandatory, the zone is mandatory
 * and must be Z, and fractional seconds do not exist in this profile. The two-digit year pivots
 * at 50: 50..99 map to 19xx, 00..49 to 20xx (RFC 5280 s4.1.2.5.1).
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {number} epoch ms UTC
 */
export function readUtcTime(bytes, tlv, what = 'UTCTime') {
  expectTlv(tlv, { tag: TAG.UTC_TIME, constructed: false }, what);
  const c = content(bytes, tlv);
  let text = '';
  for (const b of c) text += String.fromCharCode(b);
  if (c.byteLength !== 13 || c[12] !== 0x5a /* Z */) throw timeError(tlv, what, text);
  for (let i = 0; i < 12; i++) if (!isDigit(c[i])) throw timeError(tlv, what, text);
  const n = (i) => (c[i] - 0x30) * 10 + (c[i + 1] - 0x30);
  const yy = n(0);
  const year = yy >= 50 ? 1900 + yy : 2000 + yy;
  return toEpochMs(tlv, what, text, year, n(2), n(4), n(6), n(8), n(10));
}

/**
 * GeneralizedTime, RFC 5280 profile: exactly YYYYMMDDHHMMSSZ. Fractional seconds are explicitly
 * forbidden by RFC 5280 s4.1.2.5.2, and allowing them would give one instant many encodings.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {number} epoch ms UTC
 */
export function readGeneralizedTime(bytes, tlv, what = 'GeneralizedTime') {
  expectTlv(tlv, { tag: TAG.GENERALIZED_TIME, constructed: false }, what);
  const c = content(bytes, tlv);
  let text = '';
  for (const b of c) text += String.fromCharCode(b);
  if (c.byteLength !== 15 || c[14] !== 0x5a /* Z */) throw timeError(tlv, what, text);
  for (let i = 0; i < 14; i++) if (!isDigit(c[i])) throw timeError(tlv, what, text);
  const n = (i) => (c[i] - 0x30) * 10 + (c[i + 1] - 0x30);
  const year = n(0) * 100 + n(2);
  return toEpochMs(tlv, what, text, year, n(4), n(6), n(8), n(10), n(12));
}

/**
 * Either time type, as used by Validity and by name-constraint-free consumers.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {number} epoch ms UTC
 */
export function readTime(bytes, tlv, what = 'Time') {
  if (tlv.tag === TAG.UTC_TIME) return readUtcTime(bytes, tlv, what);
  if (tlv.tag === TAG.GENERALIZED_TIME) return readGeneralizedTime(bytes, tlv, what);
  throw parseError(tlv.start,
    `expected UTCTime or GeneralizedTime for ${what}, got ${tagName(tlv.cls, tlv.tag)}`);
}

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Directory string types. Each type's alphabet is enforced — a PrintableString smuggling bytes
 * outside its charset is two parsers disagreeing about one name.
 *
 * TeletexString is decoded as Latin-1: its real charset (T.61) is a negotiation-dependent mess
 * that no CA has honoured in decades, and Latin-1 is the universal de-facto reading.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {string}
 */
export function readString(bytes, tlv, what = 'string') {
  const c = content(bytes, tlv);
  const at = (i) => tlv.contentStart + i;
  switch (tlv.tag) {
    case TAG.UTF8_STRING: {
      try {
        return utf8Decoder.decode(c);
      } catch {
        throw parseError(tlv.start, `invalid UTF-8 in ${what}`);
      }
    }
    case TAG.PRINTABLE_STRING: {
      let s = '';
      for (let i = 0; i < c.byteLength; i++) {
        const b = c[i];
        const ok =
          (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) ||
          b === 0x20 || (b >= 0x27 && b <= 0x2f && b !== 0x2a) || b === 0x3a || b === 0x3d || b === 0x3f;
        if (!ok) {
          throw parseError(at(i), `byte 0x${b.toString(16)} outside PrintableString alphabet in ${what}`);
        }
        s += String.fromCharCode(b);
      }
      return s;
    }
    case TAG.IA5_STRING:
    case TAG.VISIBLE_STRING:
    case TAG.NUMERIC_STRING: {
      let s = '';
      for (let i = 0; i < c.byteLength; i++) {
        const b = c[i];
        if (b > 0x7f) throw parseError(at(i), `non-ASCII byte 0x${b.toString(16)} in ${what}`);
        if (tlv.tag === TAG.NUMERIC_STRING && !(isDigit(b) || b === 0x20)) {
          throw parseError(at(i), `byte 0x${b.toString(16)} outside NumericString alphabet in ${what}`);
        }
        s += String.fromCharCode(b);
      }
      return s;
    }
    case TAG.TELETEX_STRING: {
      let s = '';
      for (const b of c) s += String.fromCharCode(b);
      return s;
    }
    case TAG.BMP_STRING: {
      if (c.byteLength % 2 !== 0) throw parseError(tlv.start, `odd-length BMPString in ${what}`);
      let s = '';
      for (let i = 0; i < c.byteLength; i += 2) {
        const unit = (c[i] << 8) | c[i + 1];
        // BMPString is UCS-2: surrogate code units have no meaning and are rejected rather than
        // passed through where they could re-pair into unexpected characters downstream.
        if (unit >= 0xd800 && unit <= 0xdfff) {
          throw parseError(at(i), `surrogate code unit in BMPString ${what}`);
        }
        s += String.fromCharCode(unit);
      }
      return s;
    }
    default:
      throw parseError(tlv.start, `unsupported string type ${tagName(tlv.cls, tlv.tag)} for ${what}`);
  }
}

/**
 * ECDSA-Sig-Value (SEQUENCE of two INTEGERs) to the fixed-width r||s form WebCrypto verifies.
 *
 * This lives here, once, because both users of it are checking signatures: the certificate path
 * builder and the TLS CertificateVerify. TLS transmits ECDSA signatures in DER while WebCrypto
 * accepts only the P1363 concatenation, and a round-trip test that signs and verifies with
 * WebCrypto agrees with itself while failing against every real server — so this conversion is
 * exactly the sort of thing that must have one implementation and not two.
 *
 * Any malformation is an invalid signature; there is no "close enough" for signature bytes.
 *
 * @param {Uint8Array} sig DER ECDSA-Sig-Value
 * @param {number} orderLen byte width of the curve order (32 / 48 / 66)
 * @param {(why: string) => Error} onInvalid builds the caller's own error type
 * @returns {Uint8Array} r||s, each half left-padded to orderLen
 */
export function ecdsaDerToRaw(sig, orderLen, onInvalid) {
  // Every failure below, DER-level or structural, is reported through the caller's error factory.
  // Letting a CERT_PARSE escape from here would put a certificate-shaped error in front of a
  // caller checking a TLS handshake signature — the wrong taxonomy for the wrong layer.
  let kids;
  try {
    const seq = readAll(sig, 'ECDSA-Sig-Value');
    expectTlv(seq, { tag: TAG.SEQUENCE, constructed: true }, 'ECDSA-Sig-Value');
    kids = children(sig, seq, 'ECDSA-Sig-Value');
  } catch (e) {
    throw onInvalid(e?.message ?? String(e));
  }
  if (kids.length !== 2) throw onInvalid(`expected { r, s }, got ${kids.length} fields`);

  let r;
  let s;
  try {
    r = readInteger(sig, kids[0], 'r');
    s = readInteger(sig, kids[1], 's');
  } catch (e) {
    throw onInvalid(e?.message ?? String(e));
  }
  const out = new Uint8Array(orderLen * 2);
  for (const [i, part] of [r, s].entries()) {
    const label = i === 0 ? 'r' : 's';
    if (part.negative) throw onInvalid(`${label} is negative`);
    // readInteger guarantees minimal form, so at most one leading zero (the sign byte) remains.
    let b = part.bytes;
    if (b.length > 1 && b[0] === 0x00) b = b.subarray(1);
    if (b.length > orderLen) throw onInvalid(`${label} is wider than the curve order`);
    out.set(b, orderLen * (i + 1) - b.length);
  }
  return out;
}
