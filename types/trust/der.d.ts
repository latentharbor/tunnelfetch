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
export function tagName(cls: number, tag: number): string;
/**
 * @param {number} offset
 * @param {string} message
 * @returns {CertificateError}
 */
export function parseError(offset: number, message: string): CertificateError;
/**
 * Read one TLV starting at `offset`. Returns byte ranges only — content is always a subarray of
 * the caller's original buffer, never a copy, so signatures can be verified over the same bytes
 * the peer sent.
 *
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {Tlv}
 */
export function readTlv(bytes: Uint8Array, offset: number): Tlv;
/**
 * Assert a TLV has the given shape, with an error naming expected vs got at the offset.
 * @param {Tlv} tlv
 * @param {{ cls?: number, tag: number, constructed?: boolean }} shape omitted `constructed`
 *   accepts either form
 * @param {string} what
 * @returns {Tlv} the same tlv, for chaining into a reader
 */
export function expectTlv(tlv: Tlv, { cls, tag, constructed }: {
    cls?: number;
    tag: number;
    constructed?: boolean;
}, what: string): Tlv;
/**
 * Read a TLV and require it to be a constructed SEQUENCE.
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {string} [what]
 * @returns {Tlv}
 */
export function readSequence(bytes: Uint8Array, offset: number, what?: string): Tlv;
/**
 * Parse the content of a constructed element into its immediate children, requiring them to fill
 * the content exactly. Trailing bytes inside a container are as suspicious as trailing bytes
 * after the certificate.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {Tlv[]}
 */
export function children(bytes: Uint8Array, tlv: Tlv, what?: string): Tlv[];
/**
 * Read the single top-level element and reject trailing bytes after it.
 * @param {Uint8Array} bytes
 * @param {string} [what]
 * @returns {Tlv}
 */
export function readAll(bytes: Uint8Array, what?: string): Tlv;
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
export function readInteger(bytes: Uint8Array, tlv: Tlv, what?: string): {
    bytes: Uint8Array;
    value: number | null;
    negative: boolean;
};
/**
 * OBJECT IDENTIFIER to dotted string. Sub-identifiers are base-128 and must be minimal: a leading
 * 0x80 continuation byte is a second spelling of the same OID, and two spellings of one identity
 * is how "unknown critical extension" checks get bypassed.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {string} dotted form, e.g. '2.5.29.15'
 */
export function readOid(bytes: Uint8Array, tlv: Tlv, what?: string): string;
/**
 * BIT STRING: unused-bit count + payload. DER additionally requires the unused bits themselves to
 * be zero — a nonzero padding bit is another two-spellings ambiguity.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {{ unusedBits: number, bytes: Uint8Array }}
 */
export function readBitString(bytes: Uint8Array, tlv: Tlv, what?: string): {
    unusedBits: number;
    bytes: Uint8Array;
};
/**
 * BOOLEAN. DER: content is exactly one byte, 0x00 or 0xff.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {boolean}
 */
export function readBoolean(bytes: Uint8Array, tlv: Tlv, what?: string): boolean;
/**
 * UTCTime, RFC 5280 profile: exactly YYMMDDHHMMSSZ. Seconds are mandatory, the zone is mandatory
 * and must be Z, and fractional seconds do not exist in this profile. The two-digit year pivots
 * at 50: 50..99 map to 19xx, 00..49 to 20xx (RFC 5280 s4.1.2.5.1).
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {number} epoch ms UTC
 */
export function readUtcTime(bytes: Uint8Array, tlv: Tlv, what?: string): number;
/**
 * GeneralizedTime, RFC 5280 profile: exactly YYYYMMDDHHMMSSZ. Fractional seconds are explicitly
 * forbidden by RFC 5280 s4.1.2.5.2, and allowing them would give one instant many encodings.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {number} epoch ms UTC
 */
export function readGeneralizedTime(bytes: Uint8Array, tlv: Tlv, what?: string): number;
/**
 * Either time type, as used by Validity and by name-constraint-free consumers.
 * @param {Uint8Array} bytes
 * @param {Tlv} tlv
 * @param {string} [what]
 * @returns {number} epoch ms UTC
 */
export function readTime(bytes: Uint8Array, tlv: Tlv, what?: string): number;
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
export function readString(bytes: Uint8Array, tlv: Tlv, what?: string): string;
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
export function ecdsaDerToRaw(sig: Uint8Array, orderLen: number, onInvalid: (why: string) => Error): Uint8Array;
export namespace TAG {
    let BOOLEAN: number;
    let INTEGER: number;
    let BIT_STRING: number;
    let OCTET_STRING: number;
    let NULL: number;
    let OID: number;
    let UTF8_STRING: number;
    let SEQUENCE: number;
    let SET: number;
    let NUMERIC_STRING: number;
    let PRINTABLE_STRING: number;
    let TELETEX_STRING: number;
    let IA5_STRING: number;
    let UTC_TIME: number;
    let GENERALIZED_TIME: number;
    let VISIBLE_STRING: number;
    let BMP_STRING: number;
}
export namespace CLS {
    let UNIVERSAL: number;
    let APPLICATION: number;
    let CONTEXT: number;
    let PRIVATE: number;
}
/** The content bytes of a TLV, as a subarray of the original buffer. */
/** @type {(bytes: Uint8Array, tlv: Tlv) => Uint8Array} */
export const content: (bytes: Uint8Array, tlv: Tlv) => Uint8Array;
/** The full element (tag + length + content), as a subarray of the original buffer. */
/** @type {(bytes: Uint8Array, tlv: Tlv) => Uint8Array} */
export const element: (bytes: Uint8Array, tlv: Tlv) => Uint8Array;
/**
 * One decoded tag-length-value element, as byte ranges into the ORIGINAL buffer. Every reader
 * in the trust layer passes these around instead of slices precisely so that signature checks
 * always run over the peer's own bytes.
 */
export type Tlv = {
    /**
     * tag class, per {@link CLS}
     */
    cls: number;
    constructed: boolean;
    /**
     * tag number, high-tag-number form already decoded
     */
    tag: number;
    /**
     * offset of the first header byte
     */
    start: number;
    /**
     * tag + length octets
     */
    headerLen: number;
    contentStart: number;
    contentEnd: number;
    /**
     * one past the element; equals contentEnd for every legal DER element
     */
    end: number;
};
import { CertificateError } from '../errors.js';
