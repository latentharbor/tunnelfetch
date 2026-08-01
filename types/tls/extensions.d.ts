/**
 * An extension of an arbitrary type with an arbitrary body. Exists for GREASE (RFC 8701), whose
 * whole point is to carry a reserved type this package assigns no meaning to.
 * @param {number} type
 * @param {Uint8Array} body
 */
export function encodeRawExtension(type: number, body: Uint8Array): Uint8Array<ArrayBufferLike>;
/**
 * server_name (RFC 6066). Only host_name (type 0) exists in practice.
 * An IP literal must NOT be sent as SNI — RFC 6066 s3 forbids it, and servers that do virtual
 * hosting will hand back an unrelated certificate if we do, which would look like an attack.
 * @param {string} hostname
 * @returns {Uint8Array | null} null for an IP literal, which sends no SNI at all
 */
export function encodeServerName(hostname: string): Uint8Array | null;
/**
 * status_request (RFC 6066 s8): ask the server to staple an OCSP response for its certificate.
 *
 * The body is a CertificateStatusRequest: status_type ocsp(1), an empty responder_id_list (we
 * accept whatever responder the CA authorised — a client cannot usefully narrow that), and empty
 * request_extensions (no nonce: a stapled response is produced before our hello exists, so a
 * nonce could never be honoured and freshness comes from thisUpdate/nextUpdate instead).
 *
 * Offered in every hello, for both versions: it costs 9 bytes, and a server that ignores it
 * loses nothing. How the answer arrives differs by version — TLS 1.2 echoes the extension and
 * sends a separate CertificateStatus message (RFC 6066 s8), TLS 1.3 attaches it to the leaf's
 * CertificateEntry (RFC 8446 s4.4.2.1) — and each driver consumes its own form.
 * @returns {Uint8Array}
 */
export function encodeStatusRequest(): Uint8Array;
/**
 * @param {number[]} versions in preference order
 * @returns {Uint8Array}
 */
export function encodeSupportedVersions(versions: number[]): Uint8Array;
/**
 * @param {number[]} [groups]
 * @returns {Uint8Array}
 */
export function encodeSupportedGroups(groups?: number[]): Uint8Array;
/**
 * @param {number[]} [schemes]
 * @returns {Uint8Array}
 */
export function encodeSignatureAlgorithms(schemes?: number[]): Uint8Array;
/**
 * key_share entries, in the same order as supported_groups.
 * @param {Array<{ group: number, keyExchange: Uint8Array }>} shares the public halves only;
 *   private keys never reach the encoder
 * @returns {Uint8Array}
 */
export function encodeKeyShare(shares: Array<{
    group: number;
    keyExchange: Uint8Array;
}>): Uint8Array;
/**
 * The HelloRetryRequest response carries a bare group id with no share.
 * @param {number} group
 * @returns {Uint8Array}
 */
export function encodeKeyShareHrr(group: number): Uint8Array;
/**
 * @param {string[]} protocols
 * @returns {Uint8Array}
 */
export function encodeAlpn(protocols: string[]): Uint8Array;
/**
 * psk_key_exchange_modes (RFC 8446 s4.2.9), mandatory in any ClientHello that offers (or might
 * later offer) pre_shared_key, and sent in every 1.3 hello regardless because some middleboxes
 * reject its absence and it costs 6 bytes.
 *
 * Only psk_dhe_ke(1) is offered, ever. psk_ke would let a resumed connection run with no fresh
 * (EC)DHE at all, so compromise of one ticket's PSK would decrypt every session resumed from it
 * — the forward-secrecy property the rest of this package refuses to trade away (no RSA key
 * transport for the same reason). A server honouring psk_dhe_ke must still send key_share, and
 * selectServerKeyShare fails closed if it does not.
 */
export function encodePskKeyExchangeModes(): Uint8Array<ArrayBufferLike>;
/**
 * pre_shared_key for a ClientHello (RFC 8446 s4.2.11): one PskIdentity (the ticket plus its
 * obfuscated age) and one PskBinderEntry. The binder cannot be known while the hello is being
 * encoded — it is an HMAC over a transcript of the very hello it sits in, truncated just before
 * the binders list — so it is emitted here as `binderLen` ZERO bytes, at the exact length the
 * real binder will have, and the builder patches the real value in afterwards. RFC 8446
 * s4.2.11.2 requires exactly this shape: every length field is computed as if the true binder
 * were present, and only then is the binder derived and substituted.
 *
 * Exactly one identity is offered by design. The wire format allows a list, but this client
 * only ever holds resumption PSKs and offers the newest usable ticket; a multi-PSK offer would
 * multiply binder computations for a case that cannot arise here.
 *
 * @param {object} psk
 * @param {Uint8Array} psk.identity the ticket, opaque, 1..2^16-1 bytes
 * @param {number} psk.obfuscatedTicketAge uint32, already obfuscated per s4.2.11.1
 * @param {number} psk.binderLen digest length of the PSK's hash
 * @returns {Uint8Array}
 */
export function encodePreSharedKey({ identity, obfuscatedTicketAge, binderLen }: {
    identity: Uint8Array;
    obfuscatedTicketAge: number;
    binderLen: number;
}): Uint8Array;
/**
 * The number of trailing ClientHello bytes occupied by the binders list this client emits: the
 * 2-byte list length, the 1-byte entry length, and the binder itself. This is the truncation
 * arithmetic of RFC 8446 s4.2.11.2 — the binder transcript covers the hello up to and including
 * the identities, i.e. everything except these bytes — kept next to the encoder above so the
 * two cannot drift apart. pre_shared_key being the LAST extension (enforced by the builder) is
 * what makes "trailing bytes of the message" and "the binders list" the same thing.
 * @param {number} binderLen
 * @returns {number}
 */
export function pskBinderTrailerLength(binderLen: number): number;
/**
 * pre_shared_key in a ServerHello is a bare uint16 selected_identity (RFC 8446 s4.2.11).
 * @param {Uint8Array} data
 * @returns {number}
 */
export function decodeServerPreSharedKey(data: Uint8Array): number;
/** RFC 7627. Requesting extended master secret closes the triple-handshake hole in TLS 1.2. */
export function encodeExtendedMasterSecret(): Uint8Array<ArrayBufferLike>;
/**
 * RFC 5746. An empty renegotiation_info says "I support secure renegotiation and have not
 * renegotiated". We never renegotiate, but omitting this makes some TLS 1.2 servers reject us.
 */
export function encodeRenegotiationInfo(): Uint8Array<ArrayBufferLike>;
/** RFC 8422 s5.1.2: uncompressed only. Compressed points are not implemented anywhere modern. */
export function encodeEcPointFormats(): Uint8Array<ArrayBufferLike>;
/**
 * @param {Array<Uint8Array | null>} parts nulls tolerated so conditional extensions read cleanly
 * @returns {Uint8Array}
 */
export function encodeExtensionBlock(parts: Array<Uint8Array | null>): Uint8Array;
/**
 * Decode an extension block into a Map. Duplicates are rejected rather than folded: a repeated
 * extension is never legitimate and letting the last one win is how parser-differential bugs start.
 * @param {Uint8Array} bytes the block content, its outer length prefix already consumed
 * @param {string} where named in errors, e.g. 'ServerHello'
 * @returns {Map<number, Uint8Array>}
 */
export function decodeExtensionBlock(bytes: Uint8Array, where: string): Map<number, Uint8Array>;
/**
 * RFC 8446 s4.2: the server may only send extensions the client offered. Anything else means we
 * and the server disagree about the negotiation, which is not a state to continue from.
 * @param {Map<number, Uint8Array>} received
 * @param {Set<number>} offered extension types the ClientHello carried
 * @param {string} where
 * @returns {void} throws TlsError on the first unoffered extension
 */
export function rejectUnofferedExtensions(received: Map<number, Uint8Array>, offered: Set<number>, where: string): void;
/**
 * supported_versions in a ServerHello is a single uint16, not a list.
 * @param {Uint8Array} data
 * @returns {number}
 */
export function decodeSelectedVersion(data: Uint8Array): number;
/**
 * @param {Uint8Array} data
 * @param {string} where
 * @returns {{ group: number, keyExchange: Uint8Array }}
 */
export function decodeKeyShareEntry(data: Uint8Array, where: string): {
    group: number;
    keyExchange: Uint8Array;
};
/**
 * HelloRetryRequest's key_share is a bare group with no key.
 * @param {Uint8Array} data
 * @returns {number}
 */
export function decodeKeyShareHrr(data: Uint8Array): number;
/**
 * @param {Uint8Array} data
 * @returns {string} the single protocol the server selected (RFC 7301 s3.2)
 */
export function decodeAlpn(data: Uint8Array): string;
/**
 * @param {number} group
 * @param {string} where
 * @returns {import('./constants.js').GroupParams} throws TlsUnsupportedError when unimplemented
 */
export function requireSupportedGroup(group: number, where: string): import("./constants.js").GroupParams;
/**
 * @param {number} scheme
 * @returns {string}
 */
export function describeSigScheme(scheme: number): string;
/**
 * @param {number} version
 * @returns {string}
 */
export function describeVersion(version: number): string;
/**
 * Cheap classification, not validation: decides whether a name is legal as SNI.
 * @param {string} host
 * @returns {boolean}
 */
export function isIpLiteral(host: string): boolean;
import { GROUP } from './constants.js';
import { TLS12 } from './constants.js';
import { TLS13 } from './constants.js';
export { GROUP, TLS12, TLS13 };
