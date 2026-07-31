/**
 * server_name (RFC 6066). Only host_name (type 0) exists in practice.
 * An IP literal must NOT be sent as SNI — RFC 6066 s3 forbids it, and servers that do virtual
 * hosting will hand back an unrelated certificate if we do, which would look like an attack.
 * @param {string} hostname
 * @returns {Uint8Array | null} null for an IP literal, which sends no SNI at all
 */
export function encodeServerName(hostname: string): Uint8Array | null;
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
 * psk_key_exchange_modes is mandatory for a 1.3 ClientHello that might resume. We never resume,
 * but some middleboxes and servers reject its absence, and sending it costs 6 bytes.
 */
export function encodePskKeyExchangeModes(): Uint8Array<ArrayBufferLike>;
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
