// TLS extension encoding and decoding.
//
// Encoding is written as small pure functions returning bytes so the ClientHello is testable as a
// fixed vector. Decoding refuses to be clever: an extension we did not offer coming back from the
// server is a protocol violation (RFC 8446 s4.2), and an extension appearing twice is a smuggling
// shape, so both are errors rather than last-one-wins.

import { TlsError, TlsUnsupportedError, codes, hex16 } from '../errors.js';
import { utf8, u16 } from '../util/bytes.js';
import { Builder, Cursor, vector } from './wire.js';
import {
  EXTENSION,
  GROUP,
  GROUP_NAME,
  GROUP_PARAMS,
  SIG_SCHEME_NAME,
  SUPPORTED_GROUPS,
  SUPPORTED_SIG_SCHEMES,
  TLS12,
  TLS13,
  VERSION_NAME,
} from './constants.js';

/** Wrap a body as `extension_type || extension_data<0..2^16-1>`. */
function ext(type, body) {
  return new Builder().u16(type).vector(2, body).build();
}

// ------------------------------------------------------------------ encoders (ClientHello)

/**
 * server_name (RFC 6066). Only host_name (type 0) exists in practice.
 * An IP literal must NOT be sent as SNI — RFC 6066 s3 forbids it, and servers that do virtual
 * hosting will hand back an unrelated certificate if we do, which would look like an attack.
 * @param {string} hostname
 * @returns {Uint8Array | null} null for an IP literal, which sends no SNI at all
 */
export function encodeServerName(hostname) {
  if (isIpLiteral(hostname)) return null;
  const name = utf8(hostname);
  if (name.byteLength === 0 || name.byteLength > 0xffff) {
    throw new TlsError(codes.CONFIG_INVALID, `server_name of ${name.byteLength} bytes is invalid`);
  }
  const entry = new Builder().u8(0).vector(2, name).build();
  return ext(EXTENSION.server_name, vector(2, entry));
}

/**
 * @param {number[]} versions in preference order
 * @returns {Uint8Array}
 */
export function encodeSupportedVersions(versions) {
  const b = new Builder();
  for (const v of versions) b.u16(v);
  return ext(EXTENSION.supported_versions, vector(1, b.build()));
}

/**
 * @param {number[]} [groups]
 * @returns {Uint8Array}
 */
export function encodeSupportedGroups(groups = SUPPORTED_GROUPS) {
  const b = new Builder();
  for (const g of groups) b.u16(g);
  return ext(EXTENSION.supported_groups, vector(2, b.build()));
}

/**
 * @param {number[]} [schemes]
 * @returns {Uint8Array}
 */
export function encodeSignatureAlgorithms(schemes = SUPPORTED_SIG_SCHEMES) {
  const b = new Builder();
  for (const s of schemes) b.u16(s);
  return ext(EXTENSION.signature_algorithms, vector(2, b.build()));
}

/**
 * key_share entries, in the same order as supported_groups.
 * @param {Array<{ group: number, keyExchange: Uint8Array }>} shares the public halves only;
 *   private keys never reach the encoder
 * @returns {Uint8Array}
 */
export function encodeKeyShare(shares) {
  const b = new Builder();
  for (const { group, keyExchange } of shares) {
    b.u16(group).vector(2, keyExchange);
  }
  return ext(EXTENSION.key_share, vector(2, b.build()));
}

/**
 * The HelloRetryRequest response carries a bare group id with no share.
 * @param {number} group
 * @returns {Uint8Array}
 */
export function encodeKeyShareHrr(group) {
  return ext(EXTENSION.key_share, u16(group));
}

/**
 * @param {string[]} protocols
 * @returns {Uint8Array}
 */
export function encodeAlpn(protocols) {
  const b = new Builder();
  for (const p of protocols) b.vector(1, utf8(p));
  return ext(EXTENSION.alpn, vector(2, b.build()));
}

/**
 * psk_key_exchange_modes is mandatory for a 1.3 ClientHello that might resume. We never resume,
 * but some middleboxes and servers reject its absence, and sending it costs 6 bytes.
 */
export function encodePskKeyExchangeModes() {
  return ext(EXTENSION.psk_key_exchange_modes, vector(1, Uint8Array.from([1]))); // psk_dhe_ke
}

/** RFC 7627. Requesting extended master secret closes the triple-handshake hole in TLS 1.2. */
export function encodeExtendedMasterSecret() {
  return ext(EXTENSION.extended_master_secret, new Uint8Array(0));
}

/**
 * RFC 5746. An empty renegotiation_info says "I support secure renegotiation and have not
 * renegotiated". We never renegotiate, but omitting this makes some TLS 1.2 servers reject us.
 */
export function encodeRenegotiationInfo() {
  return ext(EXTENSION.renegotiation_info, vector(1, new Uint8Array(0)));
}

/** RFC 8422 s5.1.2: uncompressed only. Compressed points are not implemented anywhere modern. */
export function encodeEcPointFormats() {
  return ext(EXTENSION.ec_point_formats, vector(1, Uint8Array.from([0])));
}

/**
 * @param {Array<Uint8Array | null>} parts nulls tolerated so conditional extensions read cleanly
 * @returns {Uint8Array}
 */
export function encodeExtensionBlock(parts) {
  const b = new Builder();
  for (const p of parts) if (p) b.push(p);
  return vector(2, b.build());
}

// ------------------------------------------------------------------ decoding

/**
 * Decode an extension block into a Map. Duplicates are rejected rather than folded: a repeated
 * extension is never legitimate and letting the last one win is how parser-differential bugs start.
 * @param {Uint8Array} bytes the block content, its outer length prefix already consumed
 * @param {string} where named in errors, e.g. 'ServerHello'
 * @returns {Map<number, Uint8Array>}
 */
export function decodeExtensionBlock(bytes, where) {
  const c = new Cursor(bytes, `${where} extensions`);
  const out = new Map();
  while (!c.done) {
    const type = c.u16('extension_type');
    const data = c.vector(2, 'extension_data');
    if (out.has(type)) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `${where} contains extension ${hex16(type)} twice`,
        { where, extension: type },
      );
    }
    out.set(type, data);
  }
  return out;
}

/**
 * RFC 8446 s4.2: the server may only send extensions the client offered. Anything else means we
 * and the server disagree about the negotiation, which is not a state to continue from.
 * @param {Map<number, Uint8Array>} received
 * @param {Set<number>} offered extension types the ClientHello carried
 * @param {string} where
 * @returns {void} throws TlsError on the first unoffered extension
 */
export function rejectUnofferedExtensions(received, offered, where) {
  for (const type of received.keys()) {
    if (!offered.has(type)) {
      throw new TlsError(
        codes.TLS_EXTENSION_UNSUPPORTED,
        `${where} contains extension ${hex16(type)} which was not offered in ClientHello`,
        { where, extension: type },
      );
    }
  }
}

/**
 * supported_versions in a ServerHello is a single uint16, not a list.
 * @param {Uint8Array} data
 * @returns {number}
 */
export function decodeSelectedVersion(data) {
  const c = new Cursor(data, 'supported_versions');
  const v = c.u16('selected_version');
  c.end('selected_version');
  return v;
}

/**
 * @param {Uint8Array} data
 * @param {string} where
 * @returns {{ group: number, keyExchange: Uint8Array }}
 */
export function decodeKeyShareEntry(data, where) {
  const c = new Cursor(data, `${where} key_share`);
  const group = c.u16('group');
  const keyExchange = c.vector(2, 'key_exchange');
  c.end('key_share entry');
  return { group, keyExchange };
}

/**
 * HelloRetryRequest's key_share is a bare group with no key.
 * @param {Uint8Array} data
 * @returns {number}
 */
export function decodeKeyShareHrr(data) {
  const c = new Cursor(data, 'HelloRetryRequest key_share');
  const group = c.u16('selected_group');
  c.end('selected_group');
  return group;
}

/**
 * @param {Uint8Array} data
 * @returns {string} the single protocol the server selected (RFC 7301 s3.2)
 */
export function decodeAlpn(data) {
  const c = new Cursor(data, 'alpn');
  const list = c.sub(2, 'protocol_name_list');
  const name = list.vector(1, 'protocol_name');
  // RFC 7301 s3.2: the server's list must contain exactly one protocol.
  list.end('protocol_name_list');
  c.end('alpn');
  return new TextDecoder().decode(name);
}

// ------------------------------------------------------------------ validation helpers

/**
 * @param {number} group
 * @param {string} where
 * @returns {import('./constants.js').GroupParams} throws TlsUnsupportedError when unimplemented
 */
export function requireSupportedGroup(group, where) {
  const params = GROUP_PARAMS[group];
  if (!params) {
    const name = GROUP_NAME[group] ?? 'unknown';
    throw new TlsUnsupportedError(
      codes.TLS_GROUP_UNSUPPORTED,
      `server selected group ${hex16(group)} (${name}) in ${where}, not implemented; ` +
        `offered ${SUPPORTED_GROUPS.map((g) => `${GROUP_NAME[g]}(${hex16(g)})`).join(', ')}`,
      { group, groupName: name },
    );
  }
  return params;
}

/**
 * @param {number} scheme
 * @returns {string}
 */
export function describeSigScheme(scheme) {
  return `${hex16(scheme)}${SIG_SCHEME_NAME[scheme] ? ` (${SIG_SCHEME_NAME[scheme]})` : ''}`;
}

/**
 * @param {number} version
 * @returns {string}
 */
export function describeVersion(version) {
  return `${hex16(version)}${VERSION_NAME[version] ? ` (${VERSION_NAME[version]})` : ''}`;
}

/**
 * Cheap classification, not validation: decides whether a name is legal as SNI.
 * @param {string} host
 * @returns {boolean}
 */
export function isIpLiteral(host) {
  if (host.includes(':')) return true; // only IPv6 literals contain a colon in a bare authority
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

export { GROUP, TLS12, TLS13 };
