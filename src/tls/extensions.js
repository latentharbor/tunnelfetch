// TLS extension encoding and decoding.
//
// Encoding is written as small pure functions returning bytes so the ClientHello is testable as a
// fixed vector. Decoding refuses to be clever: an extension we did not offer coming back from the
// server is a protocol violation (RFC 8446 s4.2), and an extension appearing twice is a smuggling
// shape, so both are errors rather than last-one-wins.

import { TlsError, TlsUnsupportedError, codes, hex16 } from '../errors.js';
import { utf8, u16, u32 } from '../util/bytes.js';
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

/**
 * An extension of an arbitrary type with an arbitrary body. Exists for GREASE (RFC 8701), whose
 * whole point is to carry a reserved type this package assigns no meaning to.
 * @param {number} type
 * @param {Uint8Array} body
 */
export function encodeRawExtension(type, body) {
  return ext(type, body);
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
export function encodeStatusRequest() {
  return ext(
    EXTENSION.status_request,
    new Builder().u8(1).vector(2, new Uint8Array(0)).vector(2, new Uint8Array(0)).build(),
  );
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
export function encodePskKeyExchangeModes() {
  return ext(EXTENSION.psk_key_exchange_modes, vector(1, Uint8Array.from([1]))); // psk_dhe_ke
}

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
export function encodePreSharedKey({ identity, obfuscatedTicketAge, binderLen }) {
  if (identity.byteLength === 0 || identity.byteLength > 0xffff) {
    throw new TlsError(codes.TLS_TICKET,
      `PSK identity of ${identity.byteLength} bytes is outside 1..65535 and cannot be offered`,
      { length: identity.byteLength });
  }
  const entry = new Builder().vector(2, identity).push(u32(obfuscatedTicketAge >>> 0)).build();
  const binders = vector(2, vector(1, new Uint8Array(binderLen)));
  return ext(EXTENSION.pre_shared_key, new Builder().vector(2, entry).push(binders).build());
}

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
export function pskBinderTrailerLength(binderLen) {
  return 2 + 1 + binderLen;
}

/**
 * pre_shared_key in a ServerHello is a bare uint16 selected_identity (RFC 8446 s4.2.11).
 * @param {Uint8Array} data
 * @returns {number}
 */
export function decodeServerPreSharedKey(data) {
  const c = new Cursor(data, 'ServerHello pre_shared_key');
  const selected = c.u16('selected_identity');
  c.end('selected_identity');
  return selected;
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
