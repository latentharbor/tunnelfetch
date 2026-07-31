// Typed errors.
//
// Discipline: an error must be specific enough that one log line decides whether a missing
// feature is worth implementing. "unsupported cipher" is useless; "server selected 0xc02f
// (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) under TLS 1.2, not implemented" is actionable.
// Every throw site therefore carries the concrete value the peer asked for, in `detail`.

/**
 * One of the stable machine-readable codes in {@link codes}. Exported as a named union so a
 * caller can exhaustively switch on `err.code` and have the compiler point at the case they
 * forgot when a release adds one.
 * @typedef {(typeof codes)[keyof typeof codes]} ErrorCode
 */

/** Base for everything this package throws. Never thrown directly. */
export class TunnelFetchError extends Error {
  /**
   * @param {string} code stable machine-readable code, normally an {@link ErrorCode}. Typed as
   *   string because one internal code (`UNEXPECTED_EOF`, from the byte layer) deliberately
   *   lives outside the public table.
   * @param {string} message human-readable, must name concrete values
   * @param {Record<string, unknown>} [detail]
   */
  constructor(code, message, detail) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    if (detail) this.detail = detail;
  }
}

/** Proxy handshake failed: CONNECT refused, SOCKS5 rejected, auth required. */
export class ProxyError extends TunnelFetchError {}

/** HTTP/1.1 wire format: malformed message, ambiguous framing, truncated body. */
export class HttpError extends TunnelFetchError {}

/** TLS record layer, handshake, or a peer alert. */
export class TlsError extends TunnelFetchError {}

/**
 * HTTP/2 framing, streams, flow control, HPACK, or a peer GOAWAY/RST_STREAM. Separate from
 * HttpError because the wire format and its failure modes are entirely different: an HTTP/1.1
 * message is text framed by lengths and CRLFs, an HTTP/2 stream is a state machine over binary
 * frames sharing one connection, and a caller distinguishing "the /1.1 parser choked" from "an
 * h2 stream was reset" wants two codes, not one.
 */
export class Http2Error extends TunnelFetchError {}

/**
 * The peer offered something we deliberately do not implement.
 * Separate from TlsError so "we cannot talk to this server" is distinguishable from
 * "the connection broke", which is the difference between a feature request and a bug report.
 */
export class TlsUnsupportedError extends TlsError {}

/** Certificate chain, trust anchor, name matching, validity, or constraint failure. */
export class CertificateError extends TunnelFetchError {}

/** A deadline elapsed. `phase` says which one, because the fix differs per phase. */
export class TimeoutError extends TunnelFetchError {}

/** A configured limit was exceeded (response size, header size, redirect count). */
export class LimitError extends TunnelFetchError {}

/** The caller asked for something the chosen transport cannot honour. */
export class ConfigError extends TunnelFetchError {}

export const codes = /** @type {const} */ ({
  // proxy
  PROXY_CONNECT_REFUSED: 'PROXY_CONNECT_REFUSED',
  PROXY_AUTH_REQUIRED: 'PROXY_AUTH_REQUIRED',
  PROXY_AUTH_FAILED: 'PROXY_AUTH_FAILED',
  PROXY_PROTOCOL: 'PROXY_PROTOCOL',
  PROXY_UNREACHABLE: 'PROXY_UNREACHABLE',
  SOCKS5_NO_ACCEPTABLE_AUTH: 'SOCKS5_NO_ACCEPTABLE_AUTH',
  SOCKS5_REPLY: 'SOCKS5_REPLY',
  SOCKS5_ADDR_TYPE: 'SOCKS5_ADDR_TYPE',

  // http/1.1
  HTTP_REQUEST_LINE: 'HTTP_REQUEST_LINE',
  HTTP_STATUS_LINE: 'HTTP_STATUS_LINE',
  HTTP_HEADER: 'HTTP_HEADER',
  HTTP_FRAMING_AMBIGUOUS: 'HTTP_FRAMING_AMBIGUOUS',
  HTTP_CHUNK: 'HTTP_CHUNK',
  HTTP_BODY_TRUNCATED: 'HTTP_BODY_TRUNCATED',
  HTTP_TRAILER: 'HTTP_TRAILER',
  HTTP_UPGRADE_UNEXPECTED: 'HTTP_UPGRADE_UNEXPECTED',

  // tls
  TLS_RECORD: 'TLS_RECORD',
  TLS_ALERT: 'TLS_ALERT',
  TLS_HANDSHAKE: 'TLS_HANDSHAKE',
  TLS_TRUNCATED: 'TLS_TRUNCATED',
  TLS_VERSION_UNSUPPORTED: 'TLS_VERSION_UNSUPPORTED',
  TLS_CIPHER_UNSUPPORTED: 'TLS_CIPHER_UNSUPPORTED',
  TLS_GROUP_UNSUPPORTED: 'TLS_GROUP_UNSUPPORTED',
  TLS_SIGALG_UNSUPPORTED: 'TLS_SIGALG_UNSUPPORTED',
  TLS_EXTENSION_UNSUPPORTED: 'TLS_EXTENSION_UNSUPPORTED',
  TLS_ALPN: 'TLS_ALPN',

  // http/2 (RFC 9113) and HPACK (RFC 7541). Every one names the concrete wire value that
  // triggered it — a frame type, a stream id, a table index — because "h2 error" alone decides
  // nothing about whether a peer is broken, hostile, or speaking a feature we declined.
  HTTP2_PROTOCOL: 'HTTP2_PROTOCOL', // generic connection PROTOCOL_ERROR: preface, frame on wrong stream, ...
  HTTP2_FRAME_SIZE: 'HTTP2_FRAME_SIZE', // a frame length the type or our SETTINGS forbids
  HTTP2_SETTINGS: 'HTTP2_SETTINGS', // malformed SETTINGS, or a value out of its legal range
  HTTP2_FLOW_CONTROL: 'HTTP2_FLOW_CONTROL', // a window overflowed 2^31-1, or the peer overran ours
  HTTP2_STREAM_STATE: 'HTTP2_STREAM_STATE', // a frame illegal for the stream's current state
  HTTP2_STREAM_CLOSED: 'HTTP2_STREAM_CLOSED', // the peer RST_STREAM'd, or closed a stream we were using
  HTTP2_GOAWAY: 'HTTP2_GOAWAY', // the peer is going away and did not (or will not) serve this stream
  HTTP2_COMPRESSION: 'HTTP2_COMPRESSION', // HPACK: bad index, bad integer, invalid Huffman padding, ...
  HTTP2_HEADER: 'HTTP2_HEADER', // a decoded header list that h2 forbids (uppercase, bad pseudo-header)
  HTTP2_PUSH_UNEXPECTED: 'HTTP2_PUSH_UNEXPECTED', // PUSH_PROMISE despite our SETTINGS_ENABLE_PUSH = 0
  HTTP2_TRAILER: 'HTTP2_TRAILER', // a trailing header block that is malformed or carries pseudo-headers

  // trust
  CERT_PARSE: 'CERT_PARSE',
  CERT_CHAIN_INCOMPLETE: 'CERT_CHAIN_INCOMPLETE',
  CERT_UNTRUSTED_ROOT: 'CERT_UNTRUSTED_ROOT',
  CERT_SIGNATURE_INVALID: 'CERT_SIGNATURE_INVALID',
  CERT_SIGNATURE_WEAK: 'CERT_SIGNATURE_WEAK',
  CERT_SIGNATURE_UNSUPPORTED: 'CERT_SIGNATURE_UNSUPPORTED',
  CERT_EXPIRED: 'CERT_EXPIRED',
  CERT_NOT_YET_VALID: 'CERT_NOT_YET_VALID',
  CERT_NAME_MISMATCH: 'CERT_NAME_MISMATCH',
  CERT_CONSTRAINT: 'CERT_CONSTRAINT',
  CERT_PIN_MISMATCH: 'CERT_PIN_MISMATCH',

  // revocation, via stapled OCSP (RFC 6960 over RFC 6066/8446 status_request)
  OCSP_PARSE: 'OCSP_PARSE',
  OCSP_UNVERIFIED: 'OCSP_UNVERIFIED',
  OCSP_MISMATCH: 'OCSP_MISMATCH',
  OCSP_STALE: 'OCSP_STALE',
  OCSP_REVOKED: 'OCSP_REVOKED',
  OCSP_UNKNOWN: 'OCSP_UNKNOWN',
  OCSP_REQUIRED: 'OCSP_REQUIRED',

  // client semantics
  HTTP_CONTENT_ENCODING: 'HTTP_CONTENT_ENCODING',
  HTTP_CHARSET: 'HTTP_CHARSET',
  REDIRECT_INVALID_LOCATION: 'REDIRECT_INVALID_LOCATION',
  REDIRECT_LOOP: 'REDIRECT_LOOP',
  REDIRECT_SCHEME: 'REDIRECT_SCHEME',
  COOKIE_INVALID: 'COOKIE_INVALID',
  POOL_CLOSED: 'POOL_CLOSED',
  CONNECTION_CLOSED: 'CONNECTION_CLOSED',

  // deadlines and limits
  TIMEOUT_CONNECT: 'TIMEOUT_CONNECT',
  TIMEOUT_HANDSHAKE: 'TIMEOUT_HANDSHAKE',
  TIMEOUT_HEADERS: 'TIMEOUT_HEADERS',
  TIMEOUT_IDLE: 'TIMEOUT_IDLE',
  TIMEOUT_TOTAL: 'TIMEOUT_TOTAL',
  LIMIT_BODY: 'LIMIT_BODY',
  LIMIT_HEADER: 'LIMIT_HEADER',
  LIMIT_REDIRECTS: 'LIMIT_REDIRECTS',

  // configuration
  CONFIG_UNSATISFIABLE: 'CONFIG_UNSATISFIABLE',
  CONFIG_INVALID: 'CONFIG_INVALID',
});

/**
 * Format a byte as 0xNN, for error messages that must name a concrete wire value.
 * @param {number} n
 * @returns {string}
 */
export const hex8 = (n) => `0x${(n & 0xff).toString(16).padStart(2, '0')}`;
/**
 * Format a 16-bit wire value as 0xNNNN (cipher suites, groups, signature schemes).
 * @param {number} n
 * @returns {string}
 */
export const hex16 = (n) => `0x${(n & 0xffff).toString(16).padStart(4, '0')}`;
