// Typed errors.
//
// Discipline: an error must be specific enough that one log line decides whether a missing
// feature is worth implementing. "unsupported cipher" is useless; "server selected 0xc02f
// (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) under TLS 1.2, not implemented" is actionable.
// Every throw site therefore carries the concrete value the peer asked for, in `detail`.

/** Base for everything this package throws. Never thrown directly. */
export class TunnelFetchError extends Error {
  /**
   * @param {string} code stable machine-readable code
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

/** Format a byte as 0xNN, for error messages that must name a concrete wire value. */
export const hex8 = (n) => `0x${(n & 0xff).toString(16).padStart(2, '0')}`;
/** Format a 16-bit wire value as 0xNNNN (cipher suites, groups, signature schemes). */
export const hex16 = (n) => `0x${(n & 0xffff).toString(16).padStart(4, '0')}`;
