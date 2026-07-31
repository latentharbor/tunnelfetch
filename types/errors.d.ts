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
    constructor(code: string, message: string, detail?: Record<string, unknown>);
    code: string;
    detail: Record<string, unknown> | undefined;
}
/** Proxy handshake failed: CONNECT refused, SOCKS5 rejected, auth required. */
export class ProxyError extends TunnelFetchError {
}
/** HTTP/1.1 wire format: malformed message, ambiguous framing, truncated body. */
export class HttpError extends TunnelFetchError {
}
/** TLS record layer, handshake, or a peer alert. */
export class TlsError extends TunnelFetchError {
}
/**
 * The peer offered something we deliberately do not implement.
 * Separate from TlsError so "we cannot talk to this server" is distinguishable from
 * "the connection broke", which is the difference between a feature request and a bug report.
 */
export class TlsUnsupportedError extends TlsError {
}
/** Certificate chain, trust anchor, name matching, validity, or constraint failure. */
export class CertificateError extends TunnelFetchError {
}
/** A deadline elapsed. `phase` says which one, because the fix differs per phase. */
export class TimeoutError extends TunnelFetchError {
}
/** A configured limit was exceeded (response size, header size, redirect count). */
export class LimitError extends TunnelFetchError {
}
/** The caller asked for something the chosen transport cannot honour. */
export class ConfigError extends TunnelFetchError {
}
export namespace codes {
    let PROXY_CONNECT_REFUSED: "PROXY_CONNECT_REFUSED";
    let PROXY_AUTH_REQUIRED: "PROXY_AUTH_REQUIRED";
    let PROXY_AUTH_FAILED: "PROXY_AUTH_FAILED";
    let PROXY_PROTOCOL: "PROXY_PROTOCOL";
    let PROXY_UNREACHABLE: "PROXY_UNREACHABLE";
    let SOCKS5_NO_ACCEPTABLE_AUTH: "SOCKS5_NO_ACCEPTABLE_AUTH";
    let SOCKS5_REPLY: "SOCKS5_REPLY";
    let SOCKS5_ADDR_TYPE: "SOCKS5_ADDR_TYPE";
    let HTTP_REQUEST_LINE: "HTTP_REQUEST_LINE";
    let HTTP_STATUS_LINE: "HTTP_STATUS_LINE";
    let HTTP_HEADER: "HTTP_HEADER";
    let HTTP_FRAMING_AMBIGUOUS: "HTTP_FRAMING_AMBIGUOUS";
    let HTTP_CHUNK: "HTTP_CHUNK";
    let HTTP_BODY_TRUNCATED: "HTTP_BODY_TRUNCATED";
    let HTTP_TRAILER: "HTTP_TRAILER";
    let HTTP_UPGRADE_UNEXPECTED: "HTTP_UPGRADE_UNEXPECTED";
    let TLS_RECORD: "TLS_RECORD";
    let TLS_ALERT: "TLS_ALERT";
    let TLS_HANDSHAKE: "TLS_HANDSHAKE";
    let TLS_TRUNCATED: "TLS_TRUNCATED";
    let TLS_VERSION_UNSUPPORTED: "TLS_VERSION_UNSUPPORTED";
    let TLS_CIPHER_UNSUPPORTED: "TLS_CIPHER_UNSUPPORTED";
    let TLS_GROUP_UNSUPPORTED: "TLS_GROUP_UNSUPPORTED";
    let TLS_SIGALG_UNSUPPORTED: "TLS_SIGALG_UNSUPPORTED";
    let TLS_EXTENSION_UNSUPPORTED: "TLS_EXTENSION_UNSUPPORTED";
    let TLS_ALPN: "TLS_ALPN";
    let CERT_PARSE: "CERT_PARSE";
    let CERT_CHAIN_INCOMPLETE: "CERT_CHAIN_INCOMPLETE";
    let CERT_UNTRUSTED_ROOT: "CERT_UNTRUSTED_ROOT";
    let CERT_SIGNATURE_INVALID: "CERT_SIGNATURE_INVALID";
    let CERT_SIGNATURE_WEAK: "CERT_SIGNATURE_WEAK";
    let CERT_SIGNATURE_UNSUPPORTED: "CERT_SIGNATURE_UNSUPPORTED";
    let CERT_EXPIRED: "CERT_EXPIRED";
    let CERT_NOT_YET_VALID: "CERT_NOT_YET_VALID";
    let CERT_NAME_MISMATCH: "CERT_NAME_MISMATCH";
    let CERT_CONSTRAINT: "CERT_CONSTRAINT";
    let CERT_PIN_MISMATCH: "CERT_PIN_MISMATCH";
    let HTTP_CONTENT_ENCODING: "HTTP_CONTENT_ENCODING";
    let HTTP_CHARSET: "HTTP_CHARSET";
    let REDIRECT_INVALID_LOCATION: "REDIRECT_INVALID_LOCATION";
    let REDIRECT_LOOP: "REDIRECT_LOOP";
    let REDIRECT_SCHEME: "REDIRECT_SCHEME";
    let COOKIE_INVALID: "COOKIE_INVALID";
    let POOL_CLOSED: "POOL_CLOSED";
    let CONNECTION_CLOSED: "CONNECTION_CLOSED";
    let TIMEOUT_CONNECT: "TIMEOUT_CONNECT";
    let TIMEOUT_HANDSHAKE: "TIMEOUT_HANDSHAKE";
    let TIMEOUT_HEADERS: "TIMEOUT_HEADERS";
    let TIMEOUT_IDLE: "TIMEOUT_IDLE";
    let TIMEOUT_TOTAL: "TIMEOUT_TOTAL";
    let LIMIT_BODY: "LIMIT_BODY";
    let LIMIT_HEADER: "LIMIT_HEADER";
    let LIMIT_REDIRECTS: "LIMIT_REDIRECTS";
    let CONFIG_UNSATISFIABLE: "CONFIG_UNSATISFIABLE";
    let CONFIG_INVALID: "CONFIG_INVALID";
}
export function hex8(n: number): string;
export function hex16(n: number): string;
/**
 * One of the stable machine-readable codes in {@link codes}. Exported as a named union so a
 * caller can exhaustively switch on `err.code` and have the compiler point at the case they
 * forgot when a release adds one.
 */
export type ErrorCode = (typeof codes)[keyof typeof codes];
