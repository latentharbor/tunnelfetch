/**
 * Parse an IP literal (v4 dotted-quad or v6, optionally [bracketed]) to raw bytes, else null.
 * @param {string} text
 * @returns {Uint8Array | null}
 */
export function parseIp(text: string): Uint8Array | null;
/**
 * Verify that `cert` is a certificate for `hostname`. Returns nothing; every non-match throws
 * CERT_NAME_MISMATCH with the entries that were considered, so one log line shows exactly how
 * close the certificate was.
 *
 * @param {import('./x509.js').Certificate} cert
 * @param {string} hostname DNS name (A-label form) or IP literal, per the request URL
 * @returns {void}
 */
export function matchesIdentity(cert: import("./x509.js").Certificate, hostname: string): void;
/**
 * RFC 5280 s4.2.1.10 dNSName subtree: a constraint "example.com" covers the host itself and any
 * subdomain, at a label boundary. The seen-in-the-wild ".example.com" form covers subdomains
 * only. An empty constraint covers every DNS name (used by permittedSubtrees to say "any DNS").
 * @param {string} name
 * @param {string} base
 * @returns {boolean}
 */
export function dnsWithinSubtree(name: string, base: string): boolean;
/**
 * iPAddress subtree: same family, and (address & mask) equal on every byte.
 * @param {Uint8Array} ip
 * @param {Uint8Array} addr
 * @param {Uint8Array} mask
 * @returns {boolean}
 */
export function ipWithinSubtree(ip: Uint8Array, addr: Uint8Array, mask: Uint8Array): boolean;
