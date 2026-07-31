// Certificate identity matching (RFC 6125 / RFC 9110 s4.3.4), plus the name-subtree predicates
// shared with name-constraint enforcement in path.js.
//
// Positions taken here, all in the fail-closed direction:
//
//   * Only subjectAltName is consulted. The Common Name fallback died in browsers years ago
//     because a CN is free text that CAs historically failed to police; resurrecting it would
//     re-open every "CN=*" misissuance. A certificate with no SAN matches nothing.
//   * No IDNA. Correct IDNA needs the full UTS-46 mapping tables; an approximation would happily
//     equate names that real resolvers distinguish. Callers must present A-labels (punycode);
//     a non-ASCII hostname is refused with a clear error instead of a wrong answer.
//   * Wildcards per current CA/Browser Forum practice: one '*', alone in the leftmost label,
//     covering exactly one label, and never for a name with fewer than two labels behind it.

import { CertificateError, ConfigError, codes } from '../errors.js';
import { equal, toHex } from '../util/bytes.js';

// ------------------------------------------------------------------ IP literal parsing

/** Strict dotted-quad. Leading zeros are refused: "010" is octal to some stacks, ten to others. */
function parseIpv4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i];
    if (!/^[0-9]{1,3}$/.test(p) || (p.length > 1 && p[0] === '0')) return null;
    const v = Number(p);
    if (v > 255) return null;
    out[i] = v;
  }
  return out;
}

/**
 * IPv6 per RFC 4291 s2.2: hex groups, at most one '::' standing for one or more zero groups,
 * optional embedded dotted-quad in the final 32 bits. Zone indices ("%eth0") are refused — they
 * name a local interface and have no meaning in a certificate.
 */
function parseIpv6(text) {
  if (text.includes('%')) return null;
  const halves = text.split('::');
  if (halves.length > 2) return null;

  // Parse one colon-separated run into 16-bit groups. `isTail` marks the run that ends the
  // address, the only place an embedded IPv4 may appear.
  const parseRun = (run, isTail) => {
    if (run === '') return [];
    const groups = [];
    const parts = run.split(':');
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      if (p === '') return null; // ':::' or stray leading/trailing ':'
      if (p.includes('.')) {
        if (!isTail || i !== parts.length - 1) return null;
        const v4 = parseIpv4(p);
        if (!v4) return null;
        groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null;
        groups.push(parseInt(p, 16));
      }
    }
    return groups;
  };

  let groups;
  if (halves.length === 2) {
    const left = parseRun(halves[0], false);
    const right = parseRun(halves[1], true);
    if (!left || !right) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null; // '::' must stand for at least one group
    groups = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    groups = parseRun(text, true);
    if (!groups || groups.length !== 8) return null;
  }
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = groups[i] >> 8;
    out[i * 2 + 1] = groups[i] & 0xff;
  }
  return out;
}

/** Parse an IP literal (v4 dotted-quad or v6, optionally [bracketed]) to raw bytes, else null. */
export function parseIp(text) {
  let t = text;
  if (t.startsWith('[') && t.endsWith(']')) t = t.slice(1, -1);
  if (t.includes(':')) return parseIpv6(t);
  if (/^[0-9.]+$/.test(t)) return parseIpv4(t);
  return null;
}

// ------------------------------------------------------------------ hostname handling

const isAscii = (s) => /^[\x21-\x7e]*$/.test(s);

/**
 * Normalise the caller's requested identity: exactly one trailing dot stripped (an FQDN marker,
 * not part of the identity), ASCII lowercased. Anything unservable throws CONFIG_INVALID — this
 * is the caller's own input, not the peer's, so it is a configuration error, not a mismatch.
 */
function normalizeHostname(hostname) {
  if (typeof hostname !== 'string' || hostname.length === 0) {
    throw new ConfigError(codes.CONFIG_INVALID, 'hostname to verify must be a non-empty string');
  }
  if (hostname.includes('\0')) {
    throw new ConfigError(codes.CONFIG_INVALID, 'hostname contains a NUL byte');
  }
  const ip = parseIp(hostname);
  if (ip) return { ip, host: hostname };
  let host = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
  if (host.length === 0) {
    throw new ConfigError(codes.CONFIG_INVALID, `hostname "${hostname}" has no labels`);
  }
  if (!isAscii(host)) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `hostname "${hostname}" is not ASCII; IDNA is not implemented — pass the A-label (punycode) form`,
    );
  }
  return { ip: null, host: host.toLowerCase() };
}

/**
 * One SAN dNSName against the (lowercased, ASCII) query. Returns false rather than throwing for
 * a malformed SAN entry: the certificate may carry other, valid entries, and a name that cannot
 * be interpreted safely simply cannot match anything.
 */
function dnsNameMatches(san, host) {
  if (san.length === 0 || san.includes('\0') || !isAscii(san)) return false;
  const s = san.toLowerCase();
  if (!s.includes('*')) return s === host;
  // Wildcard rules: the '*' must be the entire leftmost label ("w*.x" and "a.*.b" are refused),
  // must be backed by at least two literal labels ("*.com" would cover a whole TLD), and matches
  // exactly one label — "*.example.com" covers "a.example.com", never "a.b.example.com" and
  // never the bare "example.com".
  if (!s.startsWith('*.')) return false;
  const rest = s.slice(2);
  if (rest.includes('*')) return false;
  const restLabels = rest.split('.');
  if (restLabels.length < 2 || restLabels.some((l) => l.length === 0)) return false;
  const hostLabels = host.split('.');
  if (hostLabels.length !== restLabels.length + 1) return false;
  if (hostLabels[0].length === 0) return false;
  return hostLabels.slice(1).join('.') === rest;
}

const describeIp = (bytes) =>
  bytes.byteLength === 4 ? Array.from(bytes).join('.') : toHex(bytes).replace(/(....)(?=.)/g, '$1:');

/**
 * Verify that `cert` is a certificate for `hostname`. Returns nothing; every non-match throws
 * CERT_NAME_MISMATCH with the entries that were considered, so one log line shows exactly how
 * close the certificate was.
 *
 * @param {ReturnType<import('./x509.js').parseCertificate>} cert
 * @param {string} hostname DNS name (A-label form) or IP literal, per the request URL
 */
export function matchesIdentity(cert, hostname) {
  const { ip, host } = normalizeHostname(hostname);
  const san = cert.subjectAltNames;
  if (!san.present) {
    throw new CertificateError(
      codes.CERT_NAME_MISMATCH,
      `certificate "${cert.subject.text}" has no subjectAltName extension; ` +
        'the Common Name is never consulted, so it cannot match any identity',
      { hostname, subject: cert.subject.text },
    );
  }
  if (ip) {
    // An IP identity matches only iPAddress entries, by raw bytes. A dNSName that happens to
    // spell the same address is a CA mistake, not an identity (RFC 6125 s1.7.2).
    for (const entry of san.ip) {
      if (equal(entry, ip)) return;
    }
    const listed = san.ip.length ? san.ip.map(describeIp).join(', ') : 'none';
    throw new CertificateError(
      codes.CERT_NAME_MISMATCH,
      `IP address ${hostname} does not match certificate "${cert.subject.text}" ` +
        `(iPAddress entries: ${listed})`,
      { hostname, subject: cert.subject.text },
    );
  }
  for (const entry of san.dns) {
    if (dnsNameMatches(entry, host)) return;
  }
  const listed = san.dns.length ? san.dns.join(', ') : 'none';
  throw new CertificateError(
    codes.CERT_NAME_MISMATCH,
    `hostname "${hostname}" does not match certificate "${cert.subject.text}" ` +
      `(dNSName entries: ${listed})`,
    { hostname, subject: cert.subject.text },
  );
}

// ------------------------------------------------------------------ name-constraint predicates

/**
 * RFC 5280 s4.2.1.10 dNSName subtree: a constraint "example.com" covers the host itself and any
 * subdomain, at a label boundary. The seen-in-the-wild ".example.com" form covers subdomains
 * only. An empty constraint covers every DNS name (used by permittedSubtrees to say "any DNS").
 */
export function dnsWithinSubtree(name, base) {
  const n = name.toLowerCase();
  const b = base.toLowerCase();
  if (b === '') return true;
  if (b.startsWith('.')) return n.length > b.length && n.endsWith(b);
  return n === b || n.endsWith(`.${b}`);
}

/** iPAddress subtree: same family, and (address & mask) equal on every byte. */
export function ipWithinSubtree(ip, addr, mask) {
  if (ip.byteLength !== addr.byteLength || addr.byteLength !== mask.byteLength) return false;
  for (let i = 0; i < ip.byteLength; i++) {
    if ((ip[i] & mask[i]) !== (addr[i] & mask[i])) return false;
  }
  return true;
}
