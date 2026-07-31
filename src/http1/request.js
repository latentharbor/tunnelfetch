// HTTP/1.1 request head serialiser.
//
// This is a pure function from a description to bytes. It adds nothing implicitly — no Host, no
// Content-Length, no Connection — because framing and connection management are decisions that
// belong to the layer that owns the socket. A serialiser with hidden defaults cannot be tested
// byte-for-byte, and byte-for-byte tests are the only kind that catch request-splitting bugs.
//
// Everything the caller provides is validated against the RFC 9110 grammar before it is allowed
// anywhere near the wire. A header value containing CR or LF is not "escaped" or "sanitised" —
// it is rejected, because a value that needs sanitising is an injection attempt, and quietly
// rewriting it turns a loud failure into a silent vulnerability.

import { HttpError, codes } from '../errors.js';

// RFC 9110 token: 1*tchar. This is the exact alphabet; anything else in a field name or method
// is either a typo or a smuggling attempt, and both deserve the same rejection.
const TOKEN_RE = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

// request-target: printable ASCII with no whitespace. Covers origin-form (`/path?q`),
// absolute-form (`http://host/path`, required when talking through a forward proxy for
// plain http), authority-form (`host:port` for CONNECT) and asterisk-form (`*`).
// A space or control character in the target splits the request line.
const TARGET_RE = /^[\x21-\x7e]+$/;

// The only versions this layer speaks. Serialising `HTTP/2` framing as text would produce
// garbage a peer might partially interpret, which is worse than failing here.
const VERSIONS = new Set(['1.0', '1.1']);

/** Encode a string whose char codes are all <= 0xFF as raw octets (inverse of bytes.js latin1). */
function latin1Bytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/**
 * Serialise a request head: request line, header fields, terminating blank line.
 *
 * `headers` may be a WHATWG Headers instance or any iterable of [name, value] pairs.
 * Pair iterables are written in caller order, unsorted — order can matter to real servers.
 * Note that a Headers instance has already lost the caller's order by spec (it iterates
 * lowercased and sorted); we serialise its iteration order as-is.
 *
 * @param {{ method: string, target: string, headers?: Headers|Iterable<[string,string]>,
 *           httpVersion?: '1.0'|'1.1' }} req
 * @returns {Uint8Array}
 */
export function serializeRequestHead({ method, target, headers = [], httpVersion = '1.1' }) {
  if (typeof method !== 'string' || !TOKEN_RE.test(method)) {
    throw new HttpError(
      codes.HTTP_REQUEST_LINE,
      `method ${JSON.stringify(method)} is not an RFC 9110 token`,
      { method },
    );
  }
  if (typeof target !== 'string' || !TARGET_RE.test(target)) {
    throw new HttpError(
      codes.HTTP_REQUEST_LINE,
      `request-target ${JSON.stringify(target)} contains whitespace, control bytes, or ` +
        'non-ASCII; targets must arrive here already encoded',
      { target },
    );
  }
  if (!VERSIONS.has(httpVersion)) {
    throw new HttpError(
      codes.HTTP_REQUEST_LINE,
      `httpVersion ${JSON.stringify(httpVersion)} is not supported (only 1.0 and 1.1)`,
      { httpVersion },
    );
  }
  if (headers === null || typeof headers[Symbol.iterator] !== 'function') {
    throw new HttpError(
      codes.HTTP_HEADER,
      'headers must be a Headers instance or an iterable of [name, value] pairs',
    );
  }

  let head = `${method} ${target} HTTP/${httpVersion}\r\n`;
  for (const entry of headers) {
    const name = String(entry[0]);
    const rawValue = String(entry[1]);
    if (!TOKEN_RE.test(name)) {
      throw new HttpError(
        codes.HTTP_HEADER,
        `header name ${JSON.stringify(name)} is not an RFC 9110 token`,
        { name },
      );
    }
    // The request-splitting defence. Checked on the raw value BEFORE trimming, so a value like
    // 'x\r\n' is rejected rather than quietly repaired into something send-safe.
    if (/[\r\n\0]/.test(rawValue)) {
      throw new HttpError(
        codes.HTTP_HEADER,
        `header ${name} value ${JSON.stringify(rawValue)} contains CR, LF, or NUL ` +
          '(header injection rejected)',
        { name, value: rawValue },
      );
    }
    // Field values are opaque octets; a char code over 0xFF has no octet representation and
    // guessing an encoding for it would send bytes the caller never wrote.
    for (let i = 0; i < rawValue.length; i++) {
      if (rawValue.charCodeAt(i) > 0xff) {
        throw new HttpError(
          codes.HTTP_HEADER,
          `header ${name} value contains U+${rawValue.codePointAt(i).toString(16)} which is not ` +
            'representable as a single octet',
          { name, value: rawValue },
        );
      }
    }
    // Leading/trailing OWS is meaningless on the wire (the peer must strip it) and Headers
    // instances arrive pre-trimmed; trimming pair-iterable input keeps both paths identical.
    const value = rawValue.replace(/^[ \t]+|[ \t]+$/g, '');
    head += `${name}: ${value}\r\n`;
  }
  head += '\r\n';
  // Every part was validated to char codes <= 0xFF, so latin1 encoding is exact.
  return latin1Bytes(head);
}
