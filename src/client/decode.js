// Content-Encoding and charset: the last two transforms between wire bytes and what the
// caller reads. Both are riddled with server-side sloppiness, so both sides are pinned here:
// the request side (what we advertise) and the response side (what we decode) live in one
// file so they cannot drift apart.

import { HttpError, codes } from '../errors.js';

/**
 * The exact Accept-Encoding value the request layer must send. The target runtime's
 * DecompressionStream supports ONLY gzip / deflate / deflate-raw (verified empirically);
 * advertising `br` or `zstd` would invite bytes we can never decode, turning every response
 * from a brotli-preferring CDN into garbage. Keep this list and decodeBody in lockstep.
 */
export const ACCEPT_ENCODING = 'gzip, deflate';

/** Codings that exist and are real but that this runtime cannot decompress. */
const KNOWN_UNSUPPORTED = new Set(['br', 'zstd', 'compress', 'x-compress']);

/**
 * One decompression stage. `sniffDeflate` handles the deflate ambiguity:
 *
 * RFC 9110 says Content-Encoding: deflate means ZLIB-WRAPPED deflate (RFC 1950), but a large
 * population of servers — old IIS most famously — send RAW deflate (RFC 1951) under the same
 * name. Every interoperable client sniffs. The test: a zlib stream starts with a 2-byte header
 * where (b0 & 0x0f) === 8 (CM = deflate) and ((b0 << 8) | b1) % 31 === 0 (the FCHECK checksum,
 * designed for exactly this kind of validation). Raw deflate data cannot systematically fake
 * both, so the check is reliable in practice.
 */
function decompressionStage(source, coding) {
  const { readable, writable } = new TransformStream();
  (async () => {
    const reader = source.getReader();
    const writer = writable.getWriter();
    try {
      // Buffer up to 2 bytes so the deflate sniff (and the empty-body check) can see them.
      const head = [];
      let headLen = 0;
      while (headLen < 2) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) {
          head.push(value);
          headLen += value.byteLength;
        }
      }
      if (headLen === 0) {
        // A zero-byte body under a Content-Encoding header is not a valid compressed stream,
        // but CDNs emit it constantly (204-shaped responses, HEAD-derived bodies). Zero bytes
        // in, zero bytes out is the only non-destructive reading, and it is what browsers do.
        await writer.close();
        return;
      }
      let format = coding;
      if (coding === 'deflate') {
        const b0 = headLen >= 1 ? firstBytes(head, 0) : -1;
        const b1 = headLen >= 2 ? firstBytes(head, 1) : -1;
        const isZlib = b1 >= 0 && (b0 & 0x0f) === 8 && ((b0 << 8) | b1) % 31 === 0;
        format = isZlib ? 'deflate' : 'deflate-raw';
      }
      const ds = new DecompressionStream(format);
      const pump = ds.readable.pipeTo(
        new WritableStream({
          write: (chunk) => writer.write(chunk),
        }),
      );
      // If corrupt input errors the decompressor while we are still writing into it, the write
      // below rejects first and control jumps to the catch — leaving `pump` rejected with no
      // listener. Pre-attach a no-op handler so that cannot surface as an unhandled rejection;
      // `await pump` on the success path still observes the real rejection.
      pump.catch(() => {});
      const dsWriter = ds.writable.getWriter();
      for (const chunk of head) await dsWriter.write(chunk);
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) await dsWriter.write(value);
      }
      await dsWriter.close();
      await pump;
      await writer.close();
    } catch (e) {
      // Corrupt compressed data surfaces to the consumer as a stream error, wrapped so the
      // caller sees which coding failed rather than a bare zlib message.
      const err =
        e instanceof HttpError
          ? e
          : new HttpError(
              codes.HTTP_CONTENT_ENCODING,
              `decoding "${coding}" failed: ${e?.message ?? e}`,
              { coding },
            );
      await writer.abort(err).catch(() => {});
      await reader.cancel(err).catch(() => {});
    }
  })();
  return readable;
}

/** Byte at logical offset `i` across the buffered head chunks. */
function firstBytes(chunks, i) {
  for (const c of chunks) {
    if (i < c.byteLength) return c[i];
    i -= c.byteLength;
  }
  return -1;
}

/**
 * Undo the response's Content-Encoding.
 *
 * @param {ReadableStream<Uint8Array>} stream the raw body
 * @param {string|null|undefined} contentEncoding the Content-Encoding header value; a
 *   comma-separated list names codings in the order the SERVER applied them, so decoding
 *   applies them in reverse.
 * @returns {ReadableStream<Uint8Array>} decoded bytes
 */
export function decodeBody(stream, contentEncoding) {
  const codings = (contentEncoding ?? '')
    .split(',')
    .map((c) => c.trim().toLowerCase())
    .filter((c) => c !== '');
  // Validate the whole list before wiring any stage, so an unsupported coding is a clean
  // synchronous throw rather than a half-consumed stream.
  for (const coding of codings) {
    if (coding === 'gzip' || coding === 'x-gzip' || coding === 'deflate' || coding === 'identity') {
      continue;
    }
    if (KNOWN_UNSUPPORTED.has(coding)) {
      throw new HttpError(
        codes.HTTP_CONTENT_ENCODING,
        `Content-Encoding "${coding}" is not decodable: this runtime's DecompressionStream ` +
          'supports only gzip/deflate/deflate-raw, which is why this client never advertises ' +
          `"${coding}" in Accept-Encoding — the server should not have sent it`,
        { coding },
      );
    }
    throw new HttpError(codes.HTTP_CONTENT_ENCODING, `unknown Content-Encoding "${coding}"`, {
      coding,
    });
  }
  let out = stream;
  for (let i = codings.length - 1; i >= 0; i--) {
    const coding = codings[i];
    if (coding === 'identity') continue; // no-op by definition
    out = decompressionStage(out, coding === 'x-gzip' ? 'gzip' : coding);
  }
  return out;
}

// --------------------------------------------------------------------------- charset

/**
 * Extract the charset parameter from a Content-Type value, handling quoting and other
 * parameters: `text/html; boundary=x; charset="ISO-8859-4"` -> 'iso-8859-4'.
 * @param {string | null | undefined} contentType
 * @returns {string|null} lowercased charset label, or null when none is declared
 */
export function charsetFromContentType(contentType) {
  if (!contentType) return null;
  // Parameters after the first ';'. A quoted-string value may contain ';', which a naive
  // split would sever — scan parameters with a regex that consumes quoted strings whole.
  const re = /;\s*([^=;\s]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)/g;
  let m;
  let charset = null;
  while ((m = re.exec(contentType)) !== null) {
    if (m[1].toLowerCase() !== 'charset') continue;
    let v = m[2].trim();
    if (v.length >= 2 && v[0] === '"' && v.at(-1) === '"') {
      v = v.slice(1, -1).replace(/\\(.)/g, '$1');
    }
    if (v !== '') charset = v.toLowerCase(); // last occurrence wins, like header params do
  }
  return charset;
}

/** BOM sniff: the byte-order mark is ground truth about the bytes that follow. */
function bomCharset(bytes) {
  if (!bytes || bytes.byteLength < 2) return null;
  if (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return 'utf-8';
  }
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return 'utf-16be';
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return 'utf-16le';
  return null;
}

/** Case-insensitive `<meta charset>` prescan over the first 1024 bytes of an HTML body. */
function metaCharset(bytes) {
  const window = bytes.subarray(0, 1024);
  // The prescan is defined over ASCII bytes; decoding as latin-1 maps every byte 1:1 to a
  // code unit, so the regex indexes cannot be shifted by multi-byte sequences.
  let s = '';
  for (let i = 0; i < window.byteLength; i++) s += String.fromCharCode(window[i]);
  s = s.toLowerCase();
  // Both meta forms declare with `charset=`: <meta charset=utf-8> directly, and
  // <meta http-equiv=content-type content="text/html; charset=utf-8"> inside content=.
  const tagRe = /<meta\b[^>]*>/g;
  let tag;
  while ((tag = tagRe.exec(s)) !== null) {
    const m = /charset\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s;"'>]+))/.exec(tag[0]);
    if (m) {
      const label = (m[1] ?? m[2] ?? m[3] ?? '').trim();
      if (label) return label;
    }
  }
  return null;
}

/**
 * Decide the charset for a response body.
 *
 * Precedence: BOM > Content-Type charset parameter > (text/html only) meta prescan > utf-8.
 * The BOM outranks even an explicit header because it describes the actual bytes, and servers
 * that recode content routinely forget to update the header; this is WHATWG "decode" order.
 * The utf-8 default matches Response.text() in fetch — for a client whose callers are code,
 * matching fetch is worth more than matching the legacy HTML default of windows-1252.
 *
 * @param {string|null|undefined} contentType
 * @param {Uint8Array} [bodyPrefix] the first bytes of the body (>= 1024 to satisfy the prescan)
 * @returns {string} a charset label for decodeText
 */
export function charsetFor(contentType, bodyPrefix) {
  const bom = bodyPrefix ? bomCharset(bodyPrefix) : null;
  if (bom) return bom;
  const declared = charsetFromContentType(contentType);
  if (declared) return declared;
  const mime = (contentType ?? '').split(';')[0].trim().toLowerCase();
  if (mime === 'text/html' && bodyPrefix) {
    const meta = metaCharset(bodyPrefix);
    if (meta) return meta.toLowerCase();
  }
  return 'utf-8';
}

/**
 * Decode bytes with a charset label.
 *
 * TextDecoder implements the WHATWG encoding registry, which is the alias table every browser
 * uses. Note one alias that looks like a bug and is not: `iso-8859-1` (and `latin1`, `ascii`)
 * maps to windows-1252, per WHATWG — the bytes 0x80-0x9F decode to the punctuation everyone
 * actually means, not C1 controls. A BOM matching the charset is stripped (TextDecoder default),
 * which is also what Response.text() does.
 *
 * Throws HttpError (HTTP_CHARSET) for a label outside the WHATWG encoding registry.
 *
 * @param {Uint8Array} bytes
 * @param {string} [charset]
 * @returns {string}
 */
export function decodeText(bytes, charset = 'utf-8') {
  let decoder;
  try {
    decoder = new TextDecoder(charset);
  } catch {
    throw new HttpError(
      codes.HTTP_CHARSET,
      `charset label "${charset}" is not a supported encoding`,
      { charset },
    );
  }
  return decoder.decode(bytes);
}
