// Content-Encoding and charset: the last two transforms between wire bytes and what the
// caller reads. Both are riddled with server-side sloppiness, so both sides are pinned here:
// the request side (what we advertise) and the response side (what we decode) live in one
// file so they cannot drift apart.

import { HttpError, codes } from '../errors.js';

/**
 * What the request layer advertises with no extra decoders registered. The target runtime's
 * DecompressionStream supports ONLY gzip / deflate / deflate-raw (verified empirically);
 * advertising `br` or `zstd` would invite bytes we can never decode, turning every response
 * from a brotli-preferring CDN into garbage. Keep this list and decodeBody in lockstep.
 *
 * It is also exactly what curl sends, which matters because this client presents curl's TLS and
 * HTTP/2 fingerprints by default: a browser-shaped handshake paired with a curl-shaped
 * Accept-Encoding is a mismatch a bot detector can read straight off the wire.
 */
export const ACCEPT_ENCODING = 'gzip, deflate';

/** Codings the runtime decodes itself. Not overridable — see acceptEncodingFor. */
const BUILT_IN = new Set(['gzip', 'x-gzip', 'deflate', 'identity']);

/** An HTTP token, which is what a content-coding name must be (RFC 9110 §5.6.2). */
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9a-z]+$/;

/**
 * The Accept-Encoding to send given the caller's extra decoders.
 *
 * Registering a decoder is what makes advertising its coding honest — the two must move together
 * or the client asks for bytes it cannot read. Order is registration order after the built-ins,
 * so a caller matching a browser can produce exactly `gzip, deflate, br, zstd`.
 *
 * @param {Record<string, BodyDecoder> | null | undefined} decoders
 * @returns {string}
 */
export function acceptEncodingFor(decoders) {
  if (!decoders) return ACCEPT_ENCODING;
  const extra = [];
  for (const name of Object.keys(decoders)) {
    const coding = name.toLowerCase();
    // A name is interpolated into a request header, so anything that is not a bare token could
    // inject a second header field. Reject at registration rather than at send time.
    if (!TOKEN.test(coding)) {
      throw new HttpError(
        codes.HTTP_CONTENT_ENCODING,
        `"${name}" is not a valid content-coding name; expected an HTTP token`,
        { coding: name },
      );
    }
    // A built-in must not be overridable. The runtime decompresses gzip and deflate in its own
    // native code, measured at roughly a third the CPU of the fastest JavaScript implementations,
    // so accepting a replacement would silently trade that away — and the two code paths disagreed
    // about it: this function treated `gzip` as already covered while decodeBody would have used
    // the caller's function. Refusing here makes both paths say the same thing.
    if (BUILT_IN.has(coding)) {
      throw new HttpError(
        codes.HTTP_CONTENT_ENCODING,
        `"${coding}" is decoded by the runtime natively and cannot be replaced; remove it from ` +
          '`decoders`. Only codings this runtime has no decoder for can be supplied.',
        { coding },
      );
    }
    if (typeof decoders[name] !== 'function') {
      throw new HttpError(
        codes.HTTP_CONTENT_ENCODING,
        `the decoder registered for "${coding}" is not a function`,
        { coding },
      );
    }
    extra.push(coding);
  }
  return extra.length ? `${ACCEPT_ENCODING}, ${extra.join(', ')}` : ACCEPT_ENCODING;
}

/** Codings that exist and are real but that this runtime cannot decompress. */
const KNOWN_UNSUPPORTED = new Set(['br', 'zstd', 'compress', 'x-compress']);

/**
 * How much decompressed output one BYOB read may deliver. A BYOB read resolves as soon as at
 * least one byte is available — it never waits for the view to fill — so a large view cannot
 * add latency; it only lets a fast decompressor hand over more per boundary crossing.
 */
const DECOMPRESS_READ_BYTES = 65536;

/**
 * One decompression stage. `sniffDeflate` handles the deflate ambiguity:
 *
 * RFC 9110 says Content-Encoding: deflate means ZLIB-WRAPPED deflate (RFC 1950), but a large
 * population of servers — old IIS most famously — send RAW deflate (RFC 1951) under the same
 * name. Every interoperable client sniffs. The test: a zlib stream starts with a 2-byte header
 * where (b0 & 0x0f) === 8 (CM = deflate) and ((b0 << 8) | b1) % 31 === 0 (the FCHECK checksum,
 * designed for exactly this kind of validation). Raw deflate data cannot systematically fake
 * both, so the check is reliable in practice.
 *
 * The output side is pull-driven and drains the decompressor with a BYOB reader when the
 * runtime supports one (a large view per read), falling back to a default reader elsewhere.
 * This shape is measured, not aesthetic: the target runtime's DecompressionStream emits
 * 4096-byte chunks, and the previous wiring (pipeTo → WritableStream → TransformStream)
 * crossed the JS/runtime boundary several times per chunk — measured on the edge at
 * ~28 ms of CPU per MB of decompressed output for this stage alone, against ~2 ms/MB for
 * the inflate itself. Draining with one 64 KiB read per crossing brings the stage to
 * ~6 ms/MB (A/B-ed old-vs-new inside one isolate: 110 ms vs 23 ms for a 4 MB body).
 * A BYOB read resolves with a partial fill the moment any output exists — verified on the
 * edge with a stalled input, 58 KB arrived into a 1 MB view — so streaming latency is
 * unchanged. Input is still pumped by an independent task: a decompressor legitimately
 * consumes many input chunks before producing output, so tying input progress to output
 * pulls would deadlock.
 */
function decompressionStage(source, coding) {
  const srcReader = source.getReader();
  /** Rejections here surface through the output stream; pre-observed like chunked.js does. */
  let pumpDone = null;
  // The returned stream must exist synchronously, but the format is only known after the
  // 2-byte sniff. `ready` settles with the DecompressionStream once the sniff has run, or
  // with null for a zero-byte body.
  const ready = (async () => {
    // Buffer up to 2 bytes so the deflate sniff (and the empty-body check) can see them.
    const head = [];
    let headLen = 0;
    while (headLen < 2) {
      const { value, done } = await srcReader.read();
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
      return null;
    }
    let format = coding;
    if (coding === 'deflate') {
      const b0 = headLen >= 1 ? firstBytes(head, 0) : -1;
      const b1 = headLen >= 2 ? firstBytes(head, 1) : -1;
      const isZlib = b1 >= 0 && (b0 & 0x0f) === 8 && ((b0 << 8) | b1) % 31 === 0;
      format = isZlib ? 'deflate' : 'deflate-raw';
    }
    const ds = new DecompressionStream(format);
    const dsWriter = ds.writable.getWriter();
    pumpDone = (async () => {
      try {
        for (const chunk of head) await dsWriter.write(chunk);
        for (;;) {
          const { value, done } = await srcReader.read();
          if (done) break;
          if (value && value.byteLength) await dsWriter.write(value);
        }
        await dsWriter.close();
      } catch (e) {
        // Either the source failed (its error must reach the consumer, so error the
        // decompressor's output with it) or the decompressor rejected its input (already
        // errored; the abort is a no-op). Both tear the source down.
        await dsWriter.abort(e).catch(() => {});
        await srcReader.cancel(e).catch(() => {});
        throw e;
      }
    })();
    pumpDone.catch(() => {});
    return ds;
  })();
  ready.catch(() => {});

  /** @type {ReadableStreamBYOBReader | ReadableStreamDefaultReader<Uint8Array> | null} */
  let out = null;
  let byob = false;
  const wrap = (e) =>
    e instanceof HttpError
      ? e
      : new HttpError(
          codes.HTTP_CONTENT_ENCODING,
          `decoding "${coding}" failed: ${e?.message ?? e}`,
          { coding },
        );

  return new ReadableStream({
    async pull(c) {
      try {
        const ds = await ready;
        if (ds === null) {
          c.close();
          return;
        }
        if (out === null) {
          try {
            out = ds.readable.getReader({ mode: 'byob' });
            byob = true;
          } catch {
            // The runtime's DecompressionStream readable is not a byte stream (Node's is
            // not); a default reader delivers the same bytes in the decompressor's own
            // chunking.
            out = ds.readable.getReader();
          }
        }
        for (;;) {
          const { value, done } = byob
            ? await /** @type {ReadableStreamBYOBReader} */ (out)
                .read(new Uint8Array(DECOMPRESS_READ_BYTES))
            : await /** @type {ReadableStreamDefaultReader<Uint8Array>} */ (out).read();
          if (done) {
            // Clean output EOF implies the input pump already closed the decompressor
            // successfully; awaiting it here surfaces any failure that raced the close.
            if (pumpDone) await pumpDone;
            c.close();
            return;
          }
          if (value.byteLength === 0) continue; // legal, carries nothing; keep reading
          c.enqueue(value);
          return;
        }
      } catch (e) {
        // Corrupt compressed data surfaces to the consumer as a stream error, wrapped so the
        // caller sees which coding failed rather than a bare zlib message.
        const err = wrap(e);
        await srcReader.cancel(err).catch(() => {});
        c.error(err);
      }
    },
    async cancel(reason) {
      // The consumer abandoned the decoded body: cancel the source and release the
      // decompressor, exactly as the failure path does — an abandoned stream must still tear
      // the connection down (the pool only reuses a connection whose body reached its framed
      // end). The source goes FIRST: the sniff may still be awaiting it, and `ready` cannot
      // settle until that read resolves.
      await srcReader.cancel(reason).catch(() => {});
      try {
        if (out) {
          await out.cancel(reason);
        } else {
          const ds = await ready.catch(() => null);
          if (ds) await ds.readable.cancel(reason);
        }
      } catch {
        /* the decompressor may already be errored */
      }
    },
  });
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
/**
 * A caller-supplied content decoder: raw coded bytes in, decoded bytes out. Streaming, so a body
 * is never fully buffered on this client's behalf.
 * @typedef {(stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>} BodyDecoder
 */

/**
 * @param {ReadableStream<Uint8Array>} stream the raw body
 * @param {string|null|undefined} contentEncoding the Content-Encoding header value; a
 *   comma-separated list names codings in the order the SERVER applied them, so decoding
 *   applies them in reverse.
 * @param {Record<string, BodyDecoder> | null} [decoders] caller-supplied codings
 * @returns {ReadableStream<Uint8Array>} decoded bytes
 */
export function decodeBody(stream, contentEncoding, decoders = null) {
  /** Look a coding up among the caller's decoders, case-insensitively as the header is. */
  const custom = (coding) => {
    if (!decoders) return null;
    for (const name of Object.keys(decoders)) {
      if (name.toLowerCase() === coding) return decoders[name];
    }
    return null;
  };
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
    // A registered decoder is the caller taking responsibility for this coding; it outranks the
    // built-in refusal, which only ever said "this runtime cannot".
    if (custom(coding)) continue;
    if (KNOWN_UNSUPPORTED.has(coding)) {
      throw new HttpError(
        codes.HTTP_CONTENT_ENCODING,
        `Content-Encoding "${coding}" is not decodable: no decoder is registered for it and this ` +
          "runtime's DecompressionStream " +
          'supports only gzip/deflate/deflate-raw, which is why this client does not advertise ' +
          `"${coding}" in Accept-Encoding — the server should not have sent it. Pass ` +
          `\`decoders: { '${coding}': fn }\` to supply one.`,
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
    // Built-ins take the native path unconditionally; acceptEncodingFor refuses to register one,
    // and this is the same rule stated where the decoding actually happens, so neither entry
    // point can be reached with the other's assumption.
    const fn = BUILT_IN.has(coding) ? null : custom(coding);
    if (fn) {
      const staged = fn(out);
      // A decoder that returns something unreadable would surface far downstream as a confusing
      // stream error; name it here, where the caller can see which coding misbehaved.
      if (!staged || typeof staged.getReader !== 'function') {
        throw new HttpError(
          codes.HTTP_CONTENT_ENCODING,
          `the decoder for "${coding}" did not return a ReadableStream`,
          { coding },
        );
      }
      out = staged;
      continue;
    }
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
