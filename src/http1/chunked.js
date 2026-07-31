// Chunked transfer-coding decoder (RFC 9112 §7.1).
//
// Chunked framing is the only place in HTTP/1.1 where the peer controls both the lengths and
// the delimiters, which makes it the classic smuggling surface. The rules here are therefore
// grammar-exact: a chunk size is HEX digits and nothing else (no sign, no leading whitespace,
// no `0x`), chunk data must be followed by exactly CRLF, and any deviation is an error rather
// than a resynchronisation attempt. A decoder that "recovers" from a framing error has silently
// agreed to a different message boundary than the sender — that is how one response's bytes
// become the next response's head.
//
// The data phase is driven purely by the declared length, never by delimiter scanning, so
// payload bytes that happen to contain CRLF (or another chunk header) are inert.

import { HttpError, LimitError, codes } from '../errors.js';
import { latin1, utf8, UnexpectedEofError } from '../util/bytes.js';

const LF = utf8('\n');

// RFC 9110 token, for trailer field names. Kept local: importing it from response.js would
// create a cycle (response.js imports this module for body framing).
const TOKEN_RE = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

// chunk-size [chunk-ext]: hex digits, then optionally BWS and a `;`-introduced extension we
// discard. The alternation is anchored so `+1`, `-1`, ` 1`, `0x1` and a bare trailing space
// all fail to match instead of parsing as a number.
const SIZE_LINE_RE = /^([0-9A-Fa-f]+)(?:[ \t]*;.*)?$/;

// field-value content: HTAB / SP / VCHAR / obs-text. Excludes NUL, CR, LF and other controls.
const FIELD_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/;

// A chunk-size line has no business being long: 13 hex digits already cover every size a safe
// integer can hold, and extensions are ignored. The bound stops a peer from streaming an
// unbounded "extension" that we would otherwise buffer while looking for its CRLF.
const CHUNK_LINE_MAX = 1024;

/** A promise with its settle functions exposed, pre-detached so an unobserved rejection
 * (caller consumed the stream but never awaited `trailers`) cannot crash the process. */
function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => {});
  return { promise, resolve, reject };
}

/** Read one CRLF-terminated line for chunk framing, mapping low-level failures to HTTP codes. */
async function readChunkLine(reader, what) {
  let raw;
  try {
    raw = await reader.readUntil(LF, CHUNK_LINE_MAX, what);
  } catch (e) {
    if (e instanceof UnexpectedEofError) {
      throw new HttpError(codes.HTTP_BODY_TRUNCATED, `stream ended inside ${what}`, {
        what,
        got: e.detail?.got,
      });
    }
    if (e instanceof LimitError) {
      // readUntil reports LIMIT_HEADER, but an endless chunk-size line is a framing attack,
      // not an oversized header block; keep the code honest.
      throw new HttpError(codes.HTTP_CHUNK, `${what} exceeded ${CHUNK_LINE_MAX} bytes`, { what });
    }
    throw e;
  }
  const line = latin1(raw);
  if (line.length < 2 || !line.endsWith('\r\n')) {
    throw new HttpError(codes.HTTP_CHUNK, `${what} ended with bare LF, expected CRLF`, {
      what,
      line,
    });
  }
  return line.slice(0, -2);
}

/**
 * Read the trailer section: zero or more `name: value` lines, then an empty line.
 * The empty line doubles as the terminal CRLF of the whole chunked body.
 */
async function readTrailers(reader, maxTrailerBytes) {
  const trailers = new Headers();
  let left = maxTrailerBytes;
  for (;;) {
    let raw;
    try {
      // The budget shrinks per line so the whole section is bounded, and readUntil's own
      // LIMIT_HEADER is the right code here: trailers are header fields.
      raw = await reader.readUntil(LF, left, 'trailer section');
    } catch (e) {
      if (e instanceof UnexpectedEofError) {
        throw new HttpError(
          codes.HTTP_BODY_TRUNCATED,
          'stream ended inside the trailer section, before the terminal CRLF',
        );
      }
      throw e;
    }
    left -= raw.byteLength;
    const line = latin1(raw);
    if (line.length < 2 || !line.endsWith('\r\n')) {
      throw new HttpError(codes.HTTP_TRAILER, 'trailer line ended with bare LF, expected CRLF', {
        line,
      });
    }
    const s = line.slice(0, -2);
    if (s === '') return trailers;
    if (s[0] === ' ' || s[0] === '\t') {
      // obs-fold; deprecated, and a folded line is exactly how a smuggled field hides.
      throw new HttpError(codes.HTTP_TRAILER, 'trailer line starts with whitespace (obs-fold)', {
        line: s,
      });
    }
    const colon = s.indexOf(':');
    if (colon <= 0) {
      throw new HttpError(codes.HTTP_TRAILER, `trailer line ${JSON.stringify(s)} has no name`, {
        line: s,
      });
    }
    const name = s.slice(0, colon);
    if (!TOKEN_RE.test(name)) {
      throw new HttpError(
        codes.HTTP_TRAILER,
        `trailer name ${JSON.stringify(name)} is not an RFC 9110 token`,
        { name },
      );
    }
    const value = s.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, '');
    if (!FIELD_VALUE_RE.test(value)) {
      throw new HttpError(
        codes.HTTP_TRAILER,
        `trailer ${name} value contains a control byte`,
        { name, value },
      );
    }
    // Framing cannot be re-litigated here: the body length was already decided, so even a
    // trailer named Content-Length is inert data and is stored, not interpreted.
    trailers.append(name, value);
  }
}

/**
 * Every cap is fail-closed: the peer controls chunk sizes and counts, so each one bounds what
 * a hostile sender can make us buffer.
 * @typedef {object} ChunkedOptions
 * @property {number} [maxBytes] total payload cap, default unlimited
 * @property {number} [maxChunkSize] per-chunk cap, default 64 MiB
 * @property {number} [maxTrailerBytes] trailer-section cap, default 8192
 */

/**
 * Decode a chunked body from `reader`.
 *
 * Returns `{ stream, trailers }`:
 * - `stream`: ReadableStream<Uint8Array> of the decoded payload octets.
 * - `trailers`: Promise<Headers|null>. Resolves with the trailer fields once the terminal
 *   chunk and its trailing CRLF have been fully consumed — i.e. the reader is positioned
 *   exactly after the body, which is the signal a connection pool needs before reuse.
 *   Resolves null if the stream is cancelled before that point (position unknown, do not
 *   reuse). Rejects with the same error the stream errors with on a protocol violation.
 *
 * Reads only what the chunked grammar covers; any bytes after the terminal CRLF stay in
 * `reader` for the next message.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {ChunkedOptions} [opts]
 * @returns {{ stream: ReadableStream<Uint8Array>, trailers: Promise<Headers | null> }}
 */
export function decodeChunked(
  reader,
  { maxBytes = Infinity, maxChunkSize = 64 * 1024 * 1024, maxTrailerBytes = 8192 } = {},
) {
  let state = 'size'; // 'size' -> 'data' -> 'data-crlf' -> 'size' ... -> 'done'
  let remaining = 0; // data bytes left in the current chunk
  let total = 0; // payload bytes delivered so far, for maxBytes
  const t = deferred();

  // Loop until we have enqueued payload or closed; a pull that returns without either would
  // just be re-invoked by the stream machinery, so we save the round-trips.
  async function drive(c) {
    for (;;) {
      if (state === 'size') {
        const line = await readChunkLine(reader, 'chunk size line');
        const m = SIZE_LINE_RE.exec(line);
        if (!m) {
          throw new HttpError(
            codes.HTTP_CHUNK,
            `malformed chunk size line ${JSON.stringify(line)}`,
            { line },
          );
        }
        const size = parseInt(m[1], 16);
        if (!Number.isSafeInteger(size)) {
          throw new HttpError(
            codes.HTTP_CHUNK,
            `chunk size 0x${m[1]} overflows a safe integer`,
            { hex: m[1] },
          );
        }
        if (size > maxChunkSize) {
          throw new HttpError(
            codes.HTTP_CHUNK,
            `chunk size ${size} exceeds maxChunkSize ${maxChunkSize}`,
            { size, limit: maxChunkSize },
          );
        }
        if (size === 0) {
          const trailers = await readTrailers(reader, maxTrailerBytes);
          state = 'done';
          t.resolve(trailers);
          c.close();
          return;
        }
        // Checked at the size line, before any data is buffered, so an over-limit body is
        // rejected for the price of one line rather than maxBytes of transfer.
        if (total + size > maxBytes) {
          throw new LimitError(
            codes.LIMIT_BODY,
            `chunked body reached ${total + size} bytes, over the ${maxBytes} byte limit`,
            { limit: maxBytes },
          );
        }
        remaining = size;
        state = 'data';
      } else if (state === 'data') {
        // Length-driven, and capped at `remaining` so we can never consume past the chunk
        // into the framing that follows it.
        const chunk = await reader.readSome(Math.min(remaining, 65536));
        if (chunk === null) {
          throw new HttpError(
            codes.HTTP_BODY_TRUNCATED,
            `stream ended with ${remaining} bytes of a chunk unread`,
            { remaining },
          );
        }
        remaining -= chunk.byteLength;
        total += chunk.byteLength;
        if (remaining === 0) state = 'data-crlf';
        c.enqueue(chunk);
        return;
      } else if (state === 'data-crlf') {
        let two;
        try {
          two = await reader.readExactly(2, 'CRLF after chunk data');
        } catch (e) {
          if (e instanceof UnexpectedEofError) {
            throw new HttpError(codes.HTTP_BODY_TRUNCATED, 'stream ended after chunk data, ' +
              'before its CRLF');
          }
          throw e;
        }
        if (two[0] !== 0x0d || two[1] !== 0x0a) {
          // The sender's size and its actual data disagree. Resynchronising here would mean
          // guessing where the message really ends, so this is fatal.
          const got = `0x${two[0].toString(16)} 0x${two[1].toString(16)}`;
          throw new HttpError(
            codes.HTTP_CHUNK,
            `chunk data not followed by CRLF (got ${got})`,
            { got: [two[0], two[1]] },
          );
        }
        state = 'size';
      } else {
        c.close();
        return;
      }
    }
  }

  const stream = new ReadableStream({
    async pull(c) {
      try {
        await drive(c);
      } catch (e) {
        state = 'done';
        t.reject(e);
        c.error(e);
      }
    },
    cancel() {
      // Cancellation abandons the connection at an unknown byte position; `null` tells the
      // caller there are no trailers and, implicitly, that the socket must not be reused.
      state = 'done';
      t.resolve(null);
    },
  });

  return { stream, trailers: t.promise };
}
