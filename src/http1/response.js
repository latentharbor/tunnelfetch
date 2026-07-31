// HTTP/1.1 response head parsing and body framing (RFC 9112 §4, §6.3).
//
// Framing is the part of an HTTP client where a bug is not a crash but a desynchronisation:
// read one byte too many and the next response's status line is gone; read one too few and this
// response's tail becomes the next response's head, attributing a payload to the wrong request.
// Everything here therefore fails closed. A message whose length is ambiguous (TE and CL both
// present, disagreeing duplicate CLs, a transfer coding we cannot decode) is an error, never a
// judgement call — RFC 9112 documents every one of these as a request-smuggling vector.

import { HttpError, LimitError, codes } from '../errors.js';
import { latin1, utf8 } from '../util/bytes.js';
import { decodeChunked } from './chunked.js';

const LF = utf8('\n');

// RFC 9110 token, for header field names. Duplicated in request.js/chunked.js rather than
// shared: it is one line, and a shared module would create an import cycle with chunked.js.
const TOKEN_RE = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

// status-line: HTTP-version SP status-code [ SP [ reason-phrase ] ].
// Exactly one space between fields, exactly three digits, and the reason phrase (with its
// leading space) may be absent entirely — `HTTP/1.1 200\r\n` is a legal status line.
const STATUS_LINE_RE = /^HTTP\/(1\.[01]) ([0-9]{3})(?: (.*))?$/;

// reason-phrase and field-value content: HTAB / SP / VCHAR / obs-text.
// Excludes NUL, CR, LF and every other control byte. Header values are opaque octets in the
// 0x80-0xFF range (decoded as latin1, never UTF-8), but control bytes have no place in them.
const FIELD_VALUE_RE = /^[\t\x20-\x7e\x80-\xff]*$/;

/** See deferred() in chunked.js: settle functions exposed, rejection pre-observed. */
function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  promise.catch(() => {});
  return { promise, resolve, reject };
}

/**
 * Read one CRLF-terminated line of the head. `budget.left` is shared across every line of
 * every head (including 1xx heads), so the total is bounded no matter how the peer shapes it.
 * The LF is the search needle so a bare-LF line is a named error instead of a stuck scan.
 */
async function readHeadLine(reader, budget, what, code) {
  const raw = await reader.readUntil(LF, budget.left, what); // throws LIMIT_HEADER over budget
  budget.left -= raw.byteLength;
  const line = latin1(raw);
  if (line.length < 2 || !line.endsWith('\r\n')) {
    throw new HttpError(code, `${what}: line ended with bare LF, expected CRLF`, { line });
  }
  return line.slice(0, -2);
}

/** Parse one head (status line + header fields + blank line) off the reader. */
async function readOneHead(reader, budget) {
  const statusLine = await readHeadLine(reader, budget, 'status line', codes.HTTP_STATUS_LINE);
  const m = STATUS_LINE_RE.exec(statusLine);
  if (!m) {
    throw new HttpError(
      codes.HTTP_STATUS_LINE,
      `malformed status line ${JSON.stringify(statusLine)}`,
      { line: statusLine },
    );
  }
  const httpVersion = m[1];
  const status = Number(m[2]);
  const statusText = m[3] ?? '';
  if (status < 100) {
    // Grammatically three digits, semantically nothing: 0xx fits no status class and any
    // behaviour we picked for it would be invented.
    throw new HttpError(codes.HTTP_STATUS_LINE, `status code ${m[2]} is not a valid status`, {
      status: m[2],
    });
  }
  if (!FIELD_VALUE_RE.test(statusText)) {
    throw new HttpError(codes.HTTP_STATUS_LINE, 'reason phrase contains a control byte', {
      line: statusLine,
    });
  }

  const headers = new Headers();
  const setCookie = [];
  for (;;) {
    const line = await readHeadLine(reader, budget, 'header field', codes.HTTP_HEADER);
    if (line === '') break;
    if (line[0] === ' ' || line[0] === '\t') {
      // obs-fold. Deprecated by RFC 9112, and a folded continuation is a smuggling vector:
      // two parsers that disagree on folding disagree on what the header said.
      throw new HttpError(
        codes.HTTP_HEADER,
        'header line starts with whitespace (obs-fold is rejected)',
        { line },
      );
    }
    const colon = line.indexOf(':');
    if (colon <= 0) {
      throw new HttpError(codes.HTTP_HEADER, `header line ${JSON.stringify(line)} has no name`, {
        line,
      });
    }
    const name = line.slice(0, colon);
    // Also rejects `Name : value` — whitespace before the colon makes name-based routing
    // ambiguous, which is why RFC 9112 §5.1 forbids it. Space is not a tchar.
    if (!TOKEN_RE.test(name)) {
      throw new HttpError(
        codes.HTTP_HEADER,
        `header name ${JSON.stringify(name)} is not an RFC 9110 token`,
        { name },
      );
    }
    const value = line.slice(colon + 1).replace(/^[ \t]+|[ \t]+$/g, '');
    if (!FIELD_VALUE_RE.test(value)) {
      throw new HttpError(codes.HTTP_HEADER, `header ${name} value contains a control byte`, {
        name,
        value,
      });
    }
    // Headers folds duplicates with ", ", which is correct for every list-valued field but
    // destroys Set-Cookie (its values contain commas in Expires dates). Keep the raw values
    // separately or no cookie jar can ever be built on top of this parser.
    if (name.toLowerCase() === 'set-cookie') setCookie.push(value);
    headers.append(name, value);
  }
  return { httpVersion, status, statusText, headers, setCookie };
}

/**
 * One skipped 1xx head. Kept because Early Hints (103) carry Link headers a caller may want;
 * everything else about a 1xx is noise by definition.
 * @typedef {object} InformationalHead
 * @property {'1.0' | '1.1'} httpVersion
 * @property {number} status
 * @property {string} statusText
 * @property {Headers} headers
 */

/**
 * The parsed response head. `setCookie` repeats the raw Set-Cookie values because the Headers
 * class folds duplicates with ", ", which destroys cookie dates — no jar can be built from the
 * folded form.
 * @typedef {object} ResponseHead
 * @property {'1.0' | '1.1'} httpVersion only versions the status-line grammar admits
 * @property {number} status
 * @property {string} statusText may be empty; `HTTP/1.1 200` is a legal status line
 * @property {Headers} headers
 * @property {string[]} setCookie one entry per Set-Cookie header, unfolded
 * @property {InformationalHead[]} informational 1xx heads skipped before the real response
 */

/**
 * @typedef {object} ReadHeadOptions
 * @property {number} [maxHeaderBytes] budget for the ENTIRE head phase, default 65536
 */

/**
 * Read the response head: status line and header fields, plus any preceding informational
 * (1xx) responses, which are legal noise before the real response (100 Continue, 103 Early
 * Hints). They are skipped — 1xx never has a body — and returned in `informational` so a
 * caller can surface Early Hints. 101 is fatal: this client never offers an upgrade, so a
 * peer switching protocols means the bytes that follow are not HTTP and cannot be framed.
 * Malformed heads throw HttpError; an oversized head throws LimitError.
 *
 * `maxHeaderBytes` bounds the ENTIRE head phase, informational heads included; a per-head
 * budget would let a peer stream 1xx responses forever.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {ReadHeadOptions} [opts]
 * @returns {Promise<ResponseHead>}
 */
export async function readResponseHead(reader, { maxHeaderBytes = 65536 } = {}) {
  const budget = { left: maxHeaderBytes };
  const informational = [];
  for (;;) {
    const head = await readOneHead(reader, budget);
    if (head.status >= 100 && head.status <= 199) {
      if (head.status === 101) {
        throw new HttpError(
          codes.HTTP_UPGRADE_UNEXPECTED,
          '101 Switching Protocols received, but no upgrade was offered',
          { statusText: head.statusText },
        );
      }
      informational.push({
        httpVersion: head.httpVersion,
        status: head.status,
        statusText: head.statusText,
        headers: head.headers,
      });
      continue;
    }
    return { ...head, informational };
  }
}

/** Split a folded list-valued header into trimmed elements, dropping empty ones (RFC 9110
 * tells recipients to tolerate a reasonable number of empty list elements). */
function listElements(value) {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '');
}

/**
 * How a response body is delimited. The four kinds are exhaustive: RFC 9112 §6.3 admits no
 * fifth, and everything ambiguous throws before a kind is chosen.
 * @typedef {'none' | 'content-length' | 'chunked' | 'until-close'} FramingKind
 */

/**
 * The framing decision. `length` is present exactly when `kind` is 'content-length'.
 * @typedef {object} Framing
 * @property {FramingKind} kind
 * @property {number} [length] declared byte count, content-length framing only
 * @property {boolean} keepAliveEligible whether the socket MAY be reused after the body ends
 *   as framed; see bodyFraming for why this is the load-bearing bit
 */

/**
 * Decide how the response body is delimited, per RFC 9112 §6.3, in its order. Ambiguous
 * framing (TE and CL together, disagreeing duplicate CLs, an undecodable transfer coding)
 * throws HttpError with HTTP_FRAMING_AMBIGUOUS — every one of those is a smuggling vector.
 *
 * `keepAliveEligible` is the load-bearing bit: it is true only when the body has a determinate
 * end (`none`, `content-length`, `chunked`). A connection pool must never reuse a socket after
 * an `until-close` body — with no marked end, "the body" is just "whatever arrived", and the
 * next request on that socket would read the previous response's tail as its own head. That is
 * the response-to-the-wrong-request bug, and this flag is the only thing standing between the
 * pool and it. (A 2xx CONNECT reply is also ineligible: the socket is a tunnel now, not HTTP.)
 *
 * @param {{ status: number, method?: string, headers: Headers }} res the head fields framing
 *   depends on; a full ResponseHead satisfies it
 * @returns {Framing}
 */
export function bodyFraming({ status, method, headers }) {
  // 1. Messages that never have a body, regardless of any framing headers present: a HEAD
  // response's Content-Length describes the GET-equivalent body that is not sent.
  if (method === 'HEAD' || (status >= 100 && status <= 199) || status === 204 || status === 304) {
    return { kind: 'none', keepAliveEligible: true };
  }
  // 2. A 2xx reply to CONNECT: the connection becomes an opaque tunnel immediately after the
  // header block. No body, and no further HTTP on this socket.
  if (method === 'CONNECT' && status >= 200 && status <= 299) {
    return { kind: 'none', keepAliveEligible: false };
  }

  const te = headers.get('transfer-encoding');
  const cl = headers.get('content-length');

  if (te !== null) {
    // 4 (checked first because it is reachable only when TE is present): both TE and CL is
    // the canonical smuggling probe — two parsers that each pick a different winner split the
    // stream at different offsets. Neither wins here.
    if (cl !== null) {
      throw new HttpError(
        codes.HTTP_FRAMING_AMBIGUOUS,
        `both Transfer-Encoding (${JSON.stringify(te)}) and Content-Length ` +
          `(${JSON.stringify(cl)}) are present; the message length is ambiguous`,
        { transferEncoding: te, contentLength: cl },
      );
    }
    // 3. Transfer-Encoding decides. Coding names are case-insensitive. `identity` is a no-op
    // we accept; any other non-chunked coding (gzip, deflate, ...) would make the payload
    // undecodable by this layer, and delivering still-coded bytes as if they were the body
    // is a silent corruption, so it is refused by name.
    const codings = listElements(te).map((s) => s.toLowerCase());
    if (codings.length === 0) {
      throw new HttpError(
        codes.HTTP_FRAMING_AMBIGUOUS,
        `Transfer-Encoding ${JSON.stringify(te)} names no transfer coding`,
        { transferEncoding: te },
      );
    }
    for (const coding of codings) {
      if (coding !== 'chunked' && coding !== 'identity') {
        throw new HttpError(
          codes.HTTP_FRAMING_AMBIGUOUS,
          `transfer coding ${JSON.stringify(coding)} is not supported (only chunked/identity)`,
          { coding, transferEncoding: te },
        );
      }
    }
    if (codings[codings.length - 1] === 'chunked') {
      return { kind: 'chunked', keepAliveEligible: true };
    }
    // TE present but the final coding is not chunked: RFC 9112 §6.3 item 4 — read to close.
    // The end of the body is only ever signalled by EOF, so the socket cannot be reused.
    return { kind: 'until-close', keepAliveEligible: false };
  }

  if (cl !== null) {
    // 5. Headers folded any duplicates to "5, 5". Identical repeats are tolerated (proxies
    // do this); any disagreement or non-digit is fatal, because a length we are unsure of
    // is a boundary we are unsure of.
    const values = cl.split(',').map((s) => s.trim());
    for (const v of values) {
      if (!/^[0-9]+$/.test(v)) {
        throw new HttpError(
          codes.HTTP_FRAMING_AMBIGUOUS,
          `Content-Length ${JSON.stringify(cl)} is not a non-negative integer`,
          { contentLength: cl },
        );
      }
      if (v !== values[0]) {
        throw new HttpError(
          codes.HTTP_FRAMING_AMBIGUOUS,
          `multiple Content-Length values disagree: ${JSON.stringify(cl)}`,
          { contentLength: cl },
        );
      }
    }
    const length = Number(values[0]);
    if (!Number.isSafeInteger(length)) {
      throw new HttpError(
        codes.HTTP_FRAMING_AMBIGUOUS,
        `Content-Length ${values[0]} overflows a safe integer`,
        { contentLength: cl },
      );
    }
    // 6. A determinate length: the pool can hand the socket out again after exactly N bytes.
    return { kind: 'content-length', length, keepAliveEligible: true };
  }

  // 7. No framing information at all: the body is everything until the peer closes, which
  // means EOF is data, not an error — and the socket is spent.
  return { kind: 'until-close', keepAliveEligible: false };
}

/**
 * A response body stream plus the completion contract a connection pool needs. The two extra
 * properties are documented on readResponseBody, which is the only producer.
 * @typedef {ReadableStream<Uint8Array> & { completed: Promise<boolean>,
 *           trailers: Promise<Headers | null> }} BodyStream
 */

/**
 * @typedef {object} ReadBodyOptions
 * @property {number} [maxBytes] fail-closed cap on total payload bytes, default unlimited
 */

/**
 * Stream the response body according to `framing`.
 *
 * The returned ReadableStream<Uint8Array> carries two extra properties — the completion
 * contract a connection pool needs:
 *
 * - `completed`: Promise<boolean>. Resolves `true` only when the body ended exactly as framed
 *   (the reader is positioned at the first byte after the body). Resolves `false` if the
 *   consumer cancelled early (position unknown). Rejects with the stream's error on a protocol
 *   violation (truncation, over-limit). The pool must await `completed === true` AND require
 *   `framing.keepAliveEligible` before reusing the socket; anything else and the next request
 *   reads this response's tail. Note it settles as the body is CONSUMED — an unread stream
 *   settles nothing (except for bodies that are complete at creation: `none` and length 0).
 * - `trailers`: Promise<Headers|null>. Chunked trailers, or null for other framings / cancel.
 *
 * Bytes are streamed through, never buffered whole; `maxBytes` bounds the total.
 *
 * @param {import('../util/bytes.js').ByteReader} reader
 * @param {Framing} framing
 * @param {ReadBodyOptions} [opts]
 * @returns {BodyStream}
 */
export function readResponseBody(reader, framing, { maxBytes = Infinity } = {}) {
  if (framing.kind === 'none') {
    // The reader is deliberately untouched: for HEAD/204/304 the very next bytes are the next
    // response, and consuming even one of them would desynchronise the connection.
    const stream = new ReadableStream({
      start(c) {
        c.close();
      },
    });
    return Object.assign(stream, {
      completed: Promise.resolve(true),
      trailers: Promise.resolve(null),
    });
  }

  if (framing.kind === 'chunked') {
    const { stream, trailers } = decodeChunked(reader, { maxBytes });
    // Trailers settle exactly when the terminal CRLF has been consumed, so their settlement
    // IS the completion signal: Headers -> framed end reached, null -> cancelled.
    const completed = trailers.then((t) => t !== null);
    completed.catch(() => {});
    return Object.assign(stream, { completed, trailers });
  }

  if (framing.kind === 'content-length') {
    const length = framing.length;
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new HttpError(codes.CONFIG_INVALID, `content-length framing with length ${length}`);
    }
    if (length > maxBytes) {
      // Rejected before the first byte is read: the declared size already breaks the limit,
      // and downloading maxBytes of it first would only delay the same answer.
      throw new LimitError(
        codes.LIMIT_BODY,
        `declared Content-Length ${length} exceeds the ${maxBytes} byte limit`,
        { length, limit: maxBytes },
      );
    }
    const done = deferred();
    let remaining = length;
    const stream = new ReadableStream({
      async pull(c) {
        if (remaining === 0) {
          c.close();
          done.resolve(true);
          return;
        }
        let chunk;
        try {
          // Capped at `remaining`: bytes after the body (a pipelined next response) must stay
          // in the reader. Over-reading here is the pipelining-corruption bug.
          chunk = await reader.readSome(Math.min(remaining, 65536));
        } catch (e) {
          done.reject(e);
          c.error(e);
          return;
        }
        if (chunk === null) {
          // The peer closed early. A short body silently returned would be indistinguishable
          // from a complete one — truncation must be loud.
          const err = new HttpError(
            codes.HTTP_BODY_TRUNCATED,
            `body ended after ${length - remaining} of the ${length} bytes declared by ` +
              'Content-Length',
            { declared: length, got: length - remaining },
          );
          done.reject(err);
          c.error(err);
          return;
        }
        remaining -= chunk.byteLength;
        c.enqueue(chunk);
        // Close on the same pull that delivers the last byte, so a consumer that stops
        // reading at exactly `length` bytes still lets `completed` settle.
        if (remaining === 0) {
          c.close();
          done.resolve(true);
        }
      },
      cancel() {
        done.resolve(false);
      },
    });
    if (length === 0) done.resolve(true); // complete at creation; no pull required
    return Object.assign(stream, { completed: done.promise, trailers: Promise.resolve(null) });
  }

  if (framing.kind === 'until-close') {
    const done = deferred();
    let total = 0;
    const stream = new ReadableStream({
      async pull(c) {
        let chunk;
        try {
          chunk = await reader.readSome(65536);
        } catch (e) {
          done.reject(e);
          c.error(e);
          return;
        }
        if (chunk === null) {
          // EOF is the framing here, so it completes the body rather than truncating it.
          // (`completed` resolves true, but keepAliveEligible is false: the socket is spent.)
          c.close();
          done.resolve(true);
          return;
        }
        total += chunk.byteLength;
        if (total > maxBytes) {
          const err = new LimitError(
            codes.LIMIT_BODY,
            `body reached ${total} bytes, over the ${maxBytes} byte limit`,
            { limit: maxBytes },
          );
          done.reject(err);
          c.error(err);
          return;
        }
        c.enqueue(chunk);
      },
      cancel() {
        done.resolve(false);
      },
    });
    return Object.assign(stream, { completed: done.promise, trailers: Promise.resolve(null) });
  }

  throw new HttpError(codes.CONFIG_INVALID, `unknown framing kind ${JSON.stringify(framing.kind)}`);
}
