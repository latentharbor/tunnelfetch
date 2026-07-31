// An in-memory network: a `connect` factory whose sockets are driven by a scripted peer.
//
// Every layer in this package takes its socket factory as a parameter precisely so this file can
// exist. Nothing here touches the network, and the "server" is ordinary JavaScript, so a whole
// request/response exchange — framing, keep-alive, redirects, cookies, decompression — is
// exercised deterministically and in milliseconds.

import { ByteReader, concat, latin1, utf8 } from '../src/util/bytes.js';
import { duplexPair } from './_harness.js';

/**
 * Build a `connect` function backed by `handler`.
 *
 * @param {(conn: {reader: ByteReader, write: (b: Uint8Array|string) => Promise<void>,
 *                 close: () => Promise<void>, addr: object, opts: object}) => Promise<void>} handler
 */
export function fakeNetwork(handler) {
  const calls = [];
  const sockets = [];

  const connect = (addr, opts = {}) => {
    const { a, b } = duplexPair();
    const record = { addr, opts, closed: false, serverDone: null };
    calls.push(record);

    const reader = new ByteReader(b.readable);
    const writer = b.writable.getWriter();
    const write = (bytes) => writer.write(typeof bytes === 'string' ? utf8(bytes) : bytes);
    const closeServer = async () => {
      try {
        await writer.close();
      } catch {
        /* peer already gone */
      }
    };

    record.serverDone = (async () => {
      try {
        await handler({ reader, write, close: closeServer, addr, opts });
      } finally {
        await closeServer();
      }
    })();
    // A handler that throws must not become an unhandled rejection; tests assert on the client.
    record.serverDone.catch(() => {});

    const socket = {
      readable: a.readable,
      writable: a.writable,
      opened: Promise.resolve({ remoteAddress: `${addr.hostname}:${addr.port}`, localAddress: null }),
      close: async () => {
        record.closed = true;
        try {
          await a.writable.abort?.();
        } catch {
          /* already closed */
        }
      },
    };
    sockets.push(socket);
    return socket;
  };

  return { connect, calls, sockets };
}

/** Read one HTTP request head (up to CRLFCRLF) and return it parsed enough to assert on. */
export async function readRequestHead(reader) {
  const block = latin1(await reader.readUntil(utf8('\r\n\r\n'), 64 * 1024, 'request head'));
  const [requestLine, ...lines] = block.split('\r\n');
  const [method, target, version] = requestLine.split(' ');
  const headers = new Map();
  const order = [];
  for (const line of lines) {
    if (!line) break;
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const name = line.slice(0, i).toLowerCase();
    order.push(name);
    headers.set(name, line.slice(i + 1).trim());
  }
  return { raw: block, method, target, version, headers, order };
}

/** Build a well-formed HTTP/1.1 response with Content-Length framing. */
export function response({ status = 200, reason = 'OK', headers = {}, body = '', version = '1.1' } = {}) {
  const bytes = typeof body === 'string' ? utf8(body) : body;
  const all = { 'content-length': String(bytes.byteLength), ...headers };
  const head = [`HTTP/${version} ${status} ${reason}`];
  for (const [k, v] of Object.entries(all)) {
    if (v === null) continue; // an explicit null omits the header, e.g. to force EOF framing
    if (Array.isArray(v)) for (const each of v) head.push(`${k}: ${each}`);
    else head.push(`${k}: ${v}`);
  }
  return concat([utf8(`${head.join('\r\n')}\r\n\r\n`), bytes]);
}

/** Encode a body with chunked transfer-coding, optionally with trailers. */
export function chunkedBody(parts, trailers = {}) {
  const out = [];
  for (const p of parts) {
    const bytes = typeof p === 'string' ? utf8(p) : p;
    out.push(utf8(`${bytes.byteLength.toString(16)}\r\n`), bytes, utf8('\r\n'));
  }
  out.push(utf8('0\r\n'));
  for (const [k, v] of Object.entries(trailers)) out.push(utf8(`${k}: ${v}\r\n`));
  out.push(utf8('\r\n'));
  return concat(out);
}

/** gzip some bytes using the platform's CompressionStream, so decode.js is exercised for real. */
export async function gzip(text) {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  void writer.write(typeof text === 'string' ? utf8(text) : text);
  void writer.close();
  const chunks = [];
  const reader = cs.readable.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(chunks);
}

/**
 * A server that answers each request from a queue of responses, keeping the connection open.
 * Returns the request heads it saw, so a test can assert what actually went on the wire.
 */
export function sequenceServer(responses, { closeAfterLast = false } = {}) {
  const seen = [];
  let i = 0;
  const handler = async ({ reader, write, close }) => {
    for (;;) {
      let head;
      try {
        head = await readRequestHead(reader);
      } catch {
        return; // client closed; nothing left to answer
      }
      seen.push(head);
      const declared = Number(head.headers.get('content-length') ?? 0);
      if (declared > 0) await reader.readExactly(declared, 'request body');

      const next = responses[Math.min(i, responses.length - 1)];
      i++;
      const bytes = typeof next === 'function' ? await next(head) : next;
      await write(bytes);
      // Closing is how a server signals an EOF-framed body; without it such a response never ends.
      if (i >= responses.length && closeAfterLast) {
        await close();
        return;
      }
    }
  };
  return { handler, seen };
}
