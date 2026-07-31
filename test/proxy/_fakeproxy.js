// In-memory fake proxy: a factory for the `connect` function every proxy entry point takes.
//
// Why a bespoke fake rather than scriptedPeer(): proxy handshakes are strictly turn-based, and
// half of what these tests assert is call metadata rather than bytes — which address was dialled,
// whether secureTransport was 'on' or 'starttls', and above all whether close() was invoked on a
// failure path (a leaked socket in a Worker is a real resource bug, so the fake must record it).
//
// Design rules that keep scripts deadlock-free:
//   * peer reads are buffered (ByteReader), so a script never depends on client chunk boundaries;
//   * peer sends are queued on the WritableStream without awaiting delivery, so a script can never
//     block on the client's read pace — WritableStream preserves write order, and end() queues
//     after every pending write;
//   * a script's throw is captured into record.scriptError, never into the test's control flow, so
//     scripts must only capture bytes and respond. Assertions belong in the test body.

import { ByteReader, utf8 } from '../../src/util/bytes.js';
import { duplexPair, fixedChunks } from '../_harness.js';

const toBytes = (x) => (typeof x === 'string' ? utf8(x) : x);

/**
 * Split bytes for send(). The shapes matter: a proxy reply and its trailing tunnel payload must be
 * deliverable in the SAME chunk, in separate chunks, or one byte at a time, because those are the
 * framings that have historically lost bytes.
 * 'whole' | 'bytes' | chunk size | array of sizes (remainder becomes a final chunk).
 */
function splitForSend(bytes, chunking) {
  if (chunking === undefined || chunking === 'whole') return [bytes];
  if (chunking === 'bytes') return fixedChunks(bytes, 1);
  if (typeof chunking === 'number') return fixedChunks(bytes, chunking);
  const out = [];
  let i = 0;
  for (const n of chunking) {
    out.push(bytes.subarray(i, i + n)); // a 0 size is allowed: empty chunks are legal and nasty
    i += n;
  }
  if (i < bytes.byteLength) out.push(bytes.subarray(i));
  return out;
}

/**
 * Build a `connect` function whose sockets are in-memory pipes driven by `script(peer, record)`.
 *
 * @param {(peer: {
 *   read: () => Promise<Uint8Array|null>,
 *   readExactly: (n: number) => Promise<Uint8Array>,
 *   readUntil: (needle: Uint8Array|string, max?: number) => Promise<Uint8Array>,
 *   send: (bytes: Uint8Array|string, chunking?: 'whole'|'bytes'|number|number[]) => Promise<void>,
 *   end: () => Promise<void>,
 *   abort: (reason?: unknown) => Promise<void>,
 * }, record: object) => Promise<void>|void} [script] runs once per connect() call, as the proxy
 * @param {{connectError?: Error, openError?: Error}} [options]
 *   connectError: connect() itself throws synchronously (dial failure before a socket exists);
 *   openError: the returned socket's `opened` promise rejects.
 * @returns {{connect: Function, calls: object[], call: object}}
 *   calls[i] records {addr, opts, socket, closeCalls, closed, session, scriptError, writeErrors}.
 */
export function fakeProxy(script, options = {}) {
  const calls = [];
  const connect = (addr, opts) => {
    const record = {
      addr: { ...addr },
      opts: { ...opts },
      closeCalls: 0,
      get closed() {
        return this.closeCalls > 0;
      },
      writeErrors: [],
      scriptError: undefined,
      session: Promise.resolve(),
      socket: undefined,
    };
    calls.push(record);
    if (options.connectError) throw options.connectError;

    const { a, b } = duplexPair();
    const reader = new ByteReader(b.readable);
    const writer = b.writable.getWriter();
    const send = (bytes, chunking) => {
      let last = Promise.resolve();
      for (const piece of splitForSend(toBytes(bytes), chunking)) {
        // Errors are recorded, not thrown: after the client cancels its side, pending proxy
        // writes reject, and that must not turn into an unhandled rejection mid-test.
        last = writer.write(piece).catch((e) => {
          record.writeErrors.push(e);
        });
      }
      return last;
    };
    const end = () =>
      writer.close().catch((e) => {
        record.writeErrors.push(e);
      });
    const peer = {
      read: () => reader.readSome(),
      readExactly: (n) => reader.readExactly(n, 'client bytes'),
      readUntil: (needle, max = 1 << 16) => reader.readUntil(toBytes(needle), max, 'client bytes'),
      send,
      end,
      abort: (reason) => writer.abort(reason).catch(() => {}),
    };
    if (script) {
      record.session = (async () => script(peer, record))().catch((e) => {
        record.scriptError = e;
      });
    }

    const opened = options.openError ? Promise.reject(options.openError) : Promise.resolve({});
    // A rejected `opened` that a code path never awaits must not crash the test process.
    opened.catch(() => {});

    record.socket = {
      readable: a.readable,
      writable: a.writable,
      opened,
      close: async () => {
        record.closeCalls += 1;
        // Emulate a real close: both directions die. Every step is best-effort because streams
        // may be locked or already done, and close() must never throw at the caller.
        await end(); // proxy->client: pending client reads see EOF instead of hanging
        try {
          await a.writable.close();
        } catch {
          try {
            await a.writable.abort('fake socket closed');
          } catch {
            /* locked by a live writer; the direction is dead anyway */
          }
        }
        try {
          await a.readable.cancel('fake socket closed');
        } catch {
          /* locked by the tunnel's reader */
        }
      },
    };
    return record.socket;
  };
  return {
    connect,
    calls,
    /** The first (usually only) connection — the common case in these tests. */
    get call() {
      return calls[0];
    },
  };
}
