// The tunnel's readable half, and why it has to be a byte stream.
//
// Both dialects finish their handshake holding a buffered reader that may already carry tunnel
// payload: an HTTP CONNECT reply is read up to its blank line and a SOCKS5 reply to its fixed
// length, and in both cases the peer is free to have sent application bytes immediately behind it.
// Those bytes must be delivered first and in order, which is why the socket cannot simply be
// handed onward.
//
// What this replaces was `new ReadableStream({ pull })` — correct, and a plain stream rather than a
// byte stream. That distinction is invisible until you look at what reads it. The TLS record layer
// asks for a BYOB reader and quietly falls back to a default one when it cannot have it, so every
// connection through a proxy lost BYOB reads, and with them `tls.pullBytes`, whose entire job is to
// decide how much of the socket arrives per boundary crossing.
//
// Measured on the edge against one origin, 4 MB, differenced at a single request:
//
//     direct     132 socket reads, 31.8 KB average fill
//     proxied    484 socket reads,  8.7 KB average fill
//
// and the knob itself, 1 MB through the record layer, n=15 in one isolate:
//
//                       pullBytes 16 KiB     pullBytes 1 MiB
//     direct            min 25  p50 31       min 73  p50 90     <- 2.9x, the knob works
//     proxied           min 95  p50 111      min 101 p50 121    <- 6%, the knob is not read
//
// So the U-curve recorded against "a real proxied socket" in util/bytes.js was four samples of one
// configuration. The knob was never reaching the code on that path.
//
// The fix is not to copy harder. Once the handshake's leftovers are drained this hands the caller's
// own view straight to the socket, so a read through a tunnel costs exactly what a read without one
// costs — no wrapper copy, and the same coalescing.

import { ByteReader } from '../util/bytes.js';

/**
 * View size handed to a *default* reader of this stream. BYOB readers supply their own view and
 * never see this; it exists so that a caller which does not do BYOB still gets socket-sized chunks
 * rather than whatever the transport felt like emitting.
 */
const TUNNEL_CHUNK = 65536;

/**
 * Wrap a proxy handshake's buffered reader plus its socket as one byte stream.
 *
 * @param {{ readable: ReadableStream<Uint8Array> }} socket the raw transport
 * @param {import('../util/bytes.js').ByteReader} reader the handshake's reader, possibly holding
 *   bytes that belong to the tunnel
 * @returns {ReadableStream<Uint8Array>}
 */
export function tunnelReadable(socket, reader) {
  /** Taken once `reader` runs dry, after which every read goes straight to the socket. */
  let direct = null;
  /** Buffered stand-in for `reader` when the socket turns out not to be a byte stream. */
  let buffered = reader;
  let promoted = false;

  // Whether a stream is BYOB-capable can only be discovered by asking it for a BYOB reader, and it
  // cannot be asked while the handshake's reader holds the lock. So: release (safe only because
  // the guard below proves nothing is buffered), ask, and on refusal re-take a buffered reader —
  // which is exactly the shape that was here before, for transports that cannot do better. Every
  // in-process stream in this package's tests is one of those, so this path is well covered.
  const promote = () => {
    if (promoted || buffered.buffered > 0 || buffered.atEof) return;
    promoted = true;
    buffered.releaseLock();
    try {
      direct = socket.readable.getReader({ mode: 'byob' });
    } catch {
      buffered = new ByteReader(socket.readable);
    }
  };

  return new ReadableStream({
    type: 'bytes',
    autoAllocateChunkSize: TUNNEL_CHUNK,
    async pull(controller) {
      // autoAllocateChunkSize guarantees a byobRequest even for a default reader, so there is one
      // path here rather than two.
      const req = controller.byobRequest;
      const view = req.view;
      promote();
      if (direct) {
        const { value, done } = await direct.read(
          new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
        );
        if (done) {
          // Close first: a BYOB request may only be answered with zero bytes once the stream is
          // closed, and the read has detached the original view, so the answer has to be the
          // zero-length view the reader handed back rather than a plain respond(0).
          controller.close();
          req.respondWithNewView(value ?? new Uint8Array(0));
          return;
        }
        req.respondWithNewView(value);
        return;
      }
      const chunk = await buffered.readSome(view.byteLength);
      if (chunk === null) {
        controller.close();
        req.respond(0);
        return;
      }
      new Uint8Array(view.buffer, view.byteOffset, view.byteLength).set(chunk);
      req.respond(chunk.byteLength);
    },
    cancel(reason) {
      return direct ? direct.cancel(reason) : buffered.cancel(reason);
    },
  });
}
