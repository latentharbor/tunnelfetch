// Offline test harness. Hermetic by construction: nothing here opens a socket.
//
// The central tool is `underAllChunkings`. Every byte-consuming parser in this package must be
// run through it. A parser that behaves differently when the same bytes arrive in different
// chunk shapes has a latent bug that only shows up under real network fragmentation, which is
// exactly the class of bug that is impossible to reproduce from a report.

import assert from 'node:assert/strict';
import { concat } from '../src/util/bytes.js';

/** Deterministic PRNG. Math.random() would make failures unreproducible. */
export function rng(seed = 0x2545f491) {
  let s = seed >>> 0;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s / 0x100000000;
  };
}

/** A ReadableStream that emits `chunks` in order, then closes. */
export function readableFrom(chunks) {
  let i = 0;
  return new ReadableStream({
    pull(c) {
      if (i < chunks.length) c.enqueue(chunks[i++]);
      else c.close();
    },
  });
}

/** A ReadableStream that emits chunks then errors, to exercise mid-message failures. */
export function readableThatErrors(chunks, error) {
  let i = 0;
  return new ReadableStream({
    pull(c) {
      if (i < chunks.length) c.enqueue(chunks[i++]);
      else c.error(error);
    },
  });
}

/** A WritableStream that records everything written. */
export function recordingWritable() {
  const chunks = [];
  const stream = new WritableStream({
    write(c) {
      chunks.push(c.slice());
    },
  });
  return { stream, chunks, get bytes() {
    return concat(chunks);
  } };
}

/** Split `bytes` into chunks of exactly `size` (last one may be shorter). */
export function fixedChunks(bytes, size) {
  const out = [];
  for (let i = 0; i < bytes.byteLength; i += size) out.push(bytes.subarray(i, i + size));
  return out.length ? out : [bytes.subarray(0, 0)];
}

/** Split `bytes` at pseudo-random points, deterministically. */
export function randomChunks(bytes, seed, maxPiece = 17) {
  const next = rng(seed);
  const out = [];
  let i = 0;
  while (i < bytes.byteLength) {
    const n = 1 + Math.floor(next() * maxPiece);
    out.push(bytes.subarray(i, Math.min(i + n, bytes.byteLength)));
    i += n;
  }
  return out.length ? out : [bytes.subarray(0, 0)];
}

/**
 * Every chunking a parser must survive. Named so a failure says which shape broke it.
 * @param {Uint8Array} bytes
 */
export function chunkings(bytes) {
  const shapes = [
    ['whole', [bytes]],
    ['byte-by-byte', fixedChunks(bytes, 1)],
    ['pairs', fixedChunks(bytes, 2)],
    ['3-byte', fixedChunks(bytes, 3)],
    ['5-byte', fixedChunks(bytes, 5)],
    ['power-of-two-boundary', fixedChunks(bytes, 16)],
  ];
  for (const seed of [1, 2, 3, 0x9e3779b9]) {
    shapes.push([`random(${seed})`, randomChunks(bytes, seed)]);
  }
  // A leading empty chunk is legal on a ReadableStream and has broken real parsers.
  shapes.push(['empty-then-whole', [new Uint8Array(0), bytes]]);
  return shapes;
}

/**
 * Run `fn(readable)` once per chunking of `bytes` and assert every run agrees.
 * `fn` must return something structured-cloneable for comparison.
 *
 * @param {Uint8Array} bytes
 * @param {(readable: ReadableStream<Uint8Array>) => Promise<any>} fn
 * @param {(a:any)=>any} [normalise] map the result to a comparable shape
 */
export async function underAllChunkings(bytes, fn, normalise = (x) => x) {
  const shapes = chunkings(bytes);
  let reference;
  let referenceName;
  for (const [name, chunks] of shapes) {
    let got;
    try {
      got = normalise(await fn(readableFrom(chunks)));
    } catch (e) {
      got = { __threw: `${e?.name}: ${e?.message}`, code: e?.code };
    }
    if (reference === undefined) {
      reference = got;
      referenceName = name;
      continue;
    }
    assert.deepStrictEqual(
      got,
      reference,
      `chunking "${name}" disagreed with "${referenceName}"\n` +
        `  ${referenceName}: ${JSON.stringify(reference)}\n` +
        `  ${name}: ${JSON.stringify(got)}`,
    );
  }
  if (reference && reference.__threw) {
    throw Object.assign(new Error(reference.__threw), { code: reference.code, consistent: true });
  }
  return reference;
}

/**
 * A bidirectional in-memory pipe, the socketpair equivalent. `a.writable` feeds `b.readable`.
 * Layers take `{readable, writable}` and nothing else, so every layer is testable with this
 * and no network.
 */
export function duplexPair() {
  const ab = new TransformStream();
  const ba = new TransformStream();
  return {
    a: { readable: ba.readable, writable: ab.writable },
    b: { readable: ab.readable, writable: ba.writable },
  };
}

/**
 * A scripted peer: replies with fixed bytes on cue and records what it received.
 * Used as a fake proxy and a fake origin server.
 *
 * @param {(received: Uint8Array, respond: (b: Uint8Array) => Promise<void>, close: () => Promise<void>) => Promise<void>|void} handler
 */
export function scriptedPeer(handler) {
  const { a, b } = duplexPair();
  const received = [];
  const done = (async () => {
    const reader = b.readable.getReader();
    const writer = b.writable.getWriter();
    const respond = (bytes) => writer.write(bytes);
    const close = async () => {
      try {
        await writer.close();
      } catch {
        /* peer gone */
      }
    };
    try {
      for (;;) {
        const { value, done: d } = await reader.read();
        if (d) break;
        if (value && value.byteLength) {
          received.push(value.slice());
          await handler(value, respond, close);
        }
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        /* already released */
      }
      try {
        await writer.close();
      } catch {
        /* already closed */
      }
    }
  })();
  return { socket: a, received, get bytes() {
    return concat(received);
  }, done };
}

/** Collect a ReadableStream into one Uint8Array. */
export async function collect(readable, limit = 1 << 24) {
  const reader = readable.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      assert.ok(total <= limit, `collect() exceeded ${limit} bytes`);
      parts.push(value);
    }
  }
  reader.releaseLock();
  return concat(parts, total);
}

/** Assert a thrown error carries the expected machine-readable code. */
export async function rejectsWithCode(fn, code, msgMatch) {
  let err;
  try {
    await fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err, `expected a throw with code ${code}, but nothing was thrown`);
  assert.equal(err.code, code, `expected code ${code}, got ${err.code}: ${err.message}`);
  if (msgMatch) assert.match(err.message, msgMatch);
  return err;
}
