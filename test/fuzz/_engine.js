// A seeded, dependency-free fuzzer for the parsers that consume bytes an attacker controls.
//
// Why this exists: this package parses X.509, OCSP, TLS records, HPACK, HTTP/1.1 heads, chunked
// bodies and HTTP/2 frames in JavaScript, from a peer that may be hostile. Unit tests prove the
// cases someone thought of. This proves a property over inputs nobody thought of:
//
//   For ANY byte string, a parser either succeeds or throws a TunnelFetchError.
//
// A `TypeError: Cannot read properties of undefined` or a `RangeError: offset is out of bounds` is
// a finding, not a pass — it means a bounds check is missing and the error escaped the typed
// contract every caller relies on to fail closed. Whether it is exploitable is a second question;
// that it is unhandled is the first.
//
// Deterministic by construction: the seed drives every mutation, so a failure prints a seed and a
// base64 case that reproduce it exactly. A fuzzer whose failures cannot be replayed is a
// flaky test generator.
//
// What this does NOT catch: a parser that loops forever. A synchronous infinite loop cannot be
// interrupted from inside the same isolate, so it surfaces as a test-runner timeout rather than a
// named failure. That is a real limitation and it is why the per-target iteration count stays low
// enough that a hang is obvious rather than mistaken for slowness.

import { TunnelFetchError } from '../../src/errors.js';

/** xorshift32. Same generator as the harness, kept local so a fuzz run has one seed source. */
export function rand32(seed) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

/**
 * Derive one mutated case from a corpus entry.
 *
 * The operator mix is deliberate. Bit flips and byte writes find missing value checks; truncation
 * finds missing length checks, which is the single most common way a hand-written parser walks off
 * the end of a buffer; splicing finds structural confusion; and length-field corruption is aimed
 * at the TLV and frame-header parsers specifically, where a declared length that disagrees with
 * the buffer is the whole attack surface.
 */
export function mutate(corpus, next) {
  const base = corpus[next() % corpus.length];
  const out = Uint8Array.from(base);
  if (out.length === 0) return out;
  const ops = 1 + (next() % 4);

  for (let i = 0; i < ops; i++) {
    switch (next() % 7) {
      case 0: {
        // flip one bit
        const at = next() % out.length;
        out[at] ^= 1 << next() % 8;
        break;
      }
      case 1: {
        // write an interesting byte: the boundary values a length or tag byte is checked against
        const interesting = [0x00, 0x01, 0x7f, 0x80, 0x81, 0xfe, 0xff];
        out[next() % out.length] = interesting[next() % interesting.length];
        break;
      }
      case 2:
        // truncate — the classic way to walk off the end
        return out.subarray(0, next() % out.length);
      case 3: {
        // splice a run from elsewhere in the same buffer over itself
        const len = 1 + (next() % Math.min(32, out.length));
        const from = next() % (out.length - len + 1);
        const to = next() % (out.length - len + 1);
        out.set(out.subarray(from, from + len), to);
        break;
      }
      case 4: {
        // zero a run
        const at = next() % out.length;
        const len = Math.min(out.length - at, 1 + (next() % 16));
        out.fill(0, at, at + len);
        break;
      }
      case 5: {
        // 0xff a run: maximal declared lengths
        const at = next() % out.length;
        const len = Math.min(out.length - at, 1 + (next() % 8));
        out.fill(0xff, at, at + len);
        break;
      }
      case 6: {
        // corrupt an early byte, where tags and length prefixes live
        out[next() % Math.min(16, out.length)] = next() % 256;
        break;
      }
    }
  }
  return out;
}

/** Base64 without node:buffer, so a failing case can be pasted straight into a test. */
function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/**
 * Run one target and assert the property. Returns a summary so a passing run can still report how
 * much of what it did was real work — a fuzz run where every case is rejected by the first byte
 * has proven very little, and that is worth seeing rather than assuming.
 *
 * @param {{name: string, corpus: Uint8Array[], run: (input: Uint8Array) => unknown}} target
 * @param {{iterations: number, seed: number}} opts
 */
export async function fuzzTarget(target, { iterations, seed }) {
  const next = rand32(seed);
  let accepted = 0;
  let typed = 0;

  for (let i = 0; i < iterations; i++) {
    const input = mutate(target.corpus, next);
    try {
      await target.run(input);
      accepted++;
    } catch (err) {
      // AbortError comes from this package's own deadlines and is a legitimate refusal.
      if (err instanceof TunnelFetchError || err?.name === 'AbortError') {
        typed++;
        continue;
      }
      const e = new Error(
        `${target.name}: input escaped the typed-error contract on iteration ${i}\n` +
          `  threw: ${err?.constructor?.name ?? typeof err}: ${err?.message}\n` +
          `  reproduce: seed=${seed} iteration=${i}\n` +
          `  case (base64): ${toBase64(input)}\n` +
          '  Every parser must fail closed with a TunnelFetchError. An untyped throw means a ' +
          'bounds or shape check is missing and callers relying on the typed contract will not ' +
          'catch it.',
      );
      e.cause = err;
      throw e;
    }
  }
  return { accepted, typed, iterations };
}
