// Deadlines.
//
// The design constraint here is measured, not assumed: on the target runtime `Date.now()` and
// `performance.now()` are frozen for the whole of a synchronous execution slice and only advance
// across I/O. A timeout implemented by comparing clock readings in a loop therefore either never
// fires or fires at an unrelated moment. Everything below is driven by timer callbacks and stream
// events instead, and no code path decides "has it been long enough?" by reading a clock.
//
// The idle deadline is the important one. For a streaming response, "how long since the last byte"
// is the signal that something is wrong; "how long in total" is not — a legitimate download or a
// slow SSE feed can run for minutes. Total is a backstop, idle is the control.

import { TimeoutError, codes } from '../errors.js';

/**
 * @typedef {object} DeadlineOptions
 * @property {number} [connectMs]    TCP connect (and proxy handshake) must complete within this
 * @property {number} [handshakeMs]  TLS handshake must complete within this
 * @property {number} [headersMs]    response status line + headers must arrive within this
 * @property {number} [idleMs]       maximum gap between body chunks
 * @property {number} [totalMs]      hard ceiling on the whole request; a backstop, not the control
 */

// The idle default is deliberately generous, and the reasoning is asymmetry rather than taste.
// Idle time is free on this runtime — it bills CPU, not wall clock — and once response headers
// have arrived a connection no longer occupies one of the six per-invocation slots reserved for
// requests still awaiting headers. So an over-long idle timeout costs a connection that is not
// being paid for, while an over-short one aborts a request that was going to succeed. Nor can the
// value be tuned to a peer's heartbeat: streaming APIs that send keep-alive events do not commit
// to an interval, and a server generating a long response before its first token is legitimately
// silent for exactly as long as it takes. Err long.
export const DEFAULT_DEADLINES = Object.freeze({
  connectMs: 10_000,
  handshakeMs: 15_000,
  // The one phase that does hold a header-wait slot, hence tighter than idle. A peer that buffers
  // a whole slow response before sending its head needs this raised; streaming peers do not.
  headersMs: 30_000,
  idleMs: 60_000,
  totalMs: 0, // 0 means no ceiling: streaming responses legitimately run long
});

/**
 * Owns every timer for one request and exposes a single AbortSignal that fires when any of them
 * elapses. Callers abort on the signal rather than each racing their own promise, so a timeout in
 * one phase tears down the whole connection instead of leaking a socket into the background.
 */
export class DeadlineController {
  /**
   * @param {DeadlineOptions} options
   * @param {{ signal?: AbortSignal, setTimer?: typeof setTimeout, clearTimer?: typeof clearTimeout }} [env]
   */
  constructor(options = {}, env = {}) {
    this.options = { ...DEFAULT_DEADLINES, ...options };
    // Wrapped rather than captured bare: on the target runtime the timer builtins are bound to
    // the global object and a detached `setTimeout` reference throws "Illegal invocation".
    // Node tolerates the detached form, so this only ever fails in production — which is where
    // the live rig found it.
    this._setTimer = env.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this._clearTimer = env.clearTimer ?? ((id) => clearTimeout(id));
    this._controller = new AbortController();
    /** @type {any} */
    this._phaseTimer = null;
    this._phaseName = null;
    /** @type {any} */
    this._idleTimer = null;
    this._totalTimer = null;
    this._settled = false;
    /** @type {TimeoutError|null} */
    this.error = null;

    if (this.options.totalMs > 0) {
      this._totalTimer = this._setTimer(
        () => this._fire(codes.TIMEOUT_TOTAL, 'total', this.options.totalMs),
        this.options.totalMs,
      );
    }

    // An externally supplied signal (the caller's AbortSignal) must tear us down too.
    const outer = env.signal;
    if (outer) {
      if (outer.aborted) this._abortFromOuter(outer);
      else {
        this._onOuterAbort = () => this._abortFromOuter(outer);
        outer.addEventListener('abort', this._onOuterAbort, { once: true });
        this._outer = outer;
      }
    }
  }

  get signal() {
    return this._controller.signal;
  }

  get aborted() {
    return this._controller.signal.aborted;
  }

  _abortFromOuter(outer) {
    if (this._settled) return;
    this._settled = true;
    this._clearAll();
    this._controller.abort(outer.reason ?? new Error('aborted by caller'));
  }

  _fire(code, phase, ms) {
    if (this._settled) return;
    this._settled = true;
    this._clearAll();
    this.error = new TimeoutError(
      code,
      `${phase} deadline of ${ms}ms elapsed`,
      { phase, ms },
    );
    this._controller.abort(this.error);
  }

  _clearAll() {
    for (const t of [this._phaseTimer, this._idleTimer, this._totalTimer]) {
      if (t !== null && t !== undefined) this._clearTimer(t);
    }
    this._phaseTimer = this._idleTimer = this._totalTimer = null;
  }

  /**
   * Start a bounded phase. Returns a function that ends it. Only one phase runs at a time; a new
   * phase implicitly ends the previous one, which matches the actual sequence
   * connect -> handshake -> headers and keeps callers from having to unwind by hand.
   */
  beginPhase(name) {
    this.endPhase();
    const ms = this.options[`${name}Ms`];
    if (!ms || ms <= 0) return () => {};
    this._phaseName = name;
    const code =
      name === 'connect' ? codes.TIMEOUT_CONNECT
      : name === 'handshake' ? codes.TIMEOUT_HANDSHAKE
      : codes.TIMEOUT_HEADERS;
    this._phaseTimer = this._setTimer(() => this._fire(code, name, ms), ms);
    return () => this.endPhase();
  }

  endPhase() {
    if (this._phaseTimer !== null) {
      this._clearTimer(this._phaseTimer);
      this._phaseTimer = null;
      this._phaseName = null;
    }
  }

  /**
   * Arm the idle deadline. Call `touch()` on every byte that arrives; each touch restarts the
   * timer. Nothing here reads a clock, which is what makes it work on a runtime whose clock is
   * frozen between I/O events.
   */
  beginIdle() {
    this.endPhase();
    this.touch();
  }

  touch() {
    const ms = this.options.idleMs;
    if (!ms || ms <= 0 || this._settled) return;
    if (this._idleTimer !== null) this._clearTimer(this._idleTimer);
    this._idleTimer = this._setTimer(() => this._fire(codes.TIMEOUT_IDLE, 'idle', ms), ms);
  }

  /** Release every timer. Safe to call more than once; must be called on every exit path. */
  dispose() {
    this._settled = true;
    this._clearAll();
    if (this._outer && this._onOuterAbort) {
      this._outer.removeEventListener('abort', this._onOuterAbort);
      this._outer = null;
    }
  }

  /**
   * Reject as soon as the signal aborts, resolve when `promise` settles first.
   * The abort reason is preserved so the caller sees the typed TimeoutError, not a generic abort.
   */
  /**
   * A promise that rejects when this controller aborts, created once and reused.
   *
   * `race` used to register and unregister an abort listener PER CALL, which is per chunk on a body
   * stream. That is invisible on a 4 MB response — a few dozen chunks — and it is the dominant
   * per-event cost on an SSE stream, where a single completion can be a hundred thousand chunks of
   * a few hundred bytes each. The signal does not change over the life of the controller, so one
   * registration is enough.
   *
   * Pre-observed, because a rejection nobody has awaited yet is an unhandled rejection.
   */
  get _abortPromise() {
    if (!this.__abortP) {
      this.__abortP = new Promise((_, reject) => {
        if (this.aborted) reject(this.signal.reason);
        else this.signal.addEventListener('abort', () => reject(this.signal.reason), { once: true });
      });
      this.__abortP.catch(() => {});
    }
    return this.__abortP;
  }

  race(promise) {
    if (this.aborted) return Promise.reject(this.signal.reason);
    return Promise.race([promise, this._abortPromise]);
  }
}

/**
 * Wrap a body stream so every chunk touches the idle deadline and an abort surfaces as the typed
 * timeout error rather than a bare AbortError.
 *
 * The stream is consumed with a plain reader rather than piped through a TransformStream because
 * a transform would buffer a chunk ahead, which is exactly the wrong behaviour for an idle
 * deadline: the timer must be reset by data reaching the consumer, not by data reaching a queue.
 *
 * @param {ReadableStream<Uint8Array>} source
 * @param {DeadlineController} deadlines
 */
export function withIdleDeadline(source, deadlines) {
  const reader = source.getReader();
  return new ReadableStream({
    async pull(controller) {
      try {
        const { value, done } = await deadlines.race(reader.read());
        if (done) {
          deadlines.dispose();
          controller.close();
          return;
        }
        deadlines.touch();
        controller.enqueue(value);
      } catch (e) {
        deadlines.dispose();
        try {
          await reader.cancel(e);
        } catch {
          /* the source may already be errored */
        }
        controller.error(e);
      }
    },
    async cancel(reason) {
      deadlines.dispose();
      try {
        await reader.cancel(reason);
      } catch {
        /* already gone */
      }
    },
  });
}

/**
 * One-shot deadline for a promise that has no stream behind it, e.g. a socket's `opened`.
 * Prefer DeadlineController when several phases share a teardown.
 */
export function withDeadline(promise, ms, code, what, env = {}) {
  if (!ms || ms <= 0) return promise;
  const setTimer = env.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = env.clearTimer ?? ((id) => clearTimeout(id));
  return new Promise((resolve, reject) => {
    const t = setTimer(() => reject(new TimeoutError(code, `${what} did not complete within ${ms}ms`, { ms, what })), ms);
    promise.then(
      (v) => {
        clearTimer(t);
        resolve(v);
      },
      (e) => {
        clearTimer(t);
        reject(e);
      },
    );
  });
}
