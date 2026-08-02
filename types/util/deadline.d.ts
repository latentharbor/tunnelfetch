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
export function withIdleDeadline(source: ReadableStream<Uint8Array>, deadlines: DeadlineController): ReadableStream<any>;
/**
 * One-shot deadline for a promise that has no stream behind it, e.g. a socket's `opened`.
 * Prefer DeadlineController when several phases share a teardown.
 */
export function withDeadline(promise: any, ms: any, code: any, what: any, env?: {}): any;
/**
 * @typedef {object} DeadlineOptions
 * @property {number} [connectMs]    TCP connect (and proxy handshake) must complete within this
 * @property {number} [handshakeMs]  TLS handshake must complete within this
 * @property {number} [headersMs]    response status line + headers must arrive within this
 * @property {number} [idleMs]       maximum gap between body chunks
 * @property {number} [totalMs]      hard ceiling on the whole request; a backstop, not the control
 */
export const DEFAULT_DEADLINES: Readonly<{
    connectMs: 10000;
    handshakeMs: 15000;
    headersMs: 30000;
    idleMs: 60000;
    totalMs: 0;
}>;
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
    constructor(options?: DeadlineOptions, env?: {
        signal?: AbortSignal;
        setTimer?: typeof setTimeout;
        clearTimer?: typeof clearTimeout;
    });
    options: {
        /**
         * TCP connect (and proxy handshake) must complete within this
         */
        connectMs: number;
        /**
         * TLS handshake must complete within this
         */
        handshakeMs: number;
        /**
         * response status line + headers must arrive within this
         */
        headersMs: number;
        /**
         * maximum gap between body chunks
         */
        idleMs: number;
        /**
         * hard ceiling on the whole request; a backstop, not the control
         */
        totalMs: number;
    };
    _setTimer: typeof setTimeout;
    _clearTimer: typeof clearTimeout;
    _controller: AbortController;
    /** @type {any} */
    _phaseTimer: any;
    _phaseName: any;
    /** @type {any} */
    _idleTimer: any;
    _totalTimer: number | null;
    _settled: boolean;
    /** @type {TimeoutError|null} */
    error: TimeoutError | null;
    _onOuterAbort: (() => void) | undefined;
    _outer: AbortSignal | undefined;
    get signal(): AbortSignal;
    get aborted(): boolean;
    _abortFromOuter(outer: any): void;
    _fire(code: any, phase: any, ms: any): void;
    _clearAll(): void;
    /**
     * Start a bounded phase. Returns a function that ends it. Only one phase runs at a time; a new
     * phase implicitly ends the previous one, which matches the actual sequence
     * connect -> handshake -> headers and keeps callers from having to unwind by hand.
     */
    beginPhase(name: any): () => void;
    endPhase(): void;
    /**
     * Arm the idle deadline. Call `touch()` on every byte that arrives; each touch restarts the
     * timer. Nothing here reads a clock, which is what makes it work on a runtime whose clock is
     * frozen between I/O events.
     */
    beginIdle(): void;
    touch(): void;
    /** Release every timer. Safe to call more than once; must be called on every exit path. */
    dispose(): void;
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
    get _abortPromise(): Promise<any>;
    __abortP: Promise<any> | undefined;
    race(promise: any): Promise<any>;
}
export type DeadlineOptions = {
    /**
     * TCP connect (and proxy handshake) must complete within this
     */
    connectMs?: number | undefined;
    /**
     * TLS handshake must complete within this
     */
    handshakeMs?: number | undefined;
    /**
     * response status line + headers must arrive within this
     */
    headersMs?: number | undefined;
    /**
     * maximum gap between body chunks
     */
    idleMs?: number | undefined;
    /**
     * hard ceiling on the whole request; a backstop, not the control
     */
    totalMs?: number | undefined;
};
import { TimeoutError } from '../errors.js';
