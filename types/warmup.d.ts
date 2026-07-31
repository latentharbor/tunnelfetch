/**
 * What one warmup() call reports. `ok` is the only field a caller usually needs; the rest exists
 * so a failure names the exact problem rather than being a silent no-op.
 * @typedef {object} WarmupReport
 * @property {boolean} ok every iteration completed
 * @property {number} iterations how many replays ran to completion
 * @property {string | null} error first failure, if any — warmup() itself never throws
 */
/**
 * Warm the hot path by replaying a recorded proxy + TLS + HTTP exchange through the real code.
 * See the module comment for what this buys, what it costs, and when NOT to call it. Never
 * called by the package itself; call it from module scope of your worker if — and only if —
 * your deployment does not bill startup CPU.
 *
 * Safe by construction: no network, no randomness, no timers, nothing cached, and it never
 * throws — a runtime that forbids more than expected yields `{ ok: false, error }` and the
 * package behaves exactly as if warmup() had never been called.
 *
 * @param {{ iterations?: number }} [opts] replay count, default 5, clamped to 1..10. One pass
 *   moves the hot functions out of the interpreter; more passes push V8's tiering further down
 *   the ramp at proportionally more startup cost. Measured startup cost is roughly 10-20 ms per
 *   iteration on current edge hardware, against the 1 s startup budget.
 * @returns {Promise<WarmupReport>}
 */
export function warmup({ iterations }?: {
    iterations?: number;
}): Promise<WarmupReport>;
/**
 * What one warmup() call reports. `ok` is the only field a caller usually needs; the rest exists
 * so a failure names the exact problem rather than being a silent no-op.
 */
export type WarmupReport = {
    /**
     * every iteration completed
     */
    ok: boolean;
    /**
     * how many replays ran to completion
     */
    iterations: number;
    /**
     * first failure, if any — warmup() itself never throws
     */
    error: string | null;
};
