/** @param {number} v @returns {boolean} */
export function isGrease(v: number): boolean;
/**
 * A deterministic-from-seed source of GREASE values and shuffles.
 *
 * Seeded rather than ad-hoc `Math.random` for two reasons: this package forbids ambient randomness
 * in `src/` (repo-hygiene enforces it, so that every byte on the wire is reproducible in a test),
 * and a fingerprint that cannot be reproduced cannot be asserted byte-for-byte.
 *
 * @param {number} seed
 */
export function greaseSource(seed: number): {
    /** A GREASE value not yet handed out in this hello, since Chromium never repeats one. */
    take(): number;
    next: () => number;
};
/**
 * Fisher-Yates over the middle of the extension list, leaving the ends alone.
 *
 * The first and last positions are not free: Chromium pins a GREASE extension to each, and
 * `pre_shared_key` MUST be last of all (RFC 8446 s4.2.11 — the binder transcript is the hello
 * truncated just before the binders, a range that only exists if nothing follows them). So the
 * shuffle covers everything between the fixed ends and nothing else.
 *
 * @param {Array<Uint8Array>} parts encoded extensions, already ordered
 * @param {{next: () => number}} rng
 * @param {(e: Uint8Array) => number} typeOf
 * @param {number} pskType
 * @returns {Array<Uint8Array>}
 */
export function shuffleExtensions(parts: Array<Uint8Array>, rng: {
    next: () => number;
}, typeOf: (e: Uint8Array) => number, pskType: number): Array<Uint8Array>;
/**
 * A GREASE key_share entry: a reserved group with a single-byte key, which is what Chromium sends.
 * The byte is fixed rather than random — it is never used for anything, and a value that varies
 * would only make the hello harder to assert on.
 *
 * @param {number} group
 */
export function greaseKeyShare(group: number): {
    group: number;
    keyExchange: Uint8Array<ArrayBuffer>;
};
/** The sixteen reserved values (RFC 8701 s2): 0x0A0A, 0x1A1A, ... 0xFAFA. */
export const GREASE_VALUES: readonly number[];
