/**
 * `profiles.chrome` with the two capabilities this package cannot perform natively already wired
 * in. Everything else about it — the cipher list, the groups, the shuffled extension order, GREASE,
 * the HTTP/2 SETTINGS and pseudo-header order, the request header order — comes from the
 * declaration unchanged, and all of it was captured off the wire from Chrome 150.
 *
 * @type {import('../profiles.js').FingerprintProfile & {
 *   ciphers: Record<string, unknown>, groups: Record<string, unknown> }}
 */
export const chrome: import("../profiles.js").FingerprintProfile & {
    ciphers: Record<string, unknown>;
    groups: Record<string, unknown>;
};
import { chacha20poly1305 } from './vendor/chacha20poly1305.js';
import { mlkem768 } from './vendor/mlkem768.js';
import { br } from './vendor/brotli-dec.js';
import { zstd } from './vendor/zstd-dec.js';
export { chacha20poly1305, mlkem768, br, zstd };
