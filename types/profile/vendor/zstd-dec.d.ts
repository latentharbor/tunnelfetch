/**
 * Make a `zstd` BodyDecoder: (ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>.
 *
 * Fail-closed: EOF anywhere but a frame boundary errors (truncated), garbage between or after
 * frames errors, frame checksums are verified when present (xxhash64 is compiled in). Multiple
 * concatenated frames are legal and decoded in sequence, like the zstd CLI does. Zero input
 * bytes decode to zero output bytes, matching the package's empty-body treatment.
 *
 * @param {{ maxOutputBytes?: number, windowLogMax?: number }} [opts] output cap (default
 *   256 MiB) and max accepted frame window log2 (default 23 = 8 MiB, Chrome's limit; clamped
 *   to [10, 23] — the wasm memory maximum is sized for 23).
 * @returns {(stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>}
 */
export function makeZstdDecoder({ maxOutputBytes, windowLogMax, }?: {
    maxOutputBytes?: number;
    windowLogMax?: number;
}): (stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>;
export const buildId: "0a52f071dfdb";
export namespace _wasm {
    export { _mod as module };
    export let shared: WebAssembly.Exports;
}
/** Ready-made `zstd` decoder with the defaults: `decoders: { zstd }`. */
export const zstd: (stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>;
declare const _mod: WebAssembly.Module;
export {};
