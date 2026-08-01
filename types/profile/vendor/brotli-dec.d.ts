/**
 * Make a `br` BodyDecoder: (ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>.
 *
 * Fail-closed by construction: a truncated stream errors (EOF before the final metablock),
 * trailing bytes after the stream end error, decode errors error — partial output is never
 * silently presented as complete. Zero input bytes decode to zero output bytes, matching how
 * the package treats empty bodies under a Content-Encoding header.
 *
 * @param {{ maxOutputBytes?: number }} [opts] cap on total decoded output (default 256 MiB;
 *   Infinity disables — then the caller owns bomb protection).
 * @returns {(stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>}
 */
export function makeBrotliDecoder({ maxOutputBytes }?: {
    maxOutputBytes?: number;
}): (stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>;
export const buildId: "c64433b01d64";
export namespace _wasm {
    export { _mod as module };
    export let shared: WebAssembly.Exports;
}
/** Ready-made `br` decoder with the default output cap: `decoders: { br }`. */
export const br: (stream: ReadableStream<Uint8Array>) => ReadableStream<Uint8Array>;
declare const _mod: WebAssembly.Module;
export {};
