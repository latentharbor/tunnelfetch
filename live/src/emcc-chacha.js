// The vendored ChaCha20-Poly1305 C, compiled by Emscripten instead of wasi-sdk clang.
//
// Same source file (wasmcrypto/c/chacha20poly1305.c), same -O3, same freestanding shape — zero
// imports in both. Only the toolchain differs, which is the whole point: Cloudflare's Kitesurf
// post warns that with "Emscripten (for example) and its many layers of mocked dependencies, the
// compiled binary can get bulky and slow", and this rig exists to check that against the workload
// this package would actually compile rather than to repeat it.
//
//   wasi-sdk 25 / LLVM 19   8839 bytes  (shipped)
//   emcc -sSTANDALONE_WASM 10321 bytes
//
// Bench-only: nothing in src/ imports this.
import EMCCCHACHA from './emccchacha.wasm';

const x = new WebAssembly.Instance(EMCCCHACHA, {}).exports;
const MSG = x.cc_msg(), AAD = x.cc_aad(), KEY = x.cc_key(), NONCE = x.cc_nonce();
const MSG_CAP = x.cc_msg_cap(), AAD_CAP = x.cc_aad_cap();
let mem = new Uint8Array(x.memory.buffer);
const view = () => (mem.buffer === x.memory.buffer ? mem : (mem = new Uint8Array(x.memory.buffer)));
const EMPTY = new Uint8Array(0);

export const emccChacha = {
  seal(key, nonce, plaintext, aad = EMPTY) {
    if (plaintext.length > MSG_CAP) throw new RangeError('plaintext too long');
    if (aad.length > AAD_CAP) throw new RangeError('aad too long');
    const m = view();
    m.set(key, KEY); m.set(nonce, NONCE); m.set(aad, AAD); m.set(plaintext, MSG);
    const n = x.cc_seal(plaintext.length, aad.length);
    if (n < 0) throw new RangeError('seal rejected input');
    return view().slice(MSG, MSG + n);
  },
  open(key, nonce, ciphertext, aad = EMPTY) {
    if (ciphertext.length < 16 || ciphertext.length > MSG_CAP + 16) {
      throw new Error('emcc chacha20poly1305: invalid ciphertext');
    }
    const m = view();
    m.set(key, KEY); m.set(nonce, NONCE); m.set(aad, AAD); m.set(ciphertext, MSG);
    const n = x.cc_open(ciphertext.length, aad.length);
    if (n < 0) throw new Error('emcc chacha20poly1305: authentication failed');
    return view().slice(MSG, MSG + n);
  },
};
