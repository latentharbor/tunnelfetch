#!/bin/sh
# Build the three toolchain-comparison modules the rig's `wasm-boundary` op instantiates.
#
# They exist to answer one question with a measurement instead of a citation: Cloudflare's Kitesurf
# post warns that with "Emscripten (for example) and its many layers of mocked dependencies, the
# compiled binary can get bulky and slow". All three implement byte-identical alloc/sum/frame_walk
# and import nothing, so `?op=wasm-boundary&tool=rust|emcc|clang` differs only in who compiled it.
#
# The artifacts are committed under live/src/ because workerd refuses WebAssembly.instantiate() on
# runtime bytes ("Wasm code generation disallowed by embedder"), so they have to be bundled at build
# time. They are a few hundred bytes each; the Rust one is larger because rustc emits more preamble.
#
#   EMSDK=/path/to/emsdk sh live/wasm/build.sh
#
# emcc comes from an emsdk checkout (git clone https://github.com/emscripten-core/emsdk, then
# ./emsdk install latest && ./emsdk activate latest; it needs python 3.10+). rust-lld ships inside
# the rustup toolchain, so the freestanding-clang build needs no separate LLVM install.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../src"

echo "== rust -> wasmbytes.wasm"
rustc --target wasm32-unknown-unknown -O --crate-type=cdylib \
  -o "$OUT/wasmbytes.wasm" "$HERE/bench.rs"

echo "== clang, freestanding -> clangbytes.wasm"
LLD="$(find "$HOME/.rustup/toolchains" -name rust-lld -maxdepth 6 | head -1)"
clang --target=wasm32 -O3 -nostdlib -ffreestanding -c "$HERE/bench.c" -o "$HERE/bench.o"
"$LLD" -flavor wasm --no-entry --allow-undefined \
  --export=alloc --export=sum --export=frame_walk --export=memory \
  -o "$OUT/clangbytes.wasm" "$HERE/bench.o"
rm -f "$HERE/bench.o"

echo "== emcc -> emccbytes.wasm"
. "${EMSDK:?set EMSDK to an emsdk checkout}/emsdk_env.sh" >/dev/null 2>&1
emcc -O3 -sSTANDALONE_WASM --no-entry -sALLOW_MEMORY_GROWTH=0 -sINITIAL_MEMORY=32MB \
  -sEXPORTED_FUNCTIONS=_alloc,_sum,_frame_walk \
  "$HERE/bench.c" -o "$OUT/emccbytes.wasm"

# The same C the package already ships as its ChaCha20-Poly1305, compiled by Emscripten instead of
# wasi-sdk clang. This is the toolchain comparison on a real cipher rather than on a toy loop; the
# shipped module stays the wasi-sdk one (see live/src/emcc-chacha.js).
echo "== emcc -> emccchacha.wasm"
emcc -O3 -sSTANDALONE_WASM --no-entry -sALLOW_MEMORY_GROWTH=0 -sINITIAL_MEMORY=16MB \
  -sEXPORTED_FUNCTIONS=_cc_key,_cc_nonce,_cc_aad,_cc_msg,_cc_msg_cap,_cc_aad_cap,_cc_seal,_cc_open \
  "$HERE/../../wasmcrypto/c/chacha20poly1305.c" -o "$OUT/emccchacha.wasm"

ls -l "$OUT"/*.wasm
