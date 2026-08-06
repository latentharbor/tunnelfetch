// The same three functions as the Rust module in live/src/wasmbytes.wasm, byte for byte in
// behaviour, so the only variable between the two builds is the toolchain.
//
// Cloudflare's own post on Kitesurf argues against Emscripten: "Emscripten (for example) and its
// many layers of mocked dependencies, the compiled binary can get bulky and slow." That is a claim
// about a toolchain, and it is cheap to check rather than repeat.

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long usize;

// A fixed arena, so no build drags in malloc and the comparison stays about codegen. 16 MiB is
// the largest buffer the rig hands over (`mb=16`), and bench.rs sizes its arena identically —
// they have to match, or one toolchain silently overruns at a size the other survives.
static u8 ARENA[16u << 20];

__attribute__((used)) u8 *alloc(usize len) {
  (void)len;
  return ARENA;
}

/** Touch every byte, with an accumulator a compiler cannot fold away. */
__attribute__((used)) u32 sum(const u8 *p, usize len) {
  u32 acc = 0;
  for (usize i = 0; i < len; i++) acc = acc * 31u + p[i];
  return acc;
}

/** Walk TLS-record-shaped headers: 5-byte header, big-endian length at [3..4], skip the body. */
__attribute__((used)) u32 frame_walk(const u8 *p, usize len) {
  u32 n = 0;
  usize off = 0;
  while (off + 5 <= len) {
    u32 blen = ((u32)p[off + 3] << 8) | (u32)p[off + 4];
    off += 5 + blen;
    n++;
    if (blen == 0) break; // a zero-length record would spin forever
  }
  return n;
}
