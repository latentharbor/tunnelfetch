// The Chrome identity, ready to use. Importing this module IS the opt-in.
//
// `profiles.chrome` in the main entry is a declaration: it names what the identity needs and
// REFUSES to be presented without it, so nobody accidentally ships a Chromium ClientHello over a
// curl handshake. That refusal is correct but it leaves the caller to find and wire two WASM
// primitives, which is friction for the common case of "I want Chrome".
//
// This module closes that gap without moving the cost onto anyone else. The main entry stays free
// of both blobs — a bundler only pulls them in for code that imports THIS path, so a caller using
// the curl default pays nothing. That is the whole reason it is a separate entry point rather than
// a flag.
//
//   import { Client } from 'tunnelfetch';
//   import { chrome } from 'tunnelfetch/profile/chrome';
//   new Client({ profile: chrome, connect, proxy });
//
// All four requirements are met here, so this profile is usable as it stands. `br` and `zstd` were
// held back at first on the grounds that there is no single right implementation — measurement
// dissolved that: a decode-only build of the reference C beats the npm alternative by 1.5x at the
// interface this package actually uses, and the whole cost is 3 ms once per isolate plus per-byte
// decoding only when an origin actually serves those codings.

import { chrome as declaration } from '../profiles.js';
import { chacha20poly1305 } from './vendor/chacha20poly1305.js';
import { mlkem768 } from './vendor/mlkem768.js';
import { br } from './vendor/brotli-dec.js';
import { zstd } from './vendor/zstd-dec.js';

/**
 * `profiles.chrome` with the two capabilities this package cannot perform natively already wired
 * in. Everything else about it — the cipher list, the groups, the shuffled extension order, GREASE,
 * the HTTP/2 SETTINGS and pseudo-header order, the request header order — comes from the
 * declaration unchanged, and all of it was captured off the wire from Chrome 150.
 *
 * @type {import('../profiles.js').FingerprintProfile & {
 *   ciphers: Record<string, unknown>, groups: Record<string, unknown> }}
 */
export const chrome = Object.freeze({
  ...declaration,
  name: `${declaration.name} (with bundled crypto and codecs)`,
  // These satisfy every entry in `requires`, so the profile constructs. A caller's own
  // `decoders`/`ciphers`/`groups` still win over these — see applyProfile.
  ciphers: Object.freeze({ chacha20: chacha20poly1305 }),
  groups: Object.freeze({ x25519mlkem768: mlkem768 }),
  // Chrome advertises `gzip, deflate, br, zstd`, so the identity is not presentable without these.
  // `decodeBody` now bounds a registered decoder's output by the client's `maxBodyBytes` too (not
  // just the built-in gzip/deflate path), so these honour the caller's cap.
  //
  // Each also self-limits at 256 MiB, and that number is worth being blunt about: a Workers isolate
  // has a 128 MB memory ceiling, so the self-limit is TWICE the ceiling and cannot fire before the
  // isolate is already dead. It is a backstop against a runaway decoder, not against a bomb. On
  // this runtime the only thing that actually stops a decompression bomb is `maxBodyBytes`, which
  // defaults to Infinity — so a caller who fetches arbitrary origins and buffers the result with
  // `.json()`/`.text()`/`.arrayBuffer()` should set it. An earlier version of this comment claimed
  // the self-limit was what kept the 1.4.1 gzip-bomb hole closed for these two codings. It was not.
  decoders: Object.freeze({ br, zstd }),
});

export { chacha20poly1305, mlkem768, br, zstd };
