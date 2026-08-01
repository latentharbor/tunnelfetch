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
  // Each bounds its own output — `decodeBody` deliberately does not cap a caller-supplied decoder,
  // and a decoder that did not self-limit would reopen the gzip-bomb hole closed in 1.4.1.
  decoders: Object.freeze({ br, zstd }),
});

export { chacha20poly1305, mlkem768, br, zstd };
