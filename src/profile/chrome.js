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
// Still not supplied here: `br` and `zstd` decoders. Those are not cryptography and there is no
// single right implementation — bring your own through `decoders` (see the README). The profile
// will keep refusing until you do, which is the point.

import { chrome as declaration } from '../profiles.js';
import { chacha20poly1305 } from './vendor/chacha20poly1305.js';
import { mlkem768 } from './vendor/mlkem768.js';

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
  name: `${declaration.name} (with bundled ML-KEM and ChaCha20)`,
  // These satisfy two of the four entries in `requires`. `decoder:br` and `decoder:zstd` remain the
  // caller's, so constructing a Client with this profile still fails until they are supplied —
  // deliberately, because a Chrome that advertises `br` and cannot read it is worse than one that
  // says so up front.
  ciphers: Object.freeze({ chacha20: chacha20poly1305 }),
  groups: Object.freeze({ x25519mlkem768: mlkem768 }),
});

export { chacha20poly1305, mlkem768 };
