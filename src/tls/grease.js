// GREASE (RFC 8701) — reserved values a client sprinkles through its ClientHello so that servers
// and middleboxes stay tolerant of values they do not recognise. A peer MUST ignore them; one that
// negotiates a GREASE value is broken, and this file makes that refusal explicit rather than
// leaving it to a downstream "no parameters for this suite" check whose message would blame the
// offer list.
//
// curl does not GREASE. Chromium does, and its placement was captured off the wire from this
// machine's Chromium rather than recalled — two ClientHellos, compared:
//
//   ciphers            one GREASE value, FIRST
//   extensions         one GREASE extension FIRST (empty) and one LAST (a single zero byte)
//   supported_groups   one GREASE value, FIRST
//   supported_versions one GREASE value, FIRST
//   key_share          one GREASE entry FIRST, carrying a one-byte key
//   ALPN               none
//   signature_algorithms none
//
// The same capture settled something that would otherwise have been guessed wrong: Chromium
// SHUFFLES its extension order on every connection. The two hellos shared an identical non-GREASE
// extension set and had entirely different orders, with GREASE first and last both times and a
// different GREASE value each time. So "match Chrome's extension order" is not a fixed list — it
// is a shuffle. See `shuffleExtensions`.

/** The sixteen reserved values (RFC 8701 s2): 0x0A0A, 0x1A1A, ... 0xFAFA. */
export const GREASE_VALUES = Object.freeze(
  Array.from({ length: 16 }, (_, i) => (i << 12) | 0x0a00 | (i << 4) | 0x0a),
);

/** @param {number} v @returns {boolean} */
export function isGrease(v) {
  return (v & 0x0f0f) === 0x0a0a && v >>> 8 === (v & 0xff);
}

/**
 * A deterministic-from-seed source of GREASE values and shuffles.
 *
 * Seeded rather than ad-hoc `Math.random` for two reasons: this package forbids ambient randomness
 * in `src/` (repo-hygiene enforces it, so that every byte on the wire is reproducible in a test),
 * and a fingerprint that cannot be reproduced cannot be asserted byte-for-byte.
 *
 * @param {number} seed
 */
export function greaseSource(seed) {
  let s = seed >>> 0 || 0x9e3779b9;
  const next = () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
  const used = new Set();
  return {
    /** A GREASE value not yet handed out in this hello, since Chromium never repeats one. */
    take() {
      for (let i = 0; i < 64; i++) {
        const v = GREASE_VALUES[next() % GREASE_VALUES.length];
        if (!used.has(v)) {
          used.add(v);
          return v;
        }
      }
      /* c8 ignore next */
      return GREASE_VALUES[used.size % GREASE_VALUES.length];
    },
    next,
  };
}

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
export function shuffleExtensions(parts, rng, typeOf, pskType) {
  const out = [...parts];
  // Anything pinned at either end stays put: leading GREASE, and trailing GREASE or pre_shared_key.
  let lo = 0;
  while (lo < out.length && isGrease(typeOf(out[lo]))) lo++;
  let hi = out.length - 1;
  while (hi > lo && (isGrease(typeOf(out[hi])) || typeOf(out[hi]) === pskType)) hi--;

  for (let i = hi; i > lo; i--) {
    const j = lo + (rng.next() % (i - lo + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/**
 * A GREASE key_share entry: a reserved group with a single-byte key, which is what Chromium sends.
 * The byte is fixed rather than random — it is never used for anything, and a value that varies
 * would only make the hello harder to assert on.
 *
 * @param {number} group
 */
export function greaseKeyShare(group) {
  return { group, keyExchange: Uint8Array.of(0x00) };
}
