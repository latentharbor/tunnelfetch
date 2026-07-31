// The resumption ticket store: per-Client, keyed like the connection pool, single-use.
//
// A ticket is a credential. Presenting one tells the server "treat this connection as a
// continuation of the session you issued it on", and the server will — without sending a
// certificate, without this client re-validating anything. So the one property this store must
// never lose is that a ticket can only ever be OFFERED under the exact configuration it was
// OBTAINED under. The pool solved the identical problem for sockets: poolKey() folds scheme,
// host, port, proxy, trust policy and TLS options into the key precisely so a connection
// validated under one policy cannot serve a request that asked for another. Tickets are keyed
// by the caller with that same key, for that same reason. Keying by hostname alone is the
// canonical mistake here: it lets a request that asked for certificate pinning resume — and
// silently skip the pin check — on the strength of a session that was never pinned at all.
//
// Three smaller policies, each deliberate:
//
//   * Single use. A ticket is consumed by take() whether or not the resumption succeeds.
//     RFC 8446 appendix C.4 wants tickets used at most once (reuse lets a passive observer
//     correlate connections), servers commonly enforce it, and a second offer of a spent ticket
//     would burn a round trip to be declined. Servers that want chains of resumption issue a
//     fresh ticket on every connection, including resumed ones.
//   * Lifetimes are honoured on both ends: a ticket_lifetime of zero is discarded on arrival
//     (s4.6.1 says exactly that), everything is capped at the protocol's seven-day ceiling
//     (clients MUST NOT cache longer, whatever the server claimed), and take() re-checks age at
//     the moment of use, so a ticket that expired while stored is dropped, not offered.
//   * The clock is injected. Ages are wall-clock quantities, and on the target runtime the
//     clock is frozen within a synchronous slice — tests need to move time, and nothing else in
//     the TLS layer reads a clock at all.

import { TlsError, codes } from '../errors.js';
import { hashLength } from './keyschedule.js';

/** RFC 8446 s4.6.1: servers MUST NOT exceed this, and clients MUST NOT cache beyond it. */
const MAX_LIFETIME_SEC = 604800; // seven days

export class TicketStore {
  /**
   * @param {object} [opts]
   * @param {number} [opts.maxPerKey] tickets retained per key, default 2 — the number a typical
   *   server flight issues; older tickets are evicted first
   * @param {() => number} [opts.now] epoch-ms source, injectable for tests
   */
  constructor({ maxPerKey = 2, now = () => Date.now() } = {}) {
    /** @type {Map<string, Array<StoredTicket>>} */
    this._byKey = new Map();
    this._maxPerKey = maxPerKey;
    this._now = now;
  }

  /**
   * @typedef {object} StoredTicket
   * @property {Uint8Array} identity
   * @property {Uint8Array} psk
   * @property {import('./keyschedule.js').ScheduleHash} hash
   * @property {number} ageAdd
   * @property {number} lifetimeMs already clamped to the seven-day ceiling
   * @property {number} receivedAtMs
   * @property {object} peer
   * @property {number} cipherSuite
   */

  /** Total tickets currently held, for tests and diagnostics. */
  get size() {
    let n = 0;
    for (const list of this._byKey.values()) n += list.length;
    return n;
  }

  /**
   * Store a captured ticket under `key`. Returns whether it was retained: a zero (or negative)
   * lifetime is a server instruction to discard immediately and is honoured silently — that is
   * the server's prerogative, not an error — while a structurally unusable capture (no PSK, no
   * identity, unknown hash) throws, because the only producer is this package's own driver and
   * a malformed capture is a bug, not an input.
   *
   * @param {string} key the pool key of the connection the ticket arrived on
   * @param {import('./connect.js').CapturedTicket} captured
   * @returns {boolean}
   */
  put(key, captured) {
    const { identity, psk, hash, lifetimeSec, ageAdd } = captured;
    hashLength(hash); // throws on anything but SHA-256/SHA-384
    if (!(identity instanceof Uint8Array) || identity.byteLength === 0 ||
        !(psk instanceof Uint8Array) || psk.byteLength === 0) {
      throw new TlsError(codes.TLS_TICKET,
        'a captured ticket needs a non-empty identity and PSK; refusing to store a blank credential');
    }
    if (!Number.isInteger(lifetimeSec) || !Number.isInteger(ageAdd)) {
      throw new TlsError(codes.TLS_TICKET,
        `ticket lifetime ${lifetimeSec} / age_add ${ageAdd} are not integers`,
        { lifetimeSec, ageAdd });
    }
    if (lifetimeSec <= 0) return false; // s4.6.1: zero means discard immediately
    const lifetimeMs = Math.min(lifetimeSec, MAX_LIFETIME_SEC) * 1000;
    const list = this._byKey.get(key) ?? [];
    list.push({
      identity, psk, hash, ageAdd, lifetimeMs,
      receivedAtMs: this._now(),
      peer: captured.peer ?? null,
      cipherSuite: captured.cipherSuite,
    });
    while (list.length > this._maxPerKey) list.shift();
    this._byKey.set(key, list);
    return true;
  }

  /**
   * Take the freshest usable ticket for `key` as a ready-to-offer PSK, or null. The ticket is
   * removed either way it goes from here — single use — and expired tickets encountered on the
   * way are dropped rather than offered: a server checks obfuscated_ticket_age against the
   * lifetime it granted, and offering a stale ticket is a round trip spent being refused.
   *
   * @param {string} key MUST be built from the same inputs as the connection's pool key; this
   *   equality is the entire trust story of resumption (see the module comment)
   * @returns {import('./connect.js').ResumptionOffer | null}
   */
  take(key) {
    const list = this._byKey.get(key);
    if (!list) return null;
    while (list.length > 0) {
      const t = /** @type {StoredTicket} */ (list.pop());
      const age = this._now() - t.receivedAtMs;
      if (age >= t.lifetimeMs) continue; // expired in storage: drop it, try the next-newest
      if (list.length === 0) this._byKey.delete(key);
      return {
        identity: t.identity,
        psk: t.psk,
        hash: t.hash,
        peer: t.peer,
        // s4.2.11.1: obfuscated_ticket_age = age-in-ms + ticket_age_add, mod 2^32, current at
        // the moment each hello is built (a HelloRetryRequest builds a second one later).
        obfuscatedTicketAge: () => {
          const ms = Math.max(0, this._now() - t.receivedAtMs);
          return (ms + t.ageAdd) % 0x100000000;
        },
      };
    }
    this._byKey.delete(key);
    return null;
  }

  /** Drop everything; a closed Client must not keep credentials alive. */
  clear() {
    this._byKey.clear();
  }
}
