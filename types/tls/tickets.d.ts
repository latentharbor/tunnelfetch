export class TicketStore {
    /**
     * @param {object} [opts]
     * @param {number} [opts.maxPerKey] tickets retained per key, default 2 — the number a typical
     *   server flight issues; older tickets are evicted first
     * @param {() => number} [opts.now] epoch-ms source, injectable for tests
     */
    constructor({ maxPerKey, now }?: {
        maxPerKey?: number | undefined;
        now?: (() => number) | undefined;
    });
    /** @type {Map<string, Array<StoredTicket>>} */
    _byKey: Map<string, Array<{
        identity: Uint8Array;
        psk: Uint8Array;
        hash: import("./keyschedule.js").ScheduleHash;
        ageAdd: number;
        /**
         * already clamped to the seven-day ceiling
         */
        lifetimeMs: number;
        receivedAtMs: number;
        peer: object;
        cipherSuite: number;
    }>>;
    _maxPerKey: number;
    _now: () => number;
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
    get size(): number;
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
    put(key: string, captured: import("./connect.js").CapturedTicket): boolean;
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
    take(key: string): import("./connect.js").ResumptionOffer | null;
    /** Drop everything; a closed Client must not keep credentials alive. */
    clear(): void;
}
