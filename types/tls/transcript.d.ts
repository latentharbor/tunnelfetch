export class Transcript {
    /**
     * @param {import('./keyschedule.js').ScheduleHash} hash fixed once the cipher suite is known
     * @param {{ maxBytes?: number }} [opts] transcript buffer cap, default 1 MiB
     */
    constructor(hash: import("./keyschedule.js").ScheduleHash, { maxBytes }?: {
        maxBytes?: number;
    });
    _hash: import("./keyschedule.js").ScheduleHash;
    /** @type {Uint8Array[]} */
    _chunks: Uint8Array[];
    _len: number;
    _maxBytes: number;
    /** @type {Uint8Array | null} digest cache, invalidated by update() */
    _cached: Uint8Array | null;
    get bytesBuffered(): number;
    /**
     * Append raw handshake message bytes (including the 4-byte message header — the transcript
     * is over complete Handshake structs, never record framing).
     * @param {Uint8Array} bytes
     */
    update(bytes: Uint8Array): void;
    /**
     * Digest of everything appended so far. Does not consume; call as often as needed.
     * @returns {Promise<Uint8Array>}
     */
    hash(): Promise<Uint8Array>;
    /**
     * HelloRetryRequest transcript substitution (RFC 8446 s4.4.1): when a ServerHello is an HRR,
     * the transcript restarts as a synthetic handshake message
     *
     *   message_hash(0xFE) || uint24 Hash.length || Hash(ClientHello1)
     *
     * so that a stateless server need only remember the hash of the first ClientHello. Call this
     * after ClientHello1 is the only message in the transcript, before appending the HRR itself.
     * @returns {Promise<void>}
     */
    replaceWithMessageHash(): Promise<void>;
}
