/**
 * A byte duplex: what every layer in this package consumes and produces.
 * @typedef {{ readable: ReadableStream<Uint8Array>,
 *             writable: WritableStream<Uint8Array> }} ByteDuplex
 */
/**
 * Handshake knobs. Every one of these narrows what is offered; none can widen it beyond what
 * `constants.js` permits, so no option here can talk the client into a suite it refuses.
 *
 * @typedef {object} TlsOptions
 * @property {number[]} [versions] versions to offer, from `TLS13` / `TLS12`. Default both.
 * @property {string[]} [alpn] ALPN protocols to offer. Default `['http/1.1']`.
 * @property {number[]} [groups] supported_groups, in preference order.
 * @property {number[]} [offerGroups] groups to send an actual key_share for. Default the first
 *   supported group; a HelloRetryRequest recovers any other choice at the cost of a round trip.
 * @property {number[]} [ciphers] cipher suites to offer, in preference order.
 * @property {Uint8Array} [clientRandom] fixed ClientHello.random, for reproducible handshakes.
 * @property {Uint8Array} [legacySessionId] fixed legacy_session_id, likewise.
 * @property {boolean} [compatibilityCcs] send the middlebox-compatibility ChangeCipherSpec.
 *   Default true.
 * @property {number} [maxHandshakeMessage] per-message cap; certificate chains dominate sizing.
 * @property {number} [maxKeyUpdates] received KeyUpdates tolerated before it is called a flood.
 * @property {number} [maxTranscriptBytes] cap on buffered handshake transcript.
 */
/**
 * Injectable nondeterminism. Supplying these makes a handshake byte-for-byte reproducible, which
 * is what allows a recorded session to be replayed in an offline test.
 * @typedef {object} TlsDeps
 * @property {(n: number) => Uint8Array} [randomBytes]
 * @property {(algorithm: object, group: number) => Promise<CryptoKeyPair>} [generateKeyPair]
 */
/**
 * What a completed handshake reports about itself.
 * @typedef {object} TlsSessionInfo
 * @property {number} version negotiated version, `0x0304` or `0x0303`
 * @property {number} cipherSuite negotiated suite
 * @property {number} group negotiated key-exchange group
 * @property {string | null} alpnProtocol
 * @property {string} hostname the identity the certificate was required to prove
 * @property {boolean} [extendedMasterSecret] TLS 1.2 only: whether RFC 7627 was in effect
 */
/**
 * A live TLS session: a plaintext duplex plus what was negotiated to get it.
 * @typedef {object} TlsSession
 * @property {ReadableStream<Uint8Array>} readable
 * @property {WritableStream<Uint8Array>} writable
 * @property {import('./record.js').RecordLayer} record
 * @property {object} peer whatever `verifyPeer` resolved with: the validated leaf
 * @property {TlsSessionInfo} info
 * @property {() => Promise<void>} close
 */
/**
 * Run a TLS handshake over a byte duplex, negotiating the version, and return the plaintext
 * duplex above it. The default offer is [TLS 1.3, TLS 1.2]; `options.versions` narrows it.
 *
 * @param {object} args
 * @param {ByteDuplex} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {import('./handshake.js').VerifyPeer} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key either
 *   driver will accept a handshake signature from. Receives the peer's stapled OCSP response,
 *   when there is one, as its third argument.
 * @param {TlsOptions} [args.options]
 * @param {TlsDeps} [args.deps]
 * @returns {Promise<TlsSession>}
 */
export function connectTls({ transport, hostname, verifyPeer, options, deps }: {
    transport: ByteDuplex;
    hostname: string;
    verifyPeer: import("./handshake.js").VerifyPeer;
    options?: TlsOptions | undefined;
    deps?: TlsDeps | undefined;
}): Promise<TlsSession>;
/**
 * A byte duplex: what every layer in this package consumes and produces.
 */
export type ByteDuplex = {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
};
/**
 * Handshake knobs. Every one of these narrows what is offered; none can widen it beyond what
 * `constants.js` permits, so no option here can talk the client into a suite it refuses.
 */
export type TlsOptions = {
    /**
     * versions to offer, from `TLS13` / `TLS12`. Default both.
     */
    versions?: number[] | undefined;
    /**
     * ALPN protocols to offer. Default `['http/1.1']`.
     */
    alpn?: string[] | undefined;
    /**
     * supported_groups, in preference order.
     */
    groups?: number[] | undefined;
    /**
     * groups to send an actual key_share for. Default the first
     * supported group; a HelloRetryRequest recovers any other choice at the cost of a round trip.
     */
    offerGroups?: number[] | undefined;
    /**
     * cipher suites to offer, in preference order.
     */
    ciphers?: number[] | undefined;
    /**
     * fixed ClientHello.random, for reproducible handshakes.
     */
    clientRandom?: Uint8Array<ArrayBufferLike> | undefined;
    /**
     * fixed legacy_session_id, likewise.
     */
    legacySessionId?: Uint8Array<ArrayBufferLike> | undefined;
    /**
     * send the middlebox-compatibility ChangeCipherSpec.
     * Default true.
     */
    compatibilityCcs?: boolean | undefined;
    /**
     * per-message cap; certificate chains dominate sizing.
     */
    maxHandshakeMessage?: number | undefined;
    /**
     * received KeyUpdates tolerated before it is called a flood.
     */
    maxKeyUpdates?: number | undefined;
    /**
     * cap on buffered handshake transcript.
     */
    maxTranscriptBytes?: number | undefined;
};
/**
 * Injectable nondeterminism. Supplying these makes a handshake byte-for-byte reproducible, which
 * is what allows a recorded session to be replayed in an offline test.
 */
export type TlsDeps = {
    randomBytes?: ((n: number) => Uint8Array) | undefined;
    generateKeyPair?: ((algorithm: object, group: number) => Promise<CryptoKeyPair>) | undefined;
};
/**
 * What a completed handshake reports about itself.
 */
export type TlsSessionInfo = {
    /**
     * negotiated version, `0x0304` or `0x0303`
     */
    version: number;
    /**
     * negotiated suite
     */
    cipherSuite: number;
    /**
     * negotiated key-exchange group
     */
    group: number;
    alpnProtocol: string | null;
    /**
     * the identity the certificate was required to prove
     */
    hostname: string;
    /**
     * TLS 1.2 only: whether RFC 7627 was in effect
     */
    extendedMasterSecret?: boolean | undefined;
};
/**
 * A live TLS session: a plaintext duplex plus what was negotiated to get it.
 */
export type TlsSession = {
    readable: ReadableStream<Uint8Array>;
    writable: WritableStream<Uint8Array>;
    record: import("./record.js").RecordLayer;
    /**
     * whatever `verifyPeer` resolved with: the validated leaf
     */
    peer: object;
    info: TlsSessionInfo;
    close: () => Promise<void>;
};
