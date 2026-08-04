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
 * @property {number[]} [ciphers] cipher suites to offer, in preference order. By default every
 *   suite must be one this package can perform: an offer it cannot honour is a dead connection the
 *   moment a server selects it, so an unknown suite is refused here rather than on the wire.
 * @property {number[]} [omitExtensions] extension types to leave out of the ClientHello, the
 *   subtractive counterpart to `extraExtensions`. `status_request` (5) is the one extension this
 *   package sends that curl does not, so an identity matching a sample without it needs this.
 *   Dropping it gives up OCSP stapling, which is the only revocation signal this package can
 *   consume — pairing it with `trust.revocation: 'require-staple'` is refused rather than left to
 *   fail every connection.
 * @property {boolean} [allowUnperformableCiphers] offer suites this package cannot complete.
 *   For fingerprint fidelity only. Real clients offer far more than this package implements — curl
 *   8.21.0 offers thirty against seven performable here, Chromium fifteen against seven — so a
 *   hello restricted to what it can honour carries a cipher list shorter than any real client's,
 *   which is exactly what a JA3 hash reads. With this set, a server that selects an unperformable
 *   suite fails the handshake; the first such suite sits behind the TLS 1.3 ones in both real
 *   lists, so a 1.3-capable server does not reach it. Knowingly trading a rare failure for an
 *   accurate fingerprint is a legitimate choice; making it silently is not.
 * @property {Uint8Array[]} [extraExtensions] pre-encoded ClientHello extensions, appended before
 *   ordering. `extensionOrder` can only arrange extensions that were BUILT — it filters to what
 *   exists and sorts that — so ordering alone cannot produce an extension this package does not
 *   generate. Chromium sends several that it does not: `signed_certificate_timestamp` (18),
 *   `compress_certificate` (27), `session_ticket` (35), `application_settings` (17613) and ECH
 *   (65037). Supplying them here is the only way to close that gap, and it is the caller's job to
 *   encode them correctly — this package does not parse what it did not build.
 * @property {number[]} [sigSchemes] signature_algorithms to offer, in preference order.
 * @property {boolean | number} [grease] send GREASE (RFC 8701) reserved values in the cipher list,
 *   the extension list (one at each end), supported_groups, supported_versions and key_share.
 *   Default false, because curl does not GREASE — Chromium does. A number is a seed, which makes
 *   the hello reproducible; `true` draws one from `deps.randomBytes`. A server that negotiates a
 *   GREASE value is refused with a typed error naming it.
 * @property {number[] | 'shuffle'} [extensionOrder] ClientHello extension types, in the order to emit them.
 *   JA3 and JA4 hash the extension list in WIRE ORDER, so this is most of what a fingerprinter
 *   reads. Defaults to curl's order (`CURL_EXTENSION_ORDER`). Extensions not named keep their
 *   natural position at the end; `pre_shared_key` is always last whatever is asked, because RFC
 *   8446 s4.2.11 defines the binder transcript as the hello truncated just before the binders.
 * @property {Uint8Array} [clientRandom] fixed ClientHello.random, for reproducible handshakes.
 * @property {Uint8Array} [legacySessionId] fixed legacy_session_id, likewise.
 * @property {boolean} [compatibilityCcs] send the middlebox-compatibility ChangeCipherSpec.
 *   Default true.
 * @property {number} [maxHandshakeMessage] per-message cap; certificate chains dominate sizing.
 * @property {number} [maxKeyUpdates] received KeyUpdates tolerated before it is called a flood.
 * @property {number} [maxTranscriptBytes] cap on buffered handshake transcript.
 * @property {ResumptionOffer} [psk] offer this resumption PSK (TLS 1.3 only; requires 1.3 in
 *   the offered versions). The server may decline, in which case the full handshake continues
 *   on this same connection — there is no reconnect at any layer.
 * @property {(ticket: CapturedTicket) => void} [onSessionTicket] receive each NewSessionTicket
 *   this connection yields, already reduced to a usable PSK per RFC 8446 s7.1. Without this the
 *   tickets are read and discarded, exactly as before.
 */
/**
 * A resumption PSK ready to offer, as produced by the ticket store from a CapturedTicket.
 * `obfuscatedTicketAge` is a closure, not a number, because the age must be current at the
 * moment each hello is BUILT — a HelloRetryRequest builds a second hello later — and because
 * clock policy belongs to the store, not to this layer (which otherwise never reads a clock).
 * `peer` rides along opaquely: it is whatever the original session's verifyPeer resolved with,
 * and a resumed session (which has no Certificate message to verify) reports it as its own —
 * sound only because the ticket store keys tickets by the full trust configuration.
 * @typedef {object} ResumptionOffer
 * @property {Uint8Array} identity the ticket
 * @property {Uint8Array} psk
 * @property {import('./keyschedule.js').ScheduleHash} hash the hash the PSK was minted under
 * @property {() => number} obfuscatedTicketAge uint32 per RFC 8446 s4.2.11.1
 * @property {object} [peer]
 */
/**
 * What a NewSessionTicket becomes by the time a caller sees it: the wire fields that govern
 * offering (lifetime, age_add) plus the derived PSK and everything needed to check a future
 * selection against it. `maxEarlyDataSize` is recorded for honesty but never acted on: 0-RTT
 * is deliberately not implemented (see the driver's note).
 * @typedef {object} CapturedTicket
 * @property {Uint8Array} identity
 * @property {Uint8Array} psk
 * @property {import('./keyschedule.js').ScheduleHash} hash
 * @property {number} cipherSuite
 * @property {number} lifetimeSec
 * @property {number} ageAdd
 * @property {number | null} maxEarlyDataSize
 * @property {string | null} alpnProtocol
 * @property {object} peer
 */
/**
 * Injectable nondeterminism and crypto primitives the platform does not provide.
 *
 * `randomBytes` and `generateKeyPair` supply reproducibility (a recorded session replayed in an
 * offline test). `aead` and `kem` supply capabilities this runtime lacks entirely: ChaCha20 and
 * ML-KEM are absent from WebCrypto here, so an implementation must be injected before the suite or
 * group they back can be offered — a ClientHello being an offer a server may take.
 * @typedef {object} TlsDeps
 * @property {(n: number) => Uint8Array} [randomBytes]
 * @property {(algorithm: object, group: number) => Promise<CryptoKeyPair>} [generateKeyPair]
 * @property {{ chacha20?: import('./aead.js').AeadOptions['impl'] }} [aead] injected AEAD
 *   implementations by name; `chacha20` gates and performs TLS_CHACHA20_POLY1305_SHA256
 * @property {{ x25519mlkem768?: import('./hybrid.js').MlKem768 }} [kem] injected KEM
 *   implementations by name; `x25519mlkem768` gates and performs the X25519MLKEM768 hybrid group
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
 * @property {boolean} [resumed] TLS 1.3 only: the server accepted the offered resumption PSK,
 *   so no certificate crossed the wire on THIS connection; the identity is the one validated
 *   by the original handshake the ticket came from
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
     * cipher suites to offer, in preference order. By default every
     * suite must be one this package can perform: an offer it cannot honour is a dead connection the
     * moment a server selects it, so an unknown suite is refused here rather than on the wire.
     */
    ciphers?: number[] | undefined;
    /**
     * extension types to leave out of the ClientHello, the
     * subtractive counterpart to `extraExtensions`. `status_request` (5) is the one extension this
     * package sends that curl does not, so an identity matching a sample without it needs this.
     * Dropping it gives up OCSP stapling, which is the only revocation signal this package can
     * consume — pairing it with `trust.revocation: 'require-staple'` is refused rather than left to
     * fail every connection.
     */
    omitExtensions?: number[] | undefined;
    /**
     * offer suites this package cannot complete.
     * For fingerprint fidelity only. Real clients offer far more than this package implements — curl
     * 8.21.0 offers thirty against seven performable here, Chromium fifteen against seven — so a
     * hello restricted to what it can honour carries a cipher list shorter than any real client's,
     * which is exactly what a JA3 hash reads. With this set, a server that selects an unperformable
     * suite fails the handshake; the first such suite sits behind the TLS 1.3 ones in both real
     * lists, so a 1.3-capable server does not reach it. Knowingly trading a rare failure for an
     * accurate fingerprint is a legitimate choice; making it silently is not.
     */
    allowUnperformableCiphers?: boolean | undefined;
    /**
     * pre-encoded ClientHello extensions, appended before
     * ordering. `extensionOrder` can only arrange extensions that were BUILT — it filters to what
     * exists and sorts that — so ordering alone cannot produce an extension this package does not
     * generate. Chromium sends several that it does not: `signed_certificate_timestamp` (18),
     * `compress_certificate` (27), `session_ticket` (35), `application_settings` (17613) and ECH
     * (65037). Supplying them here is the only way to close that gap, and it is the caller's job to
     * encode them correctly — this package does not parse what it did not build.
     */
    extraExtensions?: Uint8Array<ArrayBufferLike>[] | undefined;
    /**
     * signature_algorithms to offer, in preference order.
     */
    sigSchemes?: number[] | undefined;
    /**
     * send GREASE (RFC 8701) reserved values in the cipher list,
     * the extension list (one at each end), supported_groups, supported_versions and key_share.
     * Default false, because curl does not GREASE — Chromium does. A number is a seed, which makes
     * the hello reproducible; `true` draws one from `deps.randomBytes`. A server that negotiates a
     * GREASE value is refused with a typed error naming it.
     */
    grease?: number | boolean | undefined;
    /**
     * ClientHello extension types, in the order to emit them.
     * JA3 and JA4 hash the extension list in WIRE ORDER, so this is most of what a fingerprinter
     * reads. Defaults to curl's order (`CURL_EXTENSION_ORDER`). Extensions not named keep their
     * natural position at the end; `pre_shared_key` is always last whatever is asked, because RFC
     * 8446 s4.2.11 defines the binder transcript as the hello truncated just before the binders.
     */
    extensionOrder?: number[] | "shuffle" | undefined;
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
    /**
     * offer this resumption PSK (TLS 1.3 only; requires 1.3 in
     * the offered versions). The server may decline, in which case the full handshake continues
     * on this same connection — there is no reconnect at any layer.
     */
    psk?: ResumptionOffer | undefined;
    /**
     * receive each NewSessionTicket
     * this connection yields, already reduced to a usable PSK per RFC 8446 s7.1. Without this the
     * tickets are read and discarded, exactly as before.
     */
    onSessionTicket?: ((ticket: CapturedTicket) => void) | undefined;
};
/**
 * A resumption PSK ready to offer, as produced by the ticket store from a CapturedTicket.
 * `obfuscatedTicketAge` is a closure, not a number, because the age must be current at the
 * moment each hello is BUILT — a HelloRetryRequest builds a second hello later — and because
 * clock policy belongs to the store, not to this layer (which otherwise never reads a clock).
 * `peer` rides along opaquely: it is whatever the original session's verifyPeer resolved with,
 * and a resumed session (which has no Certificate message to verify) reports it as its own —
 * sound only because the ticket store keys tickets by the full trust configuration.
 */
export type ResumptionOffer = {
    /**
     * the ticket
     */
    identity: Uint8Array;
    psk: Uint8Array;
    /**
     * the hash the PSK was minted under
     */
    hash: import("./keyschedule.js").ScheduleHash;
    /**
     * uint32 per RFC 8446 s4.2.11.1
     */
    obfuscatedTicketAge: () => number;
    peer?: object | undefined;
};
/**
 * What a NewSessionTicket becomes by the time a caller sees it: the wire fields that govern
 * offering (lifetime, age_add) plus the derived PSK and everything needed to check a future
 * selection against it. `maxEarlyDataSize` is recorded for honesty but never acted on: 0-RTT
 * is deliberately not implemented (see the driver's note).
 */
export type CapturedTicket = {
    identity: Uint8Array;
    psk: Uint8Array;
    hash: import("./keyschedule.js").ScheduleHash;
    cipherSuite: number;
    lifetimeSec: number;
    ageAdd: number;
    maxEarlyDataSize: number | null;
    alpnProtocol: string | null;
    peer: object;
};
/**
 * Injectable nondeterminism and crypto primitives the platform does not provide.
 *
 * `randomBytes` and `generateKeyPair` supply reproducibility (a recorded session replayed in an
 * offline test). `aead` and `kem` supply capabilities this runtime lacks entirely: ChaCha20 and
 * ML-KEM are absent from WebCrypto here, so an implementation must be injected before the suite or
 * group they back can be offered — a ClientHello being an offer a server may take.
 */
export type TlsDeps = {
    randomBytes?: ((n: number) => Uint8Array) | undefined;
    generateKeyPair?: ((algorithm: object, group: number) => Promise<CryptoKeyPair>) | undefined;
    /**
     * injected AEAD
     * implementations by name; `chacha20` gates and performs TLS_CHACHA20_POLY1305_SHA256
     */
    aead?: {
        chacha20?: import("./aead.js").AeadOptions["impl"];
    } | undefined;
    /**
     * injected KEM
     * implementations by name; `x25519mlkem768` gates and performs the X25519MLKEM768 hybrid group
     */
    kem?: {
        x25519mlkem768?: import("./hybrid.js").MlKem768;
    } | undefined;
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
    /**
     * TLS 1.3 only: the server accepted the offered resumption PSK,
     * so no certificate crossed the wire on THIS connection; the identity is the one validated
     * by the original handshake the ticket came from
     */
    resumed?: boolean | undefined;
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
