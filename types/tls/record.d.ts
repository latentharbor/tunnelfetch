/**
 * A complete handshake message off the wire. `raw` includes the 4-byte header, which is the
 * form the transcript hash consumes.
 * @typedef {object} HandshakeMessage
 * @property {number} type
 * @property {Uint8Array} body
 * @property {Uint8Array} raw
 */
/**
 * Keys for one direction: a TLS 1.3 traffic `secret` (key and IV derived per RFC 8446 s7.3,
 * KeyUpdate rotation possible) or raw TLS 1.2 key_block slices (no forward rotation).
 * @typedef {{ cipher: number, secret: Uint8Array }
 *   | { cipher: number, key: Uint8Array, iv: Uint8Array }} DirectionKeys
 */
/**
 * @typedef {object} RecordLayerOptions
 * @property {number} [maxHandshakeMessage] per-message cap; certificate chains dominate sizing
 * @property {number} [maxKeyUpdates] received KeyUpdates before we call it a flood
 * @property {number} [shutdownGraceMs] how long a courtesy close_notify or fatal alert may
 *   block shutdown before being abandoned, default 2000; see _shutdown()
 * @property {null | ((type: number, length: number) => number)} [padding] extra zero bytes per
 *   record, TLS 1.3 only
 * @property {null | ((msg: HandshakeMessage) => void | Promise<void>)} [onPostHandshake]
 *   NewSessionTicket consumer; default is to discard
 */
export class RecordLayer {
    /**
     * @param {import('./connect.js').ByteDuplex} duplex ciphertext transport
     * @param {RecordLayerOptions} [opts]
     */
    constructor({ readable, writable }: import("./connect.js").ByteDuplex, opts?: RecordLayerOptions);
    _r: ByteReader;
    _w: ByteWriter;
    _maxHandshakeMessage: number;
    _maxKeyUpdates: number;
    _shutdownGraceMs: number;
    _padding: ((type: number, length: number) => number) | null;
    _onPostHandshake: ((msg: HandshakeMessage) => void | Promise<void>) | null;
    _version: number;
    /** @typedef {null | { aead: import('./aead.js').Aead, seq: bigint, cipher: number,
     *   hash: import('./keyschedule.js').ScheduleHash,
     *   secret: Uint8Array | null }} DirectionState */
    /** @type {DirectionState} */
    _send: {
        aead: import("./aead.js").Aead;
        seq: bigint;
        cipher: number;
        hash: import("./keyschedule.js").ScheduleHash;
        secret: Uint8Array | null;
    } | null;
    /** @type {DirectionState} */
    _recv: {
        aead: import("./aead.js").Aead;
        seq: bigint;
        cipher: number;
        hash: import("./keyschedule.js").ScheduleHash;
        secret: Uint8Array | null;
    } | null;
    /** Handshake reassembly. Chunk list, not one growing buffer, so a peer drip-feeding a
     * message in tiny records costs O(records), not O(records^2).
     * @type {Uint8Array[]} */
    _hsChunks: Uint8Array[];
    _hsLen: number;
    /** @type {{ type: number, len: number } | null} header of the message being assembled */
    _hsHeader: {
        type: number;
        len: number;
    } | null;
    _handshakeComplete: boolean;
    _closedByPeer: boolean;
    _closedLocally: boolean;
    /** @type {TlsError | null} first protocol error; sticky */
    _fatal: TlsError | null;
    _anyRecordWritten: boolean;
    _reading: boolean;
    /** All wire emission is funnelled through this chain. Two interleaved writers would
     * reorder — or worse, reuse — AEAD sequence numbers, and with GCM a single reused nonce
     * forfeits the key, so serialization here is a security control, not a convenience. */
    _writeChain: Promise<void>;
    _ignoredCcs: number;
    _ignoredAlerts: number;
    _emptyStreak: number;
    _keyUpdatesReceived: number;
    /**
     * Pin the negotiated version. Chooses CCS semantics (1.3: compatibility noise to ignore;
     * 1.2: a real key-change signal surfaced as `{ ccs: true }`), alert strictness, and AEAD
     * framing. Must happen before any keys are installed.
     * @param {number} version `TLS12` (0x0303) or `TLS13` (0x0304); anything else throws
     */
    setVersion(version: number): void;
    get version(): number;
    get handshakeComplete(): boolean;
    /** The handshake driver calls this after the Finished exchange. Gates CCS and KeyUpdate. */
    markHandshakeComplete(): void;
    /**
     * Install (or replace) the NewSessionTicket consumer after construction. Exists because the
     * consumer needs secrets that do not exist when the record layer is built — the resumption
     * master secret is derived from the transcript through the client Finished — so the driver
     * wires it in at handshake completion. An exception it throws surfaces on the read path and
     * fails the connection, which is the correct fate for a peer whose post-handshake messages do
     * not parse.
     * @param {null | ((msg: HandshakeMessage) => void | Promise<void>)} fn
     */
    setPostHandshake(fn: null | ((msg: HandshakeMessage) => void | Promise<void>)): void;
    /**
     * Install send-direction protection. Pass `secret` (a TLS 1.3 traffic secret; key and IV are
     * derived per RFC 8446 s7.3, and KeyUpdate rotation becomes possible) or raw `key`+`iv`
     * (TLS 1.2 key_block slices, which have no forward rotation). Sequence numbers reset.
     * @param {DirectionKeys} keys
     * @returns {Promise<void>}
     */
    setSendKeys({ cipher, secret, key, iv }: DirectionKeys): Promise<void>;
    /**
     * Install receive-direction protection. Refuses if a partially reassembled handshake
     * message is pending: RFC 8446 s5.1 forbids a handshake message from spanning a key change,
     * and enforcing it here — at the only point where the receive cipher can change — covers
     * both driver-installed keys and KeyUpdate rotation with a single check.
     * @param {DirectionKeys} keys
     * @returns {Promise<void>}
     */
    setReceiveKeys({ cipher, secret, key, iv }: DirectionKeys): Promise<void>;
    /**
     * @param {{ cipher: number, secret?: Uint8Array, key?: Uint8Array, iv?: Uint8Array }} keys
     * @returns {Promise<NonNullable<DirectionState>>}
     */
    _makeState({ cipher, secret, key, iv }: {
        cipher: number;
        secret?: Uint8Array;
        key?: Uint8Array;
        iv?: Uint8Array;
    }): Promise<NonNullable<DirectionState>>;
    /**
     * Next handshake message during the handshake phase.
     * Returns `{ type, body, raw }` (raw includes the 4-byte header, ready for the transcript),
     * `{ ccs: true }` in TLS 1.2 mode when the peer's change_cipher_spec arrives, or `null` if
     * the peer closed cleanly (which mid-handshake the driver should treat as failure).
     * @returns {Promise<HandshakeMessage | { ccs: true } | null>}
     */
    nextHandshakeMessage(): Promise<HandshakeMessage | {
        ccs: true;
    } | null>;
    /**
     * Next application data chunk, or null at clean close_notify EOF. Post-handshake handshake
     * messages (KeyUpdate, NewSessionTicket) are consumed transparently here.
     * @returns {Promise<Uint8Array | null>}
     */
    readAppData(): Promise<Uint8Array | null>;
    /**
     * @template T
     * @param {() => Promise<T>} fn
     * @returns {Promise<T>}
     */
    _guardedRead<T>(fn: () => Promise<T>): Promise<T>;
    /**
     * One protocol event: a complete handshake message, an app-data chunk, a 1.2 CCS, or close.
     * All the "ignore and keep reading" cases (compat CCS, warning alerts, empty app records)
     * loop in here, each behind a flood cap.
     * @returns {Promise<{ kind: 'close' } | { kind: 'ccs' } | { kind: 'data', bytes: Uint8Array }
     *   | { kind: 'handshake', msgType: number, body: Uint8Array, raw: Uint8Array }>}
     */
    _nextEvent(): Promise<{
        kind: "close";
    } | {
        kind: "ccs";
    } | {
        kind: "data";
        bytes: Uint8Array;
    } | {
        kind: "handshake";
        msgType: number;
        body: Uint8Array;
        raw: Uint8Array;
    }>;
    /**
     * Complete message off the reassembly buffer, if one is there.
     * @returns {{ kind: 'handshake', msgType: number, body: Uint8Array, raw: Uint8Array } | null}
     */
    _takeHandshakeMessage(): {
        kind: "handshake";
        msgType: number;
        body: Uint8Array;
        raw: Uint8Array;
    } | null;
    /**
     * Read one record off the wire and reduce it to (inner type, plaintext), or null once the
     * peer has said close_notify. Handles decryption, the plaintext/ciphertext legality rules,
     * and TLS 1.3 compatibility CCS.
     * @returns {Promise<{ type: number, data: Uint8Array } | null>}
     */
    _nextPlaintextRecord(): Promise<{
        type: number;
        data: Uint8Array;
    } | null>;
    /**
     * @param {Uint8Array} data
     * @returns {'close' | 'ignored'} or throws for fatal alerts
     */
    _handleAlert(data: Uint8Array): "close" | "ignored";
    /**
     * KeyUpdate and NewSessionTicket arriving under application keys.
     * @param {{ msgType: number, body: Uint8Array, raw: Uint8Array }} msg
     */
    _postHandshakeMessage({ msgType, body, raw }: {
        msgType: number;
        body: Uint8Array;
        raw: Uint8Array;
    }): Promise<void>;
    /**
     * Write one or more complete handshake messages, coalescing them into as few records as
     * possible (the ClientHello flight and the 1.2 client second flight benefit) and
     * fragmenting anything over 2^14.
     * @param {Uint8Array | Uint8Array[]} messages
     */
    writeHandshake(messages: Uint8Array | Uint8Array[]): Promise<void>;
    /**
     * Write application data, fragmented to the record size limit.
     * @param {Uint8Array} bytes
     * @returns {Promise<void>}
     */
    writeAppData(bytes: Uint8Array): Promise<void>;
    /** The one-byte compatibility (1.3) or key-change (1.2) CCS record. Always plaintext. */
    writeChangeCipherSpec(): Promise<void>;
    /**
     * Post-handshake KeyUpdate initiated by us: send under current keys, then rotate our send
     * chain. With `requestPeer` the peer must answer and rotate its own send keys too.
     * @param {{ requestPeer?: boolean }} [opts]
     * @returns {Promise<void>}
     */
    updateKeys({ requestPeer }?: {
        requestPeer?: boolean;
    }): Promise<void>;
    /**
     * @param {number} level `ALERT_LEVEL.warning` (1) or `ALERT_LEVEL.fatal` (2)
     * @param {number} desc alert description byte, per `ALERT_DESC`
     * @returns {Promise<void>}
     */
    sendAlert(level: number, desc: number): Promise<void>;
    /**
     * Clean shutdown: close_notify, then close the transport write side.
     * @returns {Promise<void>}
     */
    close(): Promise<void>;
    /**
     * Shutdown, bounded.
     *
     * The alert is a courtesy: a peer that has stopped reading will never see it, and its write can
     * therefore never complete once the transport's buffer fills. Awaiting that without a bound
     * hangs close() forever on the ordinary path, and hangs abort() on the failure path — where it
     * also swallows the error the caller was about to be given, turning a diagnosable failure into a
     * request that simply never returns. So the courtesy gets a deadline and is then abandoned.
     *
     * Alert and FIN are one chained task so a single deadline covers both; queueing them separately
     * would let a stalled alert consume one budget and the FIN another.
     * @param {number} level
     * @param {number} desc
     */
    _shutdown(level: number, desc: number): Promise<void>;
    /**
     * Abort: send a fatal alert naming why, then close. A peer left to time out on a dead
     * connection is an interop bug of ours, not a neutral choice.
     * @param {number} [desc] alert description byte, default internal_error
     * @returns {Promise<void>}
     */
    abort(desc?: number): Promise<void>;
    /**
     * Application-data face of the connection as a {readable, writable} pair, for stacking the
     * HTTP layer on top exactly like it would stack on a raw socket.
     * @returns {import('./connect.js').ByteDuplex}
     */
    plaintextDuplex(): import("./connect.js").ByteDuplex;
    _assertWritable(): void;
    /**
     * Serialize a wire-writing task behind every previously enqueued one.
     * @template T
     * @param {() => Promise<T>} fn
     * @returns {Promise<T>}
     */
    _enqueueWrite<T>(fn: () => Promise<T>): Promise<T>;
    /**
     * @param {number} type
     * @param {Uint8Array} bytes
     */
    _writeFragmented(type: number, bytes: Uint8Array): Promise<void>;
    /**
     * Encrypt-and-frame one fragment. Only ever runs inside the write chain.
     * @param {number} type
     * @param {Uint8Array} chunk
     */
    _emit(type: number, chunk: Uint8Array): Promise<void>;
    /**
     * @param {number} type
     * @param {Uint8Array} body
     */
    _writeRecord(type: number, body: Uint8Array): Promise<void>;
    /** Derive application_traffic_secret_N+1 and swap the send state. Runs inside the chain. */
    _rotateSend(): Promise<void>;
    /**
     * Record the first fatal error, tell the peer (best-effort), throw. Never returns.
     * @param {string} code
     * @param {string} message
     * @param {Record<string, unknown>} [detail]
     * @param {number} [alertDesc]
     * @returns {never}
     */
    _fail(code: string, message: string, detail?: Record<string, unknown>, alertDesc?: number): never;
    /**
     * Fire-and-forget: awaiting a write here could park the failure path behind transport
     * backpressure, and the error must reach our caller no matter what the peer does. The
     * write chain still orders it before the transport close.
     * @param {number} desc
     */
    _sendAlertBestEffort(desc: number): void;
}
/**
 * A complete handshake message off the wire. `raw` includes the 4-byte header, which is the
 * form the transcript hash consumes.
 */
export type HandshakeMessage = {
    type: number;
    body: Uint8Array;
    raw: Uint8Array;
};
/**
 * Keys for one direction: a TLS 1.3 traffic `secret` (key and IV derived per RFC 8446 s7.3,
 * KeyUpdate rotation possible) or raw TLS 1.2 key_block slices (no forward rotation).
 */
export type DirectionKeys = {
    cipher: number;
    secret: Uint8Array;
} | {
    cipher: number;
    key: Uint8Array;
    iv: Uint8Array;
};
export type RecordLayerOptions = {
    /**
     * per-message cap; certificate chains dominate sizing
     */
    maxHandshakeMessage?: number | undefined;
    /**
     * received KeyUpdates before we call it a flood
     */
    maxKeyUpdates?: number | undefined;
    /**
     * how long a courtesy close_notify or fatal alert may
     * block shutdown before being abandoned, default 2000; see _shutdown()
     */
    shutdownGraceMs?: number | undefined;
    /**
     * extra zero bytes per
     * record, TLS 1.3 only
     */
    padding?: ((type: number, length: number) => number) | null | undefined;
    /**
     * NewSessionTicket consumer; default is to discard
     */
    onPostHandshake?: ((msg: HandshakeMessage) => void | Promise<void>) | null | undefined;
};
import { ByteReader } from '../util/bytes.js';
import { ByteWriter } from '../util/bytes.js';
import { TlsError } from '../errors.js';
