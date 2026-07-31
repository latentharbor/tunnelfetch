/**
 * The only hashes reachable through this schedule; see the module comment for why the type
 * refuses the rest of WebCrypto's registry.
 * @typedef {'SHA-256' | 'SHA-384'} ScheduleHash
 */
/**
 * @param {ScheduleHash} hash
 * @returns {number} digest length in bytes; throws for any other hash name
 */
export function hashLength(hash: ScheduleHash): number;
/**
 * HMAC-Hash(key, data) for a single message. For repeated MACs under one key, import once with
 * importHmacKey and call crypto.subtle.sign directly instead.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export function hmac(hash: ScheduleHash, keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array>;
/**
 * HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM). RFC 5869 s2.2.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} salt
 * @param {Uint8Array} ikm
 * @returns {Promise<Uint8Array>}
 */
export function hkdfExtract(hash: ScheduleHash, salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>;
/**
 * HKDF-Expand(PRK, info, L). RFC 5869 s2.3: T(i) = HMAC(PRK, T(i-1) || info || i), i in 1..N.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} prk
 * @param {Uint8Array} info
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export function hkdfExpand(hash: ScheduleHash, prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>;
/**
 * The HkdfLabel struct from RFC 8446 s7.1, exported separately so the tests can compare our
 * encoding byte-for-byte against the `info` fields printed in the RFC 8448 traces:
 *
 *   struct {
 *     uint16 length;
 *     opaque label<7..255>;   // "tls13 " + Label
 *     opaque context<0..255>;
 *   } HkdfLabel;
 *
 * @param {string} label label WITHOUT the "tls13 " prefix
 * @param {Uint8Array} context
 * @param {number} length
 * @returns {Uint8Array}
 */
export function hkdfLabel(label: string, context: Uint8Array, length: number): Uint8Array;
/**
 * HKDF-Expand-Label(Secret, Label, Context, Length). RFC 8446 s7.1.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} secret
 * @param {string} label
 * @param {Uint8Array} context
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export function hkdfExpandLabel(hash: ScheduleHash, secret: Uint8Array, label: string, context: Uint8Array, length: number): Promise<Uint8Array>;
/**
 * Derive-Secret(Secret, Label, Messages) — the transcript is passed already hashed.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} secret
 * @param {string} label
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export function deriveSecret(hash: ScheduleHash, secret: Uint8Array, label: string, transcriptHash: Uint8Array): Promise<Uint8Array>;
/**
 * @param {ScheduleHash} hash
 * @returns {Promise<Uint8Array>}
 */
export function emptyHash(hash: ScheduleHash): Promise<Uint8Array>;
/**
 * Early Secret = HKDF-Extract(salt: 0, IKM: PSK or zeros).
 * @param {ScheduleHash} hash
 * @param {Uint8Array | null} [psk]
 * @returns {Promise<Uint8Array>}
 */
export function earlySecret(hash: ScheduleHash, psk?: Uint8Array | null): Promise<Uint8Array>;
/**
 * Handshake Secret = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} early
 * @param {Uint8Array} ecdheShared
 * @returns {Promise<Uint8Array>}
 */
export function deriveHandshakeSecret(hash: ScheduleHash, early: Uint8Array, ecdheShared: Uint8Array): Promise<Uint8Array>;
/**
 * Master Secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} handshakeSecret
 * @returns {Promise<Uint8Array>}
 */
export function deriveMasterSecret(hash: ScheduleHash, handshakeSecret: Uint8Array): Promise<Uint8Array>;
/**
 * {client,server}_handshake_traffic_secret. Transcript: ClientHello..ServerHello.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} handshakeSecret
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<{ client: Uint8Array, server: Uint8Array }>}
 */
export function handshakeTrafficSecrets(hash: ScheduleHash, handshakeSecret: Uint8Array, transcriptHash: Uint8Array): Promise<{
    client: Uint8Array;
    server: Uint8Array;
}>;
/**
 * {client,server}_application_traffic_secret_0 and (unless suppressed) exporter_master_secret.
 *
 * `exporter` defaults on so the RFC 8448 vectors and any exporter user get the full set, but the
 * handshake driver passes false: this package exposes no TLS-exporter interface, so deriving
 * exporter_master_secret on every connection is one HKDF-Expand-Label of provably dead work on
 * the hot path. Suppressing it there removes that work without changing any observable behaviour.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} masterSecret
 * @param {Uint8Array} transcriptHash
 * @param {{ exporter?: boolean }} [opts]
 * @returns {Promise<{ client: Uint8Array, server: Uint8Array, exporterMaster?: Uint8Array }>}
 */
export function applicationTrafficSecrets(hash: ScheduleHash, masterSecret: Uint8Array, transcriptHash: Uint8Array, { exporter }?: {
    exporter?: boolean;
}): Promise<{
    client: Uint8Array;
    server: Uint8Array;
    exporterMaster?: Uint8Array;
}>;
/**
 * resumption_master_secret. Transcript: ClientHello..client Finished.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} masterSecret
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export function resumptionMasterSecret(hash: ScheduleHash, masterSecret: Uint8Array, transcriptHash: Uint8Array): Promise<Uint8Array>;
/**
 * The PSK a NewSessionTicket names: HKDF-Expand-Label(res master, "resumption", nonce).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} resumptionMaster
 * @param {Uint8Array} ticketNonce
 * @returns {Promise<Uint8Array>}
 */
export function resumptionPsk(hash: ScheduleHash, resumptionMaster: Uint8Array, ticketNonce: Uint8Array): Promise<Uint8Array>;
/**
 * binder_key = Derive-Secret(Early Secret, "res binder", "") — RFC 8446 s7.1, the resumption
 * variant. The "ext binder" sibling for externally provisioned PSKs is deliberately absent:
 * this package mints PSKs only from NewSessionTicket, so an external-PSK binder key would be
 * dead code with a security label on it. The binder value itself is finishedVerifyData over
 * this key (RFC 8446 s4.2.11.2: "the PskBinderEntry is computed in the same way as the
 * Finished message but with the BaseKey being the binder_key").
 * @param {ScheduleHash} hash
 * @param {Uint8Array} early the Early Secret extracted from the PSK being offered
 * @returns {Promise<Uint8Array>}
 */
export function resumptionBinderKey(hash: ScheduleHash, early: Uint8Array): Promise<Uint8Array>;
/**
 * finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length). RFC 8446 s4.4.4.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @returns {Promise<Uint8Array>}
 */
export function finishedKey(hash: ScheduleHash, trafficSecret: Uint8Array): Promise<Uint8Array>;
/**
 * verify_data = HMAC(finished_key, Transcript-Hash).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export function finishedVerifyData(hash: ScheduleHash, trafficSecret: Uint8Array, transcriptHash: Uint8Array): Promise<Uint8Array>;
/**
 * [sender]_write_key and [sender]_write_iv from a traffic secret. RFC 8446 s7.3.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @param {number} keyLen
 * @param {number} ivLen
 * @returns {Promise<{ key: Uint8Array, iv: Uint8Array }>}
 */
export function trafficKeys(hash: ScheduleHash, trafficSecret: Uint8Array, keyLen: number, ivLen: number): Promise<{
    key: Uint8Array;
    iv: Uint8Array;
}>;
/**
 * application_traffic_secret_N+1 for KeyUpdate. RFC 8446 s7.2.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @returns {Promise<Uint8Array>}
 */
export function nextTrafficSecret(hash: ScheduleHash, trafficSecret: Uint8Array): Promise<Uint8Array>;
/**
 * PRF(secret, label, seed) = P_<hash>(secret, label + seed), where
 * P_hash(secret, seed) = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
 * with A(0) = seed, A(i) = HMAC(secret, A(i-1)).
 *
 * TLS 1.2 replaced the 1.1 MD5/SHA-1 split PRF with a single suite-selected hash, which for
 * every suite in constants.js is SHA-256 or SHA-384.
 *
 * @param {ScheduleHash} hash
 * @param {Uint8Array} secret
 * @param {string} label ASCII label, e.g. 'master secret'
 * @param {Uint8Array} seed
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export function prf12(hash: ScheduleHash, secret: Uint8Array, label: string, seed: Uint8Array, length: number): Promise<Uint8Array>;
/**
 * master_secret = PRF(pre_master, "master secret", client_random + server_random)[0..47].
 * @param {ScheduleHash} hash
 * @param {Uint8Array} preMaster
 * @param {Uint8Array} clientRandom
 * @param {Uint8Array} serverRandom
 * @returns {Promise<Uint8Array>}
 */
export function masterSecret12(hash: ScheduleHash, preMaster: Uint8Array, clientRandom: Uint8Array, serverRandom: Uint8Array): Promise<Uint8Array>;
/**
 * RFC 7627 extended master secret: the seed is the session hash (transcript through
 * ClientKeyExchange) instead of the two randoms, which binds the master secret to the full
 * handshake and kills the triple-handshake attack. This is the variant the handshake layer
 * must offer and prefer; a server that refuses the extension still gets masterSecret12, but
 * that acceptance is deliberately flagged by the handshake layer as a weaker session.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} preMaster
 * @param {Uint8Array} sessionHash
 * @returns {Promise<Uint8Array>}
 */
export function extendedMasterSecret12(hash: ScheduleHash, preMaster: Uint8Array, sessionHash: Uint8Array): Promise<Uint8Array>;
/**
 * key_block = PRF(master, "key expansion", server_random + client_random). RFC 5246 s6.3.
 * Note the randoms swap order relative to the master secret derivation — that asymmetry is in
 * the RFC, and the tests pin it. AEAD suites have no MAC keys (macLen 0), so the block is
 * client_write_key + server_write_key + client_write_IV + server_write_IV, where the "IV" is
 * the 4-byte implicit GCM salt of RFC 5288.
 *
 * @param {ScheduleHash} hash
 * @param {Uint8Array} master
 * @param {Uint8Array} clientRandom
 * @param {Uint8Array} serverRandom
 * @param {{ keyLen: number, fixedIvLen: number, macLen?: number }} lens
 * @returns {Promise<{ clientWriteKey: Uint8Array, serverWriteKey: Uint8Array,
 *   clientWriteIv: Uint8Array, serverWriteIv: Uint8Array,
 *   clientWriteMacKey?: Uint8Array, serverWriteMacKey?: Uint8Array }>} MAC keys present only
 *   when macLen > 0, which no AEAD suite ever passes
 */
export function keyBlock12(hash: ScheduleHash, master: Uint8Array, clientRandom: Uint8Array, serverRandom: Uint8Array, lens: {
    keyLen: number;
    fixedIvLen: number;
    macLen?: number;
}): Promise<{
    clientWriteKey: Uint8Array;
    serverWriteKey: Uint8Array;
    clientWriteIv: Uint8Array;
    serverWriteIv: Uint8Array;
    clientWriteMacKey?: Uint8Array;
    serverWriteMacKey?: Uint8Array;
}>;
/**
 * verify_data = PRF(master, "client finished" | "server finished", Hash(messages))[0..11].
 * 12 bytes for every suite this package negotiates (RFC 5246 s7.4.9).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} master
 * @param {'client finished' | 'server finished'} label
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export function verifyData12(hash: ScheduleHash, master: Uint8Array, label: "client finished" | "server finished", transcriptHash: Uint8Array): Promise<Uint8Array>;
/**
 * The only hashes reachable through this schedule; see the module comment for why the type
 * refuses the rest of WebCrypto's registry.
 */
export type ScheduleHash = "SHA-256" | "SHA-384";
