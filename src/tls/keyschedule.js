// The TLS key schedule: HKDF (RFC 5869), the TLS 1.3 schedule (RFC 8446 s7.1), and the
// TLS 1.2 PRF (RFC 5246 s5, RFC 7627).
//
// Everything here runs on WebCrypto (`crypto.subtle`) and nothing else, because this package
// must run where `node:crypto` does not exist. WebCrypto does ship an "HKDF" algorithm, but it
// is deliberately not used: it fuses Extract and Expand into one deriveBits call and never
// reveals the intermediate PRK, while the TLS 1.3 schedule threads that PRK through the next
// Extract as an independent secret (early -> handshake -> master). So Extract and Expand are
// implemented from their RFC 5869 definitions over HMAC, and verified against the RFC 5869
// appendix-A vectors plus the complete RFC 8448 section 3 trace.
//
// Only SHA-256 and SHA-384 are accepted, because those are the only hashes any negotiable
// suite in constants.js uses. SHA-1 exists in WebCrypto but is not reachable through here.

import { TlsError, codes } from '../errors.js';
import { concat, u8, u16, utf8 } from '../util/bytes.js';

const EMPTY = new Uint8Array(0);

/** Digest lengths for the only hashes any negotiable cipher suite selects. */
const HASH_PARAMS = {
  'SHA-256': { len: 32 },
  'SHA-384': { len: 48 },
};

/**
 * The only hashes reachable through this schedule; see the module comment for why the type
 * refuses the rest of WebCrypto's registry.
 * @typedef {'SHA-256' | 'SHA-384'} ScheduleHash
 */

/**
 * @param {ScheduleHash} hash
 * @returns {number} digest length in bytes; throws for any other hash name
 */
export function hashLength(hash) {
  const p = HASH_PARAMS[hash];
  if (!p) {
    throw new TlsError(codes.CONFIG_INVALID, `hash ${JSON.stringify(hash)} is not one of ` +
      `SHA-256/SHA-384; no negotiable cipher suite uses it`, { hash });
  }
  return p.len;
}

const zeros = (n) => new Uint8Array(n);

/**
 * Import a raw HMAC key. The WebCrypto spec forbids importing a zero-length HMAC key, but HMAC
 * itself zero-pads the key to the block size, so an empty key and a key of HashLen zero bytes
 * produce the identical MAC. RFC 5869 defines the default salt as HashLen zeros for the same
 * reason, so the substitution is exact, not an approximation.
 *
 * Separated from the sign step so a caller that MACs many messages under one key — HKDF-Expand
 * and the TLS 1.2 PRF both iterate HMAC with a fixed key — imports the key once rather than once
 * per block. Measured on the edge, importKey is ~4µs and sign ~3µs, so hoisting it roughly halves
 * per-block cost in those loops.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} keyBytes
 * @returns {Promise<CryptoKey>}
 */
async function importHmacKey(hash, keyBytes) {
  const raw = keyBytes.byteLength === 0 ? zeros(hashLength(hash)) : keyBytes;
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash }, false, ['sign']);
}

/**
 * HMAC-Hash(key, data) for a single message. For repeated MACs under one key, import once with
 * importHmacKey and call crypto.subtle.sign directly instead.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} data
 * @returns {Promise<Uint8Array>}
 */
export async function hmac(hash, keyBytes, data) {
  const key = await importHmacKey(hash, keyBytes);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

/**
 * HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM). RFC 5869 s2.2.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} salt
 * @param {Uint8Array} ikm
 * @returns {Promise<Uint8Array>}
 */
export async function hkdfExtract(hash, salt, ikm) {
  return hmac(hash, salt, ikm);
}

/**
 * HKDF-Expand(PRK, info, L). RFC 5869 s2.3: T(i) = HMAC(PRK, T(i-1) || info || i), i in 1..N.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} prk
 * @param {Uint8Array} info
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export async function hkdfExpand(hash, prk, info, length) {
  const len = hashLength(hash);
  const n = Math.ceil(length / len);
  if (!Number.isInteger(length) || length < 1 || n > 255) {
    throw new TlsError(codes.CONFIG_INVALID, `HKDF-Expand length ${length} outside 1..${255 * len}`,
      { length });
  }
  // One import for every block T(1..n): the PRK is fixed across the whole expansion.
  const key = await importHmacKey(hash, prk);
  const out = new Uint8Array(length);
  let t = EMPTY;
  for (let i = 1, o = 0; i <= n; i++, o += len) {
    t = new Uint8Array(await crypto.subtle.sign('HMAC', key, concat([t, info, u8(i)])));
    out.set(t.subarray(0, Math.min(len, length - o)), o);
  }
  return out;
}

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
export function hkdfLabel(label, context, length) {
  const full = utf8('tls13 ' + label);
  if (full.byteLength < 7 || full.byteLength > 255) {
    throw new TlsError(codes.CONFIG_INVALID, `HkdfLabel label is ${full.byteLength} bytes, ` +
      'outside 7..255', { label });
  }
  if (context.byteLength > 255) {
    throw new TlsError(codes.CONFIG_INVALID, `HkdfLabel context is ${context.byteLength} bytes, ` +
      'over 255', { contextLength: context.byteLength });
  }
  if (length < 1 || length > 0xffff) {
    throw new TlsError(codes.CONFIG_INVALID, `HkdfLabel output length ${length} outside 1..65535`,
      { length });
  }
  return concat([u16(length), u8(full.byteLength), full, u8(context.byteLength), context]);
}

/**
 * HKDF-Expand-Label(Secret, Label, Context, Length). RFC 8446 s7.1.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} secret
 * @param {string} label
 * @param {Uint8Array} context
 * @param {number} length
 * @returns {Promise<Uint8Array>}
 */
export async function hkdfExpandLabel(hash, secret, label, context, length) {
  return hkdfExpand(hash, secret, hkdfLabel(label, context, length), length);
}

/**
 * Derive-Secret(Secret, Label, Messages) — the transcript is passed already hashed.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} secret
 * @param {string} label
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export async function deriveSecret(hash, secret, label, transcriptHash) {
  return hkdfExpandLabel(hash, secret, label, transcriptHash, hashLength(hash));
}

/** Hash of the empty string, used by the two "derived" steps. Cached: it is a constant. */
const emptyHashCache = new Map();
/**
 * @param {ScheduleHash} hash
 * @returns {Promise<Uint8Array>}
 */
export async function emptyHash(hash) {
  hashLength(hash);
  let d = emptyHashCache.get(hash);
  if (!d) {
    d = new Uint8Array(await crypto.subtle.digest(hash, EMPTY));
    emptyHashCache.set(hash, d);
  }
  return d;
}

// ---------------------------------------------------------------- TLS 1.3 schedule (s7.1)
//
//             0
//             |
//             v
//   PSK ->  HKDF-Extract = Early Secret
//             |
//             +--> Derive-Secret(., "derived", "")
//             v
//   ECDHE -> HKDF-Extract = Handshake Secret
//             +--> "c hs traffic" / "s hs traffic" (transcript: ClientHello..ServerHello)
//             +--> Derive-Secret(., "derived", "")
//             v
//   0    -> HKDF-Extract = Master Secret
//             +--> "c ap traffic" / "s ap traffic" / "exp master"
//                    (transcript: ClientHello..server Finished)
//             +--> "res master" (transcript: ClientHello..client Finished)

/**
 * Early Secret = HKDF-Extract(salt: 0, IKM: PSK or zeros).
 * @param {ScheduleHash} hash
 * @param {Uint8Array | null} [psk]
 * @returns {Promise<Uint8Array>}
 */
export async function earlySecret(hash, psk) {
  return hkdfExtract(hash, EMPTY, psk ?? zeros(hashLength(hash)));
}

/**
 * Handshake Secret = HKDF-Extract(Derive-Secret(early, "derived", ""), ECDHE).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} early
 * @param {Uint8Array} ecdheShared
 * @returns {Promise<Uint8Array>}
 */
export async function deriveHandshakeSecret(hash, early, ecdheShared) {
  const derived = await deriveSecret(hash, early, 'derived', await emptyHash(hash));
  return hkdfExtract(hash, derived, ecdheShared);
}

/**
 * Master Secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} handshakeSecret
 * @returns {Promise<Uint8Array>}
 */
export async function deriveMasterSecret(hash, handshakeSecret) {
  const derived = await deriveSecret(hash, handshakeSecret, 'derived', await emptyHash(hash));
  return hkdfExtract(hash, derived, zeros(hashLength(hash)));
}

/**
 * {client,server}_handshake_traffic_secret. Transcript: ClientHello..ServerHello.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} handshakeSecret
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<{ client: Uint8Array, server: Uint8Array }>}
 */
export async function handshakeTrafficSecrets(hash, handshakeSecret, transcriptHash) {
  return {
    client: await deriveSecret(hash, handshakeSecret, 'c hs traffic', transcriptHash),
    server: await deriveSecret(hash, handshakeSecret, 's hs traffic', transcriptHash),
  };
}

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
export async function applicationTrafficSecrets(hash, masterSecret, transcriptHash, { exporter = true } = {}) {
  const out = {
    client: await deriveSecret(hash, masterSecret, 'c ap traffic', transcriptHash),
    server: await deriveSecret(hash, masterSecret, 's ap traffic', transcriptHash),
  };
  if (exporter) out.exporterMaster = await deriveSecret(hash, masterSecret, 'exp master', transcriptHash);
  return out;
}

/**
 * resumption_master_secret. Transcript: ClientHello..client Finished.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} masterSecret
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export async function resumptionMasterSecret(hash, masterSecret, transcriptHash) {
  return deriveSecret(hash, masterSecret, 'res master', transcriptHash);
}

/**
 * The PSK a NewSessionTicket names: HKDF-Expand-Label(res master, "resumption", nonce).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} resumptionMaster
 * @param {Uint8Array} ticketNonce
 * @returns {Promise<Uint8Array>}
 */
export async function resumptionPsk(hash, resumptionMaster, ticketNonce) {
  return hkdfExpandLabel(hash, resumptionMaster, 'resumption', ticketNonce, hashLength(hash));
}

/**
 * finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length). RFC 8446 s4.4.4.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @returns {Promise<Uint8Array>}
 */
export async function finishedKey(hash, trafficSecret) {
  return hkdfExpandLabel(hash, trafficSecret, 'finished', EMPTY, hashLength(hash));
}

/**
 * verify_data = HMAC(finished_key, Transcript-Hash).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export async function finishedVerifyData(hash, trafficSecret, transcriptHash) {
  return hmac(hash, await finishedKey(hash, trafficSecret), transcriptHash);
}

/**
 * [sender]_write_key and [sender]_write_iv from a traffic secret. RFC 8446 s7.3.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @param {number} keyLen
 * @param {number} ivLen
 * @returns {Promise<{ key: Uint8Array, iv: Uint8Array }>}
 */
export async function trafficKeys(hash, trafficSecret, keyLen, ivLen) {
  return {
    key: await hkdfExpandLabel(hash, trafficSecret, 'key', EMPTY, keyLen),
    iv: await hkdfExpandLabel(hash, trafficSecret, 'iv', EMPTY, ivLen),
  };
}

/**
 * application_traffic_secret_N+1 for KeyUpdate. RFC 8446 s7.2.
 * @param {ScheduleHash} hash
 * @param {Uint8Array} trafficSecret
 * @returns {Promise<Uint8Array>}
 */
export async function nextTrafficSecret(hash, trafficSecret) {
  return hkdfExpandLabel(hash, trafficSecret, 'traffic upd', EMPTY, hashLength(hash));
}

// ---------------------------------------------------------------- TLS 1.2 PRF (RFC 5246 s5)

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
export async function prf12(hash, secret, label, seed, length) {
  if (!Number.isInteger(length) || length < 1) {
    throw new TlsError(codes.CONFIG_INVALID, `PRF length ${length} is not a positive integer`,
      { length });
  }
  const labelSeed = concat([utf8(label), seed]);
  // One import for the whole P_hash iteration: the secret is the HMAC key throughout.
  const key = await importHmacKey(hash, secret);
  const mac = async (data) => new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  const out = new Uint8Array(length);
  let a = labelSeed;
  for (let o = 0; o < length; o += hashLength(hash)) {
    a = await mac(a);
    const t = await mac(concat([a, labelSeed]));
    out.set(t.subarray(0, Math.min(t.byteLength, length - o)), o);
  }
  return out;
}

/**
 * master_secret = PRF(pre_master, "master secret", client_random + server_random)[0..47].
 * @param {ScheduleHash} hash
 * @param {Uint8Array} preMaster
 * @param {Uint8Array} clientRandom
 * @param {Uint8Array} serverRandom
 * @returns {Promise<Uint8Array>}
 */
export async function masterSecret12(hash, preMaster, clientRandom, serverRandom) {
  return prf12(hash, preMaster, 'master secret', concat([clientRandom, serverRandom]), 48);
}

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
export async function extendedMasterSecret12(hash, preMaster, sessionHash) {
  return prf12(hash, preMaster, 'extended master secret', sessionHash, 48);
}

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
export async function keyBlock12(hash, master, clientRandom, serverRandom, lens) {
  const { keyLen, fixedIvLen, macLen = 0 } = lens;
  const need = 2 * macLen + 2 * keyLen + 2 * fixedIvLen;
  const block = await prf12(hash, master, 'key expansion', concat([serverRandom, clientRandom]),
    need);
  let o = 0;
  const take = (n) => block.subarray(o, (o += n));
  const clientWriteMacKey = take(macLen);
  const serverWriteMacKey = take(macLen);
  const out = {
    clientWriteKey: take(keyLen),
    serverWriteKey: take(keyLen),
    clientWriteIv: take(fixedIvLen),
    serverWriteIv: take(fixedIvLen),
  };
  if (macLen > 0) Object.assign(out, { clientWriteMacKey, serverWriteMacKey });
  return out;
}

/**
 * verify_data = PRF(master, "client finished" | "server finished", Hash(messages))[0..11].
 * 12 bytes for every suite this package negotiates (RFC 5246 s7.4.9).
 * @param {ScheduleHash} hash
 * @param {Uint8Array} master
 * @param {'client finished' | 'server finished'} label
 * @param {Uint8Array} transcriptHash
 * @returns {Promise<Uint8Array>}
 */
export async function verifyData12(hash, master, label, transcriptHash) {
  if (label !== 'client finished' && label !== 'server finished') {
    throw new TlsError(codes.CONFIG_INVALID, `verify_data label ${JSON.stringify(label)} is not ` +
      "'client finished' or 'server finished'", { label });
  }
  return prf12(hash, master, label, transcriptHash, 12);
}
