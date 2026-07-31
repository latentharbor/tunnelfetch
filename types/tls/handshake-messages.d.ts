/**
 * An ephemeral key share: the public half as sent in key_share, plus the private key the
 * eventual ServerHello selection will feed into deriveSharedSecret.
 * @typedef {object} KeyShare
 * @property {number} group
 * @property {Uint8Array} keyExchange raw public key, the exact bytes on the wire
 * @property {CryptoKey} privateKey non-extractable
 */
/**
 * Generate an ephemeral key share for one group.
 * `generateKeyPair` is injectable so a recorded handshake can be replayed with the exact private
 * key that produced it.
 *
 * @param {number} group
 * @param {import('./connect.js').TlsDeps} [deps]
 * @returns {Promise<KeyShare>}
 */
export function generateKeyShare(group: number, { generateKeyPair }?: import("./connect.js").TlsDeps): Promise<KeyShare>;
/**
 * ECDH/X25519 shared secret. The peer's key is imported in raw form, which is where a malformed
 * point is caught: WebCrypto rejects a point that is not on the curve, so we do not have to
 * implement that check ourselves — but a wrong LENGTH would be accepted by some implementations,
 * so it is checked here first.
 *
 * @param {number} group
 * @param {CryptoKey} privateKey our ephemeral private key for the group
 * @param {Uint8Array} peerKey the server's raw public key from its key_share
 * @returns {Promise<Uint8Array>} throws on any degenerate or malformed peer key
 */
export function deriveSharedSecret(group: number, privateKey: CryptoKey, peerKey: Uint8Array): Promise<Uint8Array>;
/**
 * @typedef {object} ClientHelloOptions
 * @property {string} hostname SNI, unless it is an IP literal (then no SNI is sent)
 * @property {Array<{ group: number, keyExchange: Uint8Array }>} keyShares public halves to
 *   offer; empty for a 1.2-only hello, whose wire form must not carry the extension at all
 * @property {Uint8Array} [random] fixed ClientHello.random, for reproducible handshakes
 * @property {Uint8Array} [legacySessionId] fixed legacy_session_id, likewise
 * @property {number[]} [ciphers] default: the union for the offered versions, 1.3 first
 * @property {number[]} [groups] supported_groups, default SUPPORTED_GROUPS
 * @property {number[]} [sigSchemes] default SUPPORTED_SIG_SCHEMES
 * @property {string[]} [alpn] default ['http/1.1']; empty array omits the extension
 * @property {number[]} [versions] default [TLS13, TLS12]
 * @property {Uint8Array[]} [extraExtensions] pre-encoded, sent verbatim (the HRR cookie)
 * @property {(n: number) => Uint8Array} [randomBytes] injectable randomness
 */
/**
 * The built hello plus everything later steps need to police the server's answer against what
 * was actually offered — negotiation checks must run against this record, never against the
 * defaults they might have come from.
 * @typedef {object} ClientHello
 * @property {Uint8Array} message framed handshake message, ready for the record layer
 * @property {Uint8Array} clientRandom
 * @property {Uint8Array} legacySessionId
 * @property {number[]} offeredCiphers
 * @property {number[]} offeredGroups
 * @property {number[]} offeredSigSchemes
 * @property {Set<number>} offeredExtensions extension types present in the hello
 * @property {string[]} offeredAlpn
 */
/**
 * Build a ClientHello. Returns the framed handshake message plus the metadata the rest of the
 * handshake needs to police the server's answer.
 *
 * @param {ClientHelloOptions} opts
 * @returns {ClientHello}
 */
export function buildClientHello({ hostname, keyShares, random, legacySessionId, ciphers, groups, sigSchemes, alpn, versions, extraExtensions, randomBytes, }: ClientHelloOptions): ClientHello;
/**
 * A parsed ServerHello. `isHelloRetryRequest` is decided by the random alone (RFC 8446 s4.1.3);
 * everything else is exactly what the wire carried, judged later by the negotiate* functions.
 * @typedef {object} ServerHello
 * @property {number} legacyVersion
 * @property {Uint8Array} random
 * @property {Uint8Array} legacySessionIdEcho
 * @property {number} cipherSuite
 * @property {Map<number, Uint8Array>} extensions
 * @property {boolean} isHelloRetryRequest
 */
/**
 * @param {Uint8Array} body
 * @returns {ServerHello} throws on malformed encoding or a compression method other than null
 */
export function parseServerHello(body: Uint8Array): ServerHello;
/**
 * Decide the negotiated version, and refuse every shape of downgrade.
 *
 * The subtle one is the sentinel check (RFC 8446 s4.1.3): a server that supports TLS 1.3 but was
 * pushed down to 1.2 by an attacker stripping our supported_versions plants a known value in the
 * last 8 bytes of its random. A 1.3-capable client that ignores it is exactly the client the
 * attack targets.
 *
 * @param {ServerHello} serverHello
 * @param {{ offeredVersions: number[] }} offer
 * @returns {number} the negotiated version; every downgrade shape throws instead
 */
export function negotiateVersion(serverHello: ServerHello, { offeredVersions }: {
    offeredVersions: number[];
}): number;
/**
 * @param {ServerHello} serverHello
 * @param {{ offeredCiphers: number[], version: number }} offer the negotiated version re-checks
 *   the suite's family, so a union offer cannot run a 1.3 suite under 1.2 or the reverse
 * @returns {{ suite: number, params: import('./constants.js').CipherParams }}
 */
export function negotiateCipher(serverHello: ServerHello, { offeredCiphers, version }: {
    offeredCiphers: number[];
    version: number;
}): {
    suite: number;
    params: import("./constants.js").CipherParams;
};
/**
 * RFC 8446 s4.1.3: the server must echo legacy_session_id verbatim. A mismatch means the
 * ServerHello does not belong to our ClientHello.
 * @param {ServerHello} serverHello
 * @param {Uint8Array} legacySessionId
 * @returns {void} throws TlsError on mismatch
 */
export function checkSessionIdEcho(serverHello: ServerHello, legacySessionId: Uint8Array): void;
/**
 * The server's chosen key share, validated against what we actually offered.
 * @param {ServerHello} serverHello
 * @param {KeyShare[]} keyShares the shares we generated for the hello
 * @returns {{ group: number, keyExchange: Uint8Array, privateKey: CryptoKey }} the server's
 *   group and public key, paired with OUR private key for it
 */
export function selectServerKeyShare(serverHello: ServerHello, keyShares: KeyShare[]): {
    group: number;
    keyExchange: Uint8Array;
    privateKey: CryptoKey;
};
/**
 * HelloRetryRequest: the server names one group and expects a fresh ClientHello.
 * @param {ServerHello} serverHello
 * @param {{ offeredGroups: number[] }} offer
 * @returns {{ group: number, cookie: Uint8Array | null }}
 */
export function parseHelloRetryRequest(serverHello: ServerHello, { offeredGroups }: {
    offeredGroups: number[];
}): {
    group: number;
    cookie: Uint8Array | null;
};
/**
 * TLS 1.3 Certificate (RFC 8446 s4.4.2): context, then entries carrying per-cert extensions.
 * @param {Uint8Array} body
 * @returns {Uint8Array[]} DER certificates in wire order, leaf first
 */
export function parseCertificate13(body: Uint8Array): Uint8Array[];
/**
 * TLS 1.2 Certificate (RFC 5246 s7.4.2): a bare list, no context and no per-cert extensions.
 * @param {Uint8Array} body
 * @returns {Uint8Array[]} DER certificates in wire order, leaf first
 */
export function parseCertificate12(body: Uint8Array): Uint8Array[];
/**
 * @param {Uint8Array} body
 * @returns {{ algorithm: number, signature: Uint8Array }}
 */
export function parseCertificateVerify(body: Uint8Array): {
    algorithm: number;
    signature: Uint8Array;
};
/**
 * RFC 8446 s4.4.3: 64 spaces, a context string, a zero byte, then the transcript hash.
 * @param {Uint8Array} transcriptHash
 * @param {boolean} [isServer]
 * @returns {Uint8Array}
 */
export function certificateVerifyContent(transcriptHash: Uint8Array, isServer?: boolean): Uint8Array;
/**
 * Verify a handshake signature with WebCrypto.
 * `spki` is the DER SubjectPublicKeyInfo lifted straight out of the leaf certificate, so the key
 * used to check the signature is provably the key the trust layer validated.
 *
 * @param {object} args
 * @param {number} args.scheme signature scheme id from the wire
 * @param {Uint8Array} args.spki DER SubjectPublicKeyInfo of the validated leaf
 * @param {Uint8Array} args.signature as received: DER for ECDSA, raw otherwise
 * @param {Uint8Array} args.content the exact bytes the signature must cover
 * @returns {Promise<true>} every failure throws; there is no false
 */
export function verifyHandshakeSignature({ scheme, spki, signature, content }: {
    scheme: number;
    spki: Uint8Array;
    signature: Uint8Array;
    content: Uint8Array;
}): Promise<true>;
/**
 * RFC 8422 s5.4. Only named-curve ECDHE is accepted: explicit curves are a decade-dead feature
 * and finite-field DHE would need bignum arithmetic WebCrypto does not expose.
 *
 * @param {Uint8Array} body
 * @returns {{ group: number, publicKey: Uint8Array, signatureAlgorithm: number,
 *   signature: Uint8Array, signedParams: Uint8Array }} `signedParams` is the exact byte range
 *   the server's signature covers (curve_type through the public key)
 */
export function parseServerKeyExchangeEcdhe(body: Uint8Array): {
    group: number;
    publicKey: Uint8Array;
    signatureAlgorithm: number;
    signature: Uint8Array;
    signedParams: Uint8Array;
};
/**
 * TLS 1.2 signs client_random || server_random || ServerECDHParams.
 * @param {Uint8Array} clientRandom
 * @param {Uint8Array} serverRandom
 * @param {Uint8Array} signedParams
 * @returns {Uint8Array}
 */
export function serverKeyExchangeContent(clientRandom: Uint8Array, serverRandom: Uint8Array, signedParams: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} publicKey
 * @returns {Uint8Array} framed ClientKeyExchange message
 */
export function buildClientKeyExchange(publicKey: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} verifyData
 * @returns {Uint8Array} framed Finished message
 */
export function buildFinished(verifyData: Uint8Array): Uint8Array;
/**
 * Compare a peer Finished against ours. Constant-time in intent: verify_data is derived from
 * secrets the peer must already know, so a timing leak is not a decryption oracle, but there is
 * no reason to leak the prefix length either.
 * @param {Uint8Array} received
 * @param {Uint8Array} expected
 * @returns {true} a mismatch throws; there is no false
 */
export function checkFinished(received: Uint8Array, expected: Uint8Array): true;
/**
 * The negotiated ALPN protocol, refusing anything we did not offer.
 * @param {Map<number, Uint8Array>} extensions
 * @param {string[]} offeredAlpn
 * @param {string} where
 * @returns {string | null} null when the server declined ALPN entirely
 */
export function checkAlpn(extensions: Map<number, Uint8Array>, offeredAlpn: string[], where: string): string | null;
export { GROUP_PARAMS };
/**
 * An ephemeral key share: the public half as sent in key_share, plus the private key the
 * eventual ServerHello selection will feed into deriveSharedSecret.
 */
export type KeyShare = {
    group: number;
    /**
     * raw public key, the exact bytes on the wire
     */
    keyExchange: Uint8Array;
    /**
     * non-extractable
     */
    privateKey: CryptoKey;
};
export type ClientHelloOptions = {
    /**
     * SNI, unless it is an IP literal (then no SNI is sent)
     */
    hostname: string;
    /**
     * public halves to
     * offer; empty for a 1.2-only hello, whose wire form must not carry the extension at all
     */
    keyShares: Array<{
        group: number;
        keyExchange: Uint8Array;
    }>;
    /**
     * fixed ClientHello.random, for reproducible handshakes
     */
    random?: Uint8Array<ArrayBufferLike> | undefined;
    /**
     * fixed legacy_session_id, likewise
     */
    legacySessionId?: Uint8Array<ArrayBufferLike> | undefined;
    /**
     * default: the union for the offered versions, 1.3 first
     */
    ciphers?: number[] | undefined;
    /**
     * supported_groups, default SUPPORTED_GROUPS
     */
    groups?: number[] | undefined;
    /**
     * default SUPPORTED_SIG_SCHEMES
     */
    sigSchemes?: number[] | undefined;
    /**
     * default ['http/1.1']; empty array omits the extension
     */
    alpn?: string[] | undefined;
    /**
     * default [TLS13, TLS12]
     */
    versions?: number[] | undefined;
    /**
     * pre-encoded, sent verbatim (the HRR cookie)
     */
    extraExtensions?: Uint8Array<ArrayBufferLike>[] | undefined;
    /**
     * injectable randomness
     */
    randomBytes?: ((n: number) => Uint8Array) | undefined;
};
/**
 * The built hello plus everything later steps need to police the server's answer against what
 * was actually offered — negotiation checks must run against this record, never against the
 * defaults they might have come from.
 */
export type ClientHello = {
    /**
     * framed handshake message, ready for the record layer
     */
    message: Uint8Array;
    clientRandom: Uint8Array;
    legacySessionId: Uint8Array;
    offeredCiphers: number[];
    offeredGroups: number[];
    offeredSigSchemes: number[];
    /**
     * extension types present in the hello
     */
    offeredExtensions: Set<number>;
    offeredAlpn: string[];
};
/**
 * A parsed ServerHello. `isHelloRetryRequest` is decided by the random alone (RFC 8446 s4.1.3);
 * everything else is exactly what the wire carried, judged later by the negotiate* functions.
 */
export type ServerHello = {
    legacyVersion: number;
    random: Uint8Array;
    legacySessionIdEcho: Uint8Array;
    cipherSuite: number;
    extensions: Map<number, Uint8Array>;
    isHelloRetryRequest: boolean;
};
import { GROUP_PARAMS } from './constants.js';
