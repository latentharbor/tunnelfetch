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
 * key that produced it. X25519MLKEM768 dispatches to hybrid.js, using the injected ML-KEM
 * implementation from `deps.kem`.
 *
 * @param {number} group
 * @param {import('./connect.js').TlsDeps} [deps]
 * @returns {Promise<KeyShare>}
 */
export function generateKeyShare(group: number, deps?: import("./connect.js").TlsDeps): Promise<KeyShare>;
/**
 * ECDH/X25519 shared secret. The peer's key is imported in raw form, which is where a malformed
 * point is caught: WebCrypto rejects a point that is not on the curve, so we do not have to
 * implement that check ourselves — but a wrong LENGTH would be accepted by some implementations,
 * so it is checked here first.
 *
 * @param {number} group
 * @param {CryptoKey | import('./hybrid.js').HybridPrivate} privateKey our ephemeral private key
 *   for the group (a compound value for the ML-KEM hybrid)
 * @param {Uint8Array} peerKey the server's raw public key from its key_share
 * @param {import('./connect.js').TlsDeps} [deps] carries the injected ML-KEM implementation the
 *   hybrid group needs; unused by the classical groups
 * @returns {Promise<Uint8Array>} throws on any degenerate or malformed peer key
 */
export function deriveSharedSecret(group: number, privateKey: CryptoKey | import("./hybrid.js").HybridPrivate, peerKey: Uint8Array, deps?: import("./connect.js").TlsDeps): Promise<Uint8Array>;
export function buildClientHello({ hostname, keyShares, random, legacySessionId, ciphers, groups, sigSchemes, alpn, versions, extensionOrder, extraExtensions, psk, grease, randomBytes, }: {
    hostname: any;
    keyShares: any;
    random: any;
    legacySessionId: any;
    ciphers: any;
    groups?: number[] | undefined;
    sigSchemes?: number[] | undefined;
    alpn?: string[] | undefined;
    versions?: number[] | undefined;
    extensionOrder?: readonly number[] | undefined;
    extraExtensions?: never[] | undefined;
    psk?: null | undefined;
    grease?: boolean | undefined;
    randomBytes?: ((n: any) => Uint8Array<any>) | undefined;
}): {
    message: Uint8Array<ArrayBufferLike>;
    clientRandom: any;
    legacySessionId: any;
    offeredCiphers: any;
    offeredGroups: number[];
    offeredSigSchemes: number[];
    offeredExtensions: Set<any>;
    offeredAlpn: string[];
};
/**
 * Patch the real binder over the placeholder `buildClientHello` emitted. Separate from the
 * builder because the binder is derived FROM the built message (truncated), so there is no
 * ordering in which one function could do both.
 * @param {ClientHello} hello a hello built with a psk offer
 * @param {Uint8Array} binder
 */
export function setPskBinder(hello: ClientHello, binder: Uint8Array): void;
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
 * NewSessionTicket (RFC 8446 s4.6.1), the post-handshake message a resumption PSK is minted
 * from. Strict on structure — a truncated field, trailing bytes, or a zero-length ticket ends
 * the connection, because a peer whose post-handshake messages do not parse cannot be trusted
 * to frame the application data either — but faithful to s4.6.1 on extensions: early_data is
 * validated in shape and its value RECORDED but never acted on (0-RTT is deliberately not
 * implemented; see the driver), and unrecognized extensions are ignored, which s4.6.1 makes
 * mandatory ("Clients MUST ignore unrecognized extensions").
 *
 * Lifetime semantics (zero means discard, 604800 s is the cap a client may honour) are POLICY,
 * applied by the ticket store; this function reports what the wire said.
 *
 * @param {Uint8Array} body
 * @returns {{ lifetimeSec: number, ageAdd: number, nonce: Uint8Array, ticket: Uint8Array,
 *   maxEarlyDataSize: number | null }}
 */
export function parseNewSessionTicket(body: Uint8Array): {
    lifetimeSec: number;
    ageAdd: number;
    nonce: Uint8Array;
    ticket: Uint8Array;
    maxEarlyDataSize: number | null;
};
/**
 * The CertificateStatus body of RFC 6066 s8: `status_type(1) || opaque OCSPResponse<1..2^24-1>`.
 * Two carriers share this exact shape — the TLS 1.2 CertificateStatus handshake message, and the
 * extension_data of a TLS 1.3 status_request CertificateEntry extension (RFC 8446 s4.4.2.1) —
 * which is why it is one parser and not two.
 *
 * @param {Uint8Array} body
 * @param {string} where named in errors
 * @returns {Uint8Array} the DER OCSPResponse, exactly as sent; its meaning is the trust layer's
 *   problem, not this layer's
 */
export function parseCertificateStatus(body: Uint8Array, where: string): Uint8Array;
/**
 * TLS 1.3 Certificate (RFC 8446 s4.4.2): context, then entries carrying per-cert extensions.
 *
 * Entry extensions are policed, not skipped: RFC 8446 s4.4.2 allows a server to send only
 * extensions the ClientHello offered, and s4.2 confines each type to specific messages — for
 * CertificateEntry that is status_request and signed_certificate_timestamp. An extension we
 * cannot attribute to our own offer is either a server confusion or a smuggling attempt, and
 * both end the handshake.
 *
 * Only the LEAF's stapled OCSP response is returned. A server may staple for intermediates too;
 * those staples are validated structurally (they must still be well-formed CertificateStatus)
 * but not consumed — this package checks revocation of the identity it is authenticating, and
 * inventing partial intermediate coverage would imply a guarantee it does not give.
 *
 * @param {Uint8Array} body
 * @param {{ offeredExtensions?: Set<number> }} [opts] extension types our ClientHello offered.
 *   Omitting it means "nothing was offered", the fail-closed reading.
 * @returns {{ chain: Uint8Array[], ocspResponse: Uint8Array | null }} DER certificates in wire
 *   order (leaf first), plus the leaf's stapled DER OCSPResponse if the server sent one
 */
export function parseCertificate13(body: Uint8Array, { offeredExtensions }?: {
    offeredExtensions?: Set<number>;
}): {
    chain: Uint8Array[];
    ocspResponse: Uint8Array | null;
};
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
 * @property {{ identity: Uint8Array, obfuscatedTicketAge: number, binderLen: number }} [psk]
 *   offer this resumption PSK. Encoded with a zeroed binder placeholder; the caller MUST derive
 *   the real binder over `message.subarray(0, truncatedLength)` and patch it in at
 *   `binderOffset` before the hello touches the wire — a zero binder on the wire is a hello
 *   every honest server must reject.
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
 * @property {number} [binderOffset] psk only: where the binder's bytes sit in `message`
 * @property {number} [truncatedLength] psk only: how many leading bytes of `message` the binder
 *   transcript covers (RFC 8446 s4.2.11.2 truncation — everything except the binders list)
 */
/**
 * Build a ClientHello. Returns the framed handshake message plus the metadata the rest of the
 * handshake needs to police the server's answer.
 *
 * @param {ClientHelloOptions} opts
 * @returns {ClientHello}
 */
/**
 * Extension emission order, by type. This is not cosmetic: JA3 and JA4 hash the extension list in
 * WIRE ORDER, so the order alone is a large part of what a fingerprinter reads.
 *
 * Captured from curl 8.21.0 / OpenSSL 3.6.3, which sends:
 *   renegotiation_info, server_name, ec_point_formats, supported_groups, ALPN, encrypt_then_mac,
 *   extended_master_secret, post_handshake_auth, signature_algorithms, supported_versions,
 *   psk_key_exchange_modes, key_share
 *
 * Two of those this package does not send, and the reason is the same in both cases — an extension
 * is a claim about what we can do. encrypt_then_mac only applies to CBC suites, which are not
 * offered; post_handshake_auth invites a CertificateRequest after the handshake, which is not
 * implemented. status_request goes the other way: curl does not send it, this package does,
 * because a stapled OCSP response is its only revocation signal. It is placed where OpenSSL puts
 * it when it does send one, right after server_name.
 *
 * Anything not named here keeps its natural position at the end, and pre_shared_key is forced last
 * whatever the caller asks for, because RFC 8446 s4.2.11 defines the binder transcript as the hello
 * truncated just before the binders — a range that only exists if nothing follows them.
 */
/** `extensionOrder: SHUFFLE_EXTENSIONS` reproduces what Chromium does — see grease.js. */
export const SHUFFLE_EXTENSIONS: "shuffle";
export const CURL_EXTENSION_ORDER: readonly number[];
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
     * offer this resumption PSK. Encoded with a zeroed binder placeholder; the caller MUST derive
     * the real binder over `message.subarray(0, truncatedLength)` and patch it in at
     * `binderOffset` before the hello touches the wire — a zero binder on the wire is a hello
     * every honest server must reject.
     */
    psk?: {
        identity: Uint8Array;
        obfuscatedTicketAge: number;
        binderLen: number;
    } | undefined;
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
    /**
     * psk only: where the binder's bytes sit in `message`
     */
    binderOffset?: number | undefined;
    /**
     * psk only: how many leading bytes of `message` the binder
     * transcript covers (RFC 8446 s4.2.11.2 truncation — everything except the binders list)
     */
    truncatedLength?: number | undefined;
};
import { GROUP_PARAMS } from './constants.js';
