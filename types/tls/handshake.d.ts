/**
 * Run a TLS 1.3 handshake over a byte duplex and return the plaintext duplex above it.
 *
 * @param {object} args
 * @param {import('./connect.js').ByteDuplex} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {VerifyPeer} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key this
 *   handshake will accept a CertificateVerify signature from.
 * @param {import('./connect.js').TlsOptions} [args.options] `versions` is ignored: this entry
 *   pins the offer to [TLS 1.3]
 * @param {import('./connect.js').TlsDeps} [args.deps]
 * @returns {Promise<import('./connect.js').TlsSession>}
 */
export function handshakeTls13({ transport, hostname, verifyPeer, options, deps }: {
    transport: import("./connect.js").ByteDuplex;
    hostname: string;
    verifyPeer: VerifyPeer;
    options?: import("./connect.js").TlsOptions | undefined;
    deps?: import("./connect.js").TlsDeps | undefined;
}): Promise<import("./connect.js").TlsSession>;
/**
 * Continue a TLS 1.3 handshake from the first ServerHello (which may be a HelloRetryRequest).
 * Called by connect.js once negotiation routed the connection here.
 * @param {HandshakeContext} ctx
 * @returns {Promise<import('./connect.js').TlsSession>}
 */
export function continueTls13(ctx: HandshakeContext): Promise<import("./connect.js").TlsSession>;
/**
 * Only one key share is offered by default. A second costs a key generation and 30-odd bytes for
 * a group the server is unlikely to prefer; a HelloRetryRequest recovers the rare case at the
 * cost of one round trip.
 */
export const DEFAULT_OFFER_GROUPS: number[];
/**
 * The injected trust decision. Must throw to reject; resolves with the validated leaf, whose
 * SPKI is the only key a driver will accept a handshake signature from.
 */
export type VerifyPeer = (chain: Uint8Array[], hostname: string) => Promise<{
    spki: {
        spkiDer: Uint8Array;
    };
}>;
/**
 * Driver context assembled by connect.js after the ServerHello routed the connection: the
 * record layer, the transcript (created under the negotiated suite's hash, ClientHello already
 * folded in), the ClientHello metadata, the parsed ServerHello with its raw bytes, and the
 * offer that produced them. Both continue* drivers consume exactly this shape.
 */
export type HandshakeContext = {
    record: import("./record.js").RecordLayer;
    transcript: import("./transcript.js").Transcript;
    hello: import("./handshake-messages.js").ClientHello;
    serverHello: import("./handshake-messages.js").ServerHello;
    rawServerHello: Uint8Array;
    suite: number;
    params: import("./constants.js").CipherParams;
    hostname: string;
    verifyPeer: VerifyPeer;
    options: import("./connect.js").TlsOptions;
    deps: import("./connect.js").TlsDeps;
    offer: {
        versions: number[];
        ciphers: number[];
        groups: number[];
        offerGroups: number[];
        alpn: string[];
        keyShares: import("./handshake-messages.js").KeyShare[];
    };
};
