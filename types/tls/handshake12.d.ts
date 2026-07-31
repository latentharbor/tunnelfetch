/**
 * The one refusal that must fire regardless of which message was expected. Exported for
 * connect.js, whose ServerHello wait is the earliest point a 1.2 server can spring one.
 * @returns {never}
 */
export function refuseHelloRequest(): never;
/**
 * Run a TLS 1.2 handshake over a byte duplex and return the plaintext duplex above it.
 *
 * @param {object} args
 * @param {import('./connect.js').ByteDuplex} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {import('./handshake.js').VerifyPeer} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key this
 *   handshake will accept a ServerKeyExchange signature from.
 * @param {import('./connect.js').TlsOptions} [args.options] `versions` is ignored: this entry
 *   pins the offer to [TLS 1.2]
 * @param {import('./connect.js').TlsDeps} [args.deps]
 * @returns {Promise<import('./connect.js').TlsSession>}
 */
export function handshakeTls12({ transport, hostname, verifyPeer, options, deps }: {
    transport: import("./connect.js").ByteDuplex;
    hostname: string;
    verifyPeer: import("./handshake.js").VerifyPeer;
    options?: import("./connect.js").TlsOptions | undefined;
    deps?: import("./connect.js").TlsDeps | undefined;
}): Promise<import("./connect.js").TlsSession>;
/**
 * Continue a TLS 1.2 handshake from the ServerHello. Called by connect.js once negotiation
 * routed the connection here; the record layer arrives already pinned to 1.2 semantics and the
 * transcript already runs under the negotiated suite's PRF hash.
 * @param {import('./handshake.js').HandshakeContext} ctx
 * @returns {Promise<import('./connect.js').TlsSession>}
 */
export function continueTls12(ctx: import("./handshake.js").HandshakeContext): Promise<import("./connect.js").TlsSession>;
