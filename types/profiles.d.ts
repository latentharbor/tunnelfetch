/**
 * Fold a profile into a Client's options, and refuse an identity that cannot be honoured.
 *
 * Explicit options WIN over the profile: a caller who names a field meant to name it, and silently
 * overriding them would make the profile impossible to adjust. The profile fills what was not said.
 *
 * @param {object} options as given to the Client
 * @returns {object} options with the profile folded in
 */
export function applyProfile(options: object): object;
/**
 * @typedef {object} FingerprintProfile
 * @property {string} name
 * @property {object} [tls] merged into `tls`
 * @property {readonly string[]} [headerOrder]
 * @property {Array<[number, number]>} [http2Settings]
 * @property {string[]} [http2PseudoHeaderOrder]
 * @property {Record<string, string>} [http2HpackIndexing]
 * @property {Array<[string, string]>} [headers] default request headers, in order
 * @property {string[]} [requires] capabilities the caller must inject for this identity to be
 *   honest: `'cipher:chacha20'`, `'group:x25519mlkem768'`, `'decoder:br'`, `'decoder:zstd'`
 */
/**
 * curl 8.21.0 / OpenSSL 3.6.3. Complete: every layer was captured, and everything it offers is
 * something this package can actually perform. This is the default identity.
 */
export const curl: Readonly<{
    name: "curl/8.21.0";
    tls: Readonly<{
        alpn: string[];
        extensionOrder: readonly number[];
        grease: false;
    }>;
    headerOrder: readonly string[];
    headers: readonly string[][];
    http2Settings: readonly number[][];
    http2PseudoHeaderOrder: readonly string[];
    http2HpackIndexing: Readonly<{
        ':path': "without";
    }>;
    requires: readonly never[];
}>;
/**
 * Chromium, TLS layer captured off the wire.
 *
 * INCOMPLETE ON PURPOSE, and it refuses to be used as though it were not. Two things are missing
 * and neither can be papered over:
 *
 *   * Chromium offers TLS_CHACHA20_POLY1305_SHA256 and the X25519MLKEM768 group, and this package
 *     implements neither. A ClientHello is an OFFER: a server may take either, and a client that
 *     then cannot complete the handshake has traded a fingerprint mismatch for a dead connection.
 *     Both are reachable by injection, which is why they are listed in `requires` rather than
 *     silently dropped.
 *   * Chromium's HTTP/2 preface was not captured — capturing it needs a TLS server the browser
 *     will trust, which is a different exercise. So this profile carries no h2 layer, and using it
 *     with HTTP/2 enabled would produce a Chromium ClientHello above a curl h2 preface: precisely
 *     the split identity a profile exists to prevent.
 *
 * `applyProfile` refuses both cases with a message naming what is missing.
 */
export const chrome: Readonly<{
    name: "chrome/150";
    tls: Readonly<{
        ciphers: readonly number[];
        groups: readonly number[];
        offerGroups: readonly number[];
        sigSchemes: readonly number[];
        alpn: string[];
        extensionOrder: "shuffle";
        grease: true;
    }>;
    http2Settings: readonly number[][];
    http2ConnectionWindow: number;
    http2PseudoHeaderOrder: readonly string[];
    headerOrder: readonly string[];
    headers: readonly string[][];
    requires: readonly string[];
}>;
/** @type {Record<string, FingerprintProfile>} */
export const profiles: Record<string, FingerprintProfile>;
export type FingerprintProfile = {
    name: string;
    /**
     * merged into `tls`
     */
    tls?: object | undefined;
    headerOrder?: readonly string[] | undefined;
    http2Settings?: [number, number][] | undefined;
    http2PseudoHeaderOrder?: string[] | undefined;
    http2HpackIndexing?: Record<string, string> | undefined;
    /**
     * default request headers, in order
     */
    headers?: [string, string][] | undefined;
    /**
     * capabilities the caller must inject for this identity to be
     * honest: `'cipher:chacha20'`, `'group:x25519mlkem768'`, `'decoder:br'`, `'decoder:zstd'`
     */
    requires?: string[] | undefined;
};
