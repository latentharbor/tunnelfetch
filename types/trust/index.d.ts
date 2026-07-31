/**
 * A trust anchor as supplied by a caller: PEM text or raw DER.
 * @typedef {string | Uint8Array} AnchorInput
 */
/**
 * Revocation policy, for the modes that validate chains. Checking is via stapled OCSP only, so
 * the knob decides what a MISSING staple means: `'staple'` (the default) tolerates absence but
 * fully verifies any staple that is present; `'require-staple'` makes absence OCSP_REQUIRED.
 * A verified `revoked` or `unknown` verdict is fatal under both — no value ignores it.
 * @typedef {'staple' | 'require-staple'} RevocationPolicy
 */
/**
 * Verify against the bundled CCADB root store. The default.
 * @typedef {{ mode?: 'system', revocation?: RevocationPolicy }} SystemTrust
 */
/**
 * Verify against exactly these anchors and nothing else. The bundled store is not consulted.
 * @typedef {{ mode: 'anchors', anchors: AnchorInput[],
 *             revocation?: RevocationPolicy }} AnchorsTrust
 */
/**
 * Full path validation, plus a requirement that some certificate in the accepted path (or its
 * anchor) match one of `pins`. Pins are `sha256/` followed by the base64 SHA-256 of a
 * SubjectPublicKeyInfo, the same spelling HPKP used.
 * @typedef {{ mode: 'pinned', pins: string[], anchors?: AnchorInput[],
 *             revocation?: RevocationPolicy }} PinnedTrust
 */
/**
 * No path validation at all. `insecureAcceptAnyCertificate` is mandatory and must be `true`, so
 * that this mode can never be reached by a typo in `mode`. Supplying `pins` turns it into
 * pin-only trust: no chain is built, but a pin must still match. `revocation` is refused here:
 * without a validated issuer there is no trusted key to verify a staple against, so the check
 * cannot be performed honestly and pretending otherwise would be worse.
 * @typedef {{ mode: 'none', insecureAcceptAnyCertificate: true, pins?: string[] }} NoTrust
 */
/**
 * Caller-supplied policy. Returning normally accepts the chain; throwing rejects it. The third
 * argument carries the peer's stapled OCSP response (DER, or null) so a custom policy can judge
 * revocation itself — `verifyOcspStaple` is exported for exactly that.
 * @typedef {{ mode: 'custom',
 *             verify: (chain: ParsedCertificate[], hostname: string,
 *                      details?: { ocspResponse: Uint8Array | null })
 *               => void | Promise<void> }} CustomTrust
 */
/**
 * The `verify=` knob, in httpx's spirit. Written as a discriminated union so that a TypeScript
 * caller cannot ask for pinning without pins, or reach `mode: 'none'` without spelling out the
 * flag that says they meant it — both of which are otherwise runtime errors discovered in
 * production rather than compile errors discovered while typing.
 * @typedef {SystemTrust | AnchorsTrust | PinnedTrust | NoTrust | CustomTrust} TrustConfig
 */
/**
 * A parsed certificate, as returned by `parseCertificate`. Only the members other layers rely on
 * are named here; the object carries the full parse.
 * @typedef {object} ParsedCertificate
 * @property {Uint8Array} der the original bytes, never re-encoded
 * @property {Uint8Array} tbsBytes exact TBSCertificate slice the signature covers
 * @property {{ spkiDer: Uint8Array, algorithmOid: string, keyBytes: Uint8Array }} spki
 * @property {{ text: string }} subject
 * @property {{ text: string }} issuer
 * @property {number} notBefore epoch ms
 * @property {number} notAfter epoch ms
 * @property {{ dns: string[], ip: Uint8Array[], uri: string[], email: string[] }} subjectAltNames
 */
/**
 * Verify a TLS-delivered certificate chain for `hostname`.
 *
 * @param {object} opts
 * @param {Uint8Array[]} opts.chain DER certificates, leaf first, as the peer sent them
 * @param {string} opts.hostname identity from the request URL (DNS name or IP literal)
 * @param {TrustConfig} [opts.trust] the verification policy; defaults to the bundled roots
 * @param {number} [opts.now] epoch ms, for tests and for callers with a better clock
 * @param {Uint8Array | null} [opts.ocspResponse] the peer's stapled DER OCSPResponse, when the
 *   handshake carried one; judged under `trust.revocation` (see the policy comment above)
 * @returns {Promise<ParsedCertificate>} the parsed leaf. Every other outcome throws.
 */
export function verifyChain({ chain, hostname, trust, now, ocspResponse, }: {
    chain: Uint8Array[];
    hostname: string;
    trust?: TrustConfig | undefined;
    now?: number | undefined;
    ocspResponse?: Uint8Array<ArrayBufferLike> | null | undefined;
}): Promise<ParsedCertificate>;
export { matchesIdentity } from "./name.js";
/**
 * A trust anchor as supplied by a caller: PEM text or raw DER.
 */
export type AnchorInput = string | Uint8Array;
/**
 * Revocation policy, for the modes that validate chains. Checking is via stapled OCSP only, so
 * the knob decides what a MISSING staple means: `'staple'` (the default) tolerates absence but
 * fully verifies any staple that is present; `'require-staple'` makes absence OCSP_REQUIRED.
 * A verified `revoked` or `unknown` verdict is fatal under both — no value ignores it.
 */
export type RevocationPolicy = "staple" | "require-staple";
/**
 * Verify against the bundled CCADB root store. The default.
 */
export type SystemTrust = {
    mode?: "system";
    revocation?: RevocationPolicy;
};
/**
 * Verify against exactly these anchors and nothing else. The bundled store is not consulted.
 */
export type AnchorsTrust = {
    mode: "anchors";
    anchors: AnchorInput[];
    revocation?: RevocationPolicy;
};
/**
 * Full path validation, plus a requirement that some certificate in the accepted path (or its
 * anchor) match one of `pins`. Pins are `sha256/` followed by the base64 SHA-256 of a
 * SubjectPublicKeyInfo, the same spelling HPKP used.
 */
export type PinnedTrust = {
    mode: "pinned";
    pins: string[];
    anchors?: AnchorInput[];
    revocation?: RevocationPolicy;
};
/**
 * No path validation at all. `insecureAcceptAnyCertificate` is mandatory and must be `true`, so
 * that this mode can never be reached by a typo in `mode`. Supplying `pins` turns it into
 * pin-only trust: no chain is built, but a pin must still match. `revocation` is refused here:
 * without a validated issuer there is no trusted key to verify a staple against, so the check
 * cannot be performed honestly and pretending otherwise would be worse.
 */
export type NoTrust = {
    mode: "none";
    insecureAcceptAnyCertificate: true;
    pins?: string[];
};
/**
 * Caller-supplied policy. Returning normally accepts the chain; throwing rejects it. The third
 * argument carries the peer's stapled OCSP response (DER, or null) so a custom policy can judge
 * revocation itself — `verifyOcspStaple` is exported for exactly that.
 */
export type CustomTrust = {
    mode: "custom";
    verify: (chain: ParsedCertificate[], hostname: string, details?: {
        ocspResponse: Uint8Array | null;
    }) => void | Promise<void>;
};
/**
 * The `verify=` knob, in httpx's spirit. Written as a discriminated union so that a TypeScript
 * caller cannot ask for pinning without pins, or reach `mode: 'none'` without spelling out the
 * flag that says they meant it — both of which are otherwise runtime errors discovered in
 * production rather than compile errors discovered while typing.
 */
export type TrustConfig = SystemTrust | AnchorsTrust | PinnedTrust | NoTrust | CustomTrust;
/**
 * A parsed certificate, as returned by `parseCertificate`. Only the members other layers rely on
 * are named here; the object carries the full parse.
 */
export type ParsedCertificate = {
    /**
     * the original bytes, never re-encoded
     */
    der: Uint8Array;
    /**
     * exact TBSCertificate slice the signature covers
     */
    tbsBytes: Uint8Array;
    spki: {
        spkiDer: Uint8Array;
        algorithmOid: string;
        keyBytes: Uint8Array;
    };
    subject: {
        text: string;
    };
    issuer: {
        text: string;
    };
    /**
     * epoch ms
     */
    notBefore: number;
    /**
     * epoch ms
     */
    notAfter: number;
    subjectAltNames: {
        dns: string[];
        ip: Uint8Array[];
        uri: string[];
        email: string[];
    };
};
export { parseCertificate, decodePem } from "./x509.js";
export { validatePath, anchorFromCertificate } from "./path.js";
export { verifyOcspStaple, parseOcspResponse } from "./ocsp.js";
export { systemAnchors, provenance as rootStoreProvenance } from "./roots.js";
