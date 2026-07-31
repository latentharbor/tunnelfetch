/**
 * The RFC 5280 s6.1.1 trust-anchor triple, normalised. Validity bounds are recorded but never
 * enforced — see the module comment for why expiring a root is store policy, not path policy.
 * @typedef {object} TrustAnchor
 * @property {Uint8Array} subjectBytes exact subject DN DER
 * @property {string} subjectText
 * @property {Uint8Array} spkiDer
 * @property {Uint8Array | null} subjectKeyIdentifier
 * @property {import('./x509.js').NameConstraints | null} nameConstraints
 * @property {number | null} notBefore
 * @property {number | null} notAfter
 */
/**
 * Anything normalizeAnchor accepts: DER, a parsed certificate, or an anchor-shaped record.
 * The record form also admits `nameConstraintsBytes` (raw extnValue), which is how the bundled
 * store defers parsing to the one anchor a handshake actually lands on.
 * @typedef {object} AnchorRecord
 * @property {Uint8Array} subjectBytes
 * @property {Uint8Array} spkiDer
 * @property {string} [subjectText]
 * @property {Uint8Array | null} [subjectKeyIdentifier]
 * @property {import('./x509.js').NameConstraints | null} [nameConstraints]
 * @property {Uint8Array | null} [nameConstraintsBytes]
 * @property {number | null} [notBefore]
 * @property {number | null} [notAfter]
 */
/** @typedef {Uint8Array | import('./x509.js').Certificate | AnchorRecord} AnchorLike */
/**
 * An indexed anchor lookup: everything path building needs from a root store. The bundled
 * store implements it with a subject-hash index so a handshake touches one anchor, not all.
 * @typedef {{ forIssuer: (subjectDn: Uint8Array) => AnchorLike[] | Promise<AnchorLike[]> }}
 *   AnchorSource
 */
/**
 * Strip a parsed certificate down to the RFC 5280 s6.1.1 trust-anchor triple. Used for the
 * `mode:'anchors'` knob and by the root-store generator, so both feed path validation through
 * the identical shape.
 * @param {import('./x509.js').Certificate} cert
 * @returns {TrustAnchor}
 */
export function anchorFromCertificate(cert: import("./x509.js").Certificate): TrustAnchor;
/**
 * Verify `cert`'s signature over its original to-be-signed bytes with the signer's public key.
 *
 * The scheme comes from resolveSignatureScheme (which is where MD5/SHA-1 die, before any
 * cryptography runs). For ECDSA the curve belongs to the issuer's key, not the OID, so the
 * WebCrypto import parameters are chosen from the issuer's SPKI and only the hash from the OID —
 * both looked up in SIG_SCHEME_PARAMS rather than re-declared here.
 *
 * Exported (as verifySignedObject) for the OCSP checker: a BasicOCSPResponse is signed exactly
 * like a certificate — an AlgorithmIdentifier, a BIT STRING over the original DER of a TBS
 * element — and two implementations of "check an X.509-style signature" is two chances for one
 * of them to be subtly the weaker. `cert` is therefore the structural subset both callers can
 * supply: `{ tbsBytes, signature, signatureAlgorithm, subject: { text } }`, which a parsed
 * Certificate satisfies as-is and the OCSP checker fakes up from response fields.
 *
 * @param {{ tbsBytes: Uint8Array, signature: Uint8Array,
 *           signatureAlgorithm: import('./x509.js').AlgorithmId,
 *           subject: { text: string } }} cert what was signed, certificate-shaped
 * @param {Uint8Array} issuerSpkiDer the signer's SubjectPublicKeyInfo, DER
 * @param {string} issuerText the signer's name, for error messages
 * @returns {Promise<void>} every failure throws a typed CertificateError
 */
export function verifySignedObject(cert: {
    tbsBytes: Uint8Array;
    signature: Uint8Array;
    signatureAlgorithm: import("./x509.js").AlgorithmId;
    subject: {
        text: string;
    };
}, issuerSpkiDer: Uint8Array, issuerText: string): Promise<void>;
/**
 * Build and validate a certification path. Every failure throws a typed CertificateError;
 * there is no boolean to forget to check.
 *
 * @param {object} opts
 * @param {Array<Uint8Array | import('./x509.js').Certificate>} opts.chain DER (or
 *   already-parsed) certificates, leaf first, in whatever order and with whatever extras the
 *   server chose to send
 * @param {AnchorLike[] | AnchorSource} opts.anchors trust anchors, or an indexed anchor source
 * @param {string | null} [opts.hostname] identity to require of the leaf; omit to skip
 *   (index.js never omits)
 * @param {number} [opts.now] epoch ms
 * @param {number} [opts.maxPathLength] hard cap on path certificates — this runs on a metered
 *   runtime and a pathological chain must cost O(cap), not O(chain²)
 * @returns {Promise<{ leaf: import('./x509.js').Certificate,
 *   path: import('./x509.js').Certificate[], anchor: TrustAnchor }>} parsed leaf, the
 *   validated path (leaf first), and the anchor that terminated it
 */
export function validatePath({ chain, anchors, hostname, now, maxPathLength }: {
    chain: Array<Uint8Array | import("./x509.js").Certificate>;
    anchors: AnchorLike[] | AnchorSource;
    hostname?: string | null | undefined;
    now?: number | undefined;
    maxPathLength?: number | undefined;
}): Promise<{
    leaf: import("./x509.js").Certificate;
    path: import("./x509.js").Certificate[];
    anchor: TrustAnchor;
}>;
/**
 * The RFC 5280 s6.1.1 trust-anchor triple, normalised. Validity bounds are recorded but never
 * enforced — see the module comment for why expiring a root is store policy, not path policy.
 */
export type TrustAnchor = {
    /**
     * exact subject DN DER
     */
    subjectBytes: Uint8Array;
    subjectText: string;
    spkiDer: Uint8Array;
    subjectKeyIdentifier: Uint8Array | null;
    nameConstraints: import("./x509.js").NameConstraints | null;
    notBefore: number | null;
    notAfter: number | null;
};
/**
 * Anything normalizeAnchor accepts: DER, a parsed certificate, or an anchor-shaped record.
 * The record form also admits `nameConstraintsBytes` (raw extnValue), which is how the bundled
 * store defers parsing to the one anchor a handshake actually lands on.
 */
export type AnchorRecord = {
    subjectBytes: Uint8Array;
    spkiDer: Uint8Array;
    subjectText?: string | undefined;
    subjectKeyIdentifier?: Uint8Array<ArrayBufferLike> | null | undefined;
    nameConstraints?: import("./x509.js").NameConstraints | null | undefined;
    nameConstraintsBytes?: Uint8Array<ArrayBufferLike> | null | undefined;
    notBefore?: number | null | undefined;
    notAfter?: number | null | undefined;
};
export type AnchorLike = Uint8Array | import("./x509.js").Certificate | AnchorRecord;
/**
 * An indexed anchor lookup: everything path building needs from a root store. The bundled
 * store implements it with a subject-hash index so a handshake touches one anchor, not all.
 */
export type AnchorSource = {
    forIssuer: (subjectDn: Uint8Array) => AnchorLike[] | Promise<AnchorLike[]>;
};
