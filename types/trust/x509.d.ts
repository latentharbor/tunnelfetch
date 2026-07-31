/**
 * A parsed X.500 Name. `bytes` is the exact DER of the whole Name — the canonical identity for
 * every comparison; `rdns` and `text` exist for constraint checks and log lines respectively.
 * @typedef {object} DistinguishedName
 * @property {Uint8Array} bytes
 * @property {Array<Array<{ oid: string, value: string }>>} rdns one array per RDN, in order;
 *   non-string attribute values are rendered as '#hex'
 * @property {string} text human-readable 'CN=..., O=...' form
 */
/**
 * Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName (SET OF AttributeTypeAndValue).
 *
 * `bytes` is the exact DER of the whole Name and is the canonical form used for all issuer ==
 * subject comparisons. RFC 5280 s7.1 also allows caseIgnore/whitespace-folded matching, but a CA
 * that spells its own name two different ways between certificates breaks every deployed
 * validator that matters (they compare bytes too), and a lax comparator is one more place to
 * confuse two names. Exact bytes, fail closed.
 *
 * @param {Uint8Array} bytes
 * @param {import('./der.js').Tlv} tlv
 * @returns {DistinguishedName}
 */
export function parseName(bytes: Uint8Array, tlv: import("./der.js").Tlv): DistinguishedName;
/**
 * One GeneralSubtree, reduced to what constraint enforcement can act on. 'other' entries are
 * forms this validator cannot enforce; path.js rejects the path when a critical extension
 * carries one, which is why they are preserved rather than dropped.
 * @typedef {{ type: 'dns', value: string } | { type: 'email', value: string }
 *   | { type: 'uri', value: string } | { type: 'ip', addr: Uint8Array, mask: Uint8Array }
 *   | { type: 'other', tag: number }} NameConstraintSubtree
 */
/**
 * @typedef {object} NameConstraints
 * @property {ReadonlyArray<NameConstraintSubtree> | null} permitted
 * @property {ReadonlyArray<NameConstraintSubtree> | null} excluded
 */
/**
 * NameConstraints (RFC 5280 s4.2.1.10). Subtrees we cannot enforce are preserved as
 * `{type:'other'}` entries so path.js can refuse to ignore them when the extension is critical.
 * A GeneralSubtree with minimum != 0 or maximum present is demoted to unsupported for the same
 * reason: RFC 5280 forbids them, and enforcing a constraint we cannot interpret is worse than
 * rejecting.
 *
 * @param {Uint8Array} valueBytes the extnValue content
 * @returns {NameConstraints}
 */
export function parseNameConstraints(valueBytes: Uint8Array): NameConstraints;
/**
 * How to verify one certificate signature. `scheme` indexes SIG_SCHEME_PARAMS where the OID
 * fully determines it; for ECDSA only the hash is known here and path.js completes the plan
 * from the issuer's curve.
 * @typedef {object} SignaturePlan
 * @property {'rsa-pkcs1' | 'rsa-pss' | 'ecdsa' | 'ed25519'} kind
 * @property {number} [scheme]
 * @property {'SHA-256' | 'SHA-384' | 'SHA-512'} [hash] weaker hashes died in the OID check
 * @property {string} name for error messages
 */
/**
 * Map a certificate's signature algorithm to a verification plan, or throw.
 *
 * Called by path.js exactly when a certificate's signature is about to anchor trust. Weak
 * algorithms (MD2/MD4/MD5, SHA-1) are rejected here by OID, before any cryptography runs — some
 * runtimes' verifiers still accept SHA-1 and this one must provably not be among them. ECDSA
 * returns only the hash: in X.509 (unlike TLS) the curve belongs to the issuer's key, so path.js
 * completes the plan from the issuer's SPKI.
 *
 * @param {Certificate} cert
 * @returns {SignaturePlan}
 */
export function resolveSignatureScheme(cert: Certificate): SignaturePlan;
/**
 * Parse a bare SubjectPublicKeyInfo element (as stored for trust anchors, which persist only the
 * SPKI rather than a whole certificate). Same walk as inside a certificate.
 * @param {Uint8Array} spkiDer
 * @returns {Spki}
 */
export function parseSubjectPublicKeyInfo(spkiDer: Uint8Array): Spki;
/**
 * The certificate's signatureAlgorithm, with parameters kept both raw and as a Tlv because
 * RSA-PSS resolution has to re-walk them.
 * @typedef {object} AlgorithmId
 * @property {string} oid
 * @property {Uint8Array | null} paramsBytes
 * @property {import('./der.js').Tlv | null} paramsTlv
 * @property {Uint8Array} bytes the whole AlgorithmIdentifier element
 */
/**
 * A fully parsed certificate. Frozen; every byte field is a subarray of the original `der`.
 * This is the complete shape behind the trimmed `ParsedCertificate` documented on the public
 * verifyChain surface.
 * @typedef {object} Certificate
 * @property {Uint8Array} der the original bytes, never re-encoded
 * @property {Uint8Array} tbsBytes exact TBSCertificate slice the signature covers
 * @property {number} version 1, 2 or 3
 * @property {string} serialNumber hex of the INTEGER content bytes
 * @property {boolean} serialNegative negative serials are misissuance but must still parse
 * @property {AlgorithmId} signatureAlgorithm
 * @property {Uint8Array} signature
 * @property {DistinguishedName} issuer
 * @property {DistinguishedName} subject
 * @property {number} notBefore epoch ms
 * @property {number} notAfter epoch ms
 * @property {Spki} spki
 * @property {Map<string, { critical: boolean, valueBytes: Uint8Array }>} extensions by OID
 * @property {{ present: boolean, ca: boolean, pathLenConstraint: number | null }} basicConstraints
 * @property {KeyUsage | null} keyUsage null when the extension is absent
 * @property {ReadonlyArray<string> | null} extendedKeyUsage KeyPurposeId OIDs
 * @property {SubjectAltNames} subjectAltNames
 * @property {Uint8Array | null} subjectKeyIdentifier
 * @property {Uint8Array | null} authorityKeyIdentifier keyIdentifier field only
 * @property {NameConstraints | null} nameConstraints
 * @property {ReadonlyArray<string>} unknownCriticalExtensions OIDs path.js must reject on
 * @property {boolean} isSelfIssued subject DER equals issuer DER
 */
/**
 * Parse one DER certificate into a frozen, fully-walked structure. Throws CertificateError
 * (CERT_PARSE) on malformed or self-contradictory encodings; judgement about what the
 * certificate MAY do lives in path.js.
 *
 * `tbsBytes` is the exact original slice of the TBSCertificate element — signature verification
 * happens over these bytes and never over anything re-encoded.
 *
 * @param {Uint8Array} der
 * @returns {Certificate}
 */
export function parseCertificate(der: Uint8Array): Certificate;
/**
 * Extract every CERTIFICATE block from PEM text as DER. Used for user-supplied trust anchors;
 * TLS itself always delivers DER. Throws CERT_PARSE on bad base64 or when no block is found.
 * @param {string} text
 * @returns {Uint8Array[]}
 */
export function decodePem(text: string): Uint8Array[];
export namespace OID {
    let rsaEncryption: "1.2.840.113549.1.1.1";
    let rsassaPss: "1.2.840.113549.1.1.10";
    let ecPublicKey: "1.2.840.10045.2.1";
    let ed25519: "1.3.101.112";
    let ed448: "1.3.101.113";
    let secp256r1: "1.2.840.10045.3.1.7";
    let secp384r1: "1.3.132.0.34";
    let secp521r1: "1.3.132.0.35";
    let sha256WithRsa: "1.2.840.113549.1.1.11";
    let sha384WithRsa: "1.2.840.113549.1.1.12";
    let sha512WithRsa: "1.2.840.113549.1.1.13";
    let ecdsaWithSha256: "1.2.840.10045.4.3.2";
    let ecdsaWithSha384: "1.2.840.10045.4.3.3";
    let ecdsaWithSha512: "1.2.840.10045.4.3.4";
    let sha1: "1.3.14.3.2.26";
    let sha256: "2.16.840.1.101.3.4.2.1";
    let sha384: "2.16.840.1.101.3.4.2.2";
    let sha512: "2.16.840.1.101.3.4.2.3";
    let mgf1: "1.2.840.113549.1.1.8";
    let subjectKeyIdentifier: "2.5.29.14";
    let keyUsage: "2.5.29.15";
    let subjectAltName: "2.5.29.17";
    let issuerAltName: "2.5.29.18";
    let basicConstraints: "2.5.29.19";
    let nameConstraints: "2.5.29.30";
    let crlDistributionPoints: "2.5.29.31";
    let certificatePolicies: "2.5.29.32";
    let authorityKeyIdentifier: "2.5.29.35";
    let extendedKeyUsage: "2.5.29.37";
    let freshestCrl: "2.5.29.46";
    let authorityInfoAccess: "1.3.6.1.5.5.7.1.1";
    let subjectInfoAccess: "1.3.6.1.5.5.7.1.11";
    let sctList: "1.3.6.1.4.1.11129.2.4.2";
    let serverAuth: "1.3.6.1.5.5.7.3.1";
    let clientAuth: "1.3.6.1.5.5.7.3.2";
    let anyExtendedKeyUsage: "2.5.29.37.0";
}
/**
 * Extensions this validator understands, or has deliberately judged safe to leave unprocessed
 * even when marked critical. Everything else that is critical causes rejection in path.js
 * (RFC 5280 s6.1: a relying party MUST reject on unrecognised critical extensions — ignoring
 * them is the classic fail-open).
 *
 * certificatePolicies is listed because with no required policy set, RFC 5280 policy processing
 * cannot fail; policyConstraints / inhibitAnyPolicy are deliberately NOT listed, because they
 * make policy processing mandatory and we do not implement it — they are always critical, so
 * their presence in a path rejects it.
 */
export const KNOWN_EXTENSIONS: Set<"2.5.29.14" | "2.5.29.15" | "2.5.29.17" | "2.5.29.18" | "2.5.29.19" | "2.5.29.30" | "2.5.29.31" | "2.5.29.32" | "2.5.29.35" | "2.5.29.37" | "2.5.29.46" | "1.3.6.1.5.5.7.1.1" | "1.3.6.1.5.5.7.1.11" | "1.3.6.1.4.1.11129.2.4.2">;
/**
 * A parsed X.500 Name. `bytes` is the exact DER of the whole Name — the canonical identity for
 * every comparison; `rdns` and `text` exist for constraint checks and log lines respectively.
 */
export type DistinguishedName = {
    bytes: Uint8Array;
    /**
     * one array per RDN, in order;
     * non-string attribute values are rendered as '#hex'
     */
    rdns: Array<Array<{
        oid: string;
        value: string;
    }>>;
    /**
     * human-readable 'CN=..., O=...' form
     */
    text: string;
};
/**
 * The nine RFC 5280 s4.2.1.3 bits, each explicit so a validator reads `false`, never
 * `undefined` — an absent bit and an unset bit must be indistinguishable.
 */
export type KeyUsage = {
    digitalSignature: boolean;
    nonRepudiation: boolean;
    keyEncipherment: boolean;
    dataEncipherment: boolean;
    keyAgreement: boolean;
    keyCertSign: boolean;
    cRLSign: boolean;
    encipherOnly: boolean;
    decipherOnly: boolean;
};
/**
 * The SAN entries identity matching consults. `present` distinguishes "no SAN extension"
 * (matches nothing, by policy) from "SAN with no entries of this type".
 */
export type SubjectAltNames = {
    present: boolean;
    dns: ReadonlyArray<string>;
    /**
     * raw 4- or 16-byte addresses
     */
    ip: ReadonlyArray<Uint8Array>;
    uri: ReadonlyArray<string>;
    email: ReadonlyArray<string>;
};
/**
 * One GeneralSubtree, reduced to what constraint enforcement can act on. 'other' entries are
 * forms this validator cannot enforce; path.js rejects the path when a critical extension
 * carries one, which is why they are preserved rather than dropped.
 */
export type NameConstraintSubtree = {
    type: "dns";
    value: string;
} | {
    type: "email";
    value: string;
} | {
    type: "uri";
    value: string;
} | {
    type: "ip";
    addr: Uint8Array;
    mask: Uint8Array;
} | {
    type: "other";
    tag: number;
};
export type NameConstraints = {
    permitted: ReadonlyArray<NameConstraintSubtree> | null;
    excluded: ReadonlyArray<NameConstraintSubtree> | null;
};
/**
 * How to verify one certificate signature. `scheme` indexes SIG_SCHEME_PARAMS where the OID
 * fully determines it; for ECDSA only the hash is known here and path.js completes the plan
 * from the issuer's curve.
 */
export type SignaturePlan = {
    kind: "rsa-pkcs1" | "rsa-pss" | "ecdsa" | "ed25519";
    scheme?: number | undefined;
    /**
     * weaker hashes died in the OID check
     */
    hash?: "SHA-256" | "SHA-384" | "SHA-512" | undefined;
    /**
     * for error messages
     */
    name: string;
};
/**
 * A parsed SubjectPublicKeyInfo. `spkiDer` is the exact original element — the bytes WebCrypto
 * imports and the bytes SPKI pinning hashes, so it must never be a re-encoding.
 */
export type Spki = {
    algorithmOid: string;
    /**
     * named curve, EC keys only
     */
    curveOid: string | null;
    /**
     * the subjectPublicKey payload
     */
    keyBytes: Uint8Array;
    spkiDer: Uint8Array;
};
/**
 * The certificate's signatureAlgorithm, with parameters kept both raw and as a Tlv because
 * RSA-PSS resolution has to re-walk them.
 */
export type AlgorithmId = {
    oid: string;
    paramsBytes: Uint8Array | null;
    paramsTlv: import("./der.js").Tlv | null;
    /**
     * the whole AlgorithmIdentifier element
     */
    bytes: Uint8Array;
};
/**
 * A fully parsed certificate. Frozen; every byte field is a subarray of the original `der`.
 * This is the complete shape behind the trimmed `ParsedCertificate` documented on the public
 * verifyChain surface.
 */
export type Certificate = {
    /**
     * the original bytes, never re-encoded
     */
    der: Uint8Array;
    /**
     * exact TBSCertificate slice the signature covers
     */
    tbsBytes: Uint8Array;
    /**
     * 1, 2 or 3
     */
    version: number;
    /**
     * hex of the INTEGER content bytes
     */
    serialNumber: string;
    /**
     * negative serials are misissuance but must still parse
     */
    serialNegative: boolean;
    signatureAlgorithm: AlgorithmId;
    signature: Uint8Array;
    issuer: DistinguishedName;
    subject: DistinguishedName;
    /**
     * epoch ms
     */
    notBefore: number;
    /**
     * epoch ms
     */
    notAfter: number;
    spki: Spki;
    /**
     * by OID
     */
    extensions: Map<string, {
        critical: boolean;
        valueBytes: Uint8Array;
    }>;
    basicConstraints: {
        present: boolean;
        ca: boolean;
        pathLenConstraint: number | null;
    };
    /**
     * null when the extension is absent
     */
    keyUsage: KeyUsage | null;
    /**
     * KeyPurposeId OIDs
     */
    extendedKeyUsage: ReadonlyArray<string> | null;
    subjectAltNames: SubjectAltNames;
    subjectKeyIdentifier: Uint8Array | null;
    /**
     * keyIdentifier field only
     */
    authorityKeyIdentifier: Uint8Array | null;
    nameConstraints: NameConstraints | null;
    /**
     * OIDs path.js must reject on
     */
    unknownCriticalExtensions: ReadonlyArray<string>;
    /**
     * subject DER equals issuer DER
     */
    isSelfIssued: boolean;
};
