/**
 * Parse a DER OCSPResponse (RFC 6960 s4.2.1) into a fully-walked structure.
 *
 * A parser, not a judge, exactly like parseCertificate: it throws OCSP_PARSE on malformed or
 * self-contradictory bytes and on constructs this package refuses to interpret (unknown
 * responseType, unrecognized critical extensions); whether the parsed response is TRUE is
 * verifyOcspStaple's problem.
 *
 * @param {Uint8Array} der
 * @returns {OcspResponse}
 */
export function parseOcspResponse(der: Uint8Array): OcspResponse;
/**
 * Verify a stapled OCSP response against the certificate it must vouch for.
 *
 * Every check the module comment promises happens here, in this order: parse, match the CertID
 * to `leaf`/`issuer`, establish the signer (the CA itself or an RFC 6960 s4.2.2.2 delegated
 * responder), verify the signature over the original tbsResponseData bytes, and only then read
 * the verdict and its freshness window. `revoked` and `unknown` always throw; `good` throws
 * unless the window covers `now`.
 *
 * @param {object} args
 * @param {Uint8Array} args.staple DER OCSPResponse, exactly as the peer stapled it
 * @param {import('./x509.js').Certificate} args.leaf the validated leaf the staple must cover
 * @param {OcspIssuer} args.issuer the leaf's issuer, from the validated path
 * @param {number} args.now epoch ms, injected — never a wall clock read here
 * @returns {Promise<OcspVerdict>} every failure throws a typed CertificateError (OCSP_* codes)
 */
export function verifyOcspStaple({ staple, leaf, issuer, now }: {
    staple: Uint8Array;
    leaf: import("./x509.js").Certificate;
    issuer: OcspIssuer;
    now: number;
}): Promise<OcspVerdict>;
/**
 * CertID (RFC 6960 s4.1.1): which certificate a SingleResponse is talking about.
 */
export type OcspCertId = {
    hashOid: string;
    issuerNameHash: Uint8Array;
    issuerKeyHash: Uint8Array;
    /**
     * INTEGER content bytes, minimal DER
     */
    serialBytes: Uint8Array;
};
/**
 * One SingleResponse, parsed. Times are epoch ms.
 */
export type OcspSingleResponse = {
    certId: OcspCertId;
    status: {
        kind: "good";
    } | {
        kind: "unknown";
    } | {
        kind: "revoked";
        revocationTime: number;
        reason: number | null;
    };
    thisUpdate: number;
    nextUpdate: number | null;
};
/**
 * A parsed BasicOCSPResponse. `tbsBytes` is the exact original ResponseData element — the bytes
 * the signature covers, never re-encoded.
 */
export type OcspBasicResponse = {
    tbsBytes: Uint8Array;
    signatureAlgorithm: import("./x509.js").AlgorithmId;
    signature: Uint8Array;
    responderId: {
        kind: "name";
        nameBytes: Uint8Array;
    } | {
        kind: "key";
        keyHash: Uint8Array;
    };
    /**
     * epoch ms
     */
    producedAt: number;
    singles: OcspSingleResponse[];
    /**
     * attached responder certificates, parsed
     */
    certs: import("./x509.js").Certificate[];
};
export type OcspResponse = {
    responseStatus: number;
    responseStatusName: string;
    /**
     * null exactly when responseStatus != successful
     */
    basic: OcspBasicResponse | null;
};
/**
 * The issuer of the certificate under check, reduced to what OCSP verification needs. Built by
 * the caller from the VALIDATED path — the certificate that actually signed the leaf, or the
 * trust anchor when the leaf sits directly under one — never from the unverified wire chain.
 */
export type OcspIssuer = {
    /**
     * exact subject Name DER
     */
    subjectBytes: Uint8Array;
    /**
     * SubjectPublicKeyInfo DER
     */
    spkiDer: Uint8Array;
    /**
     * for error messages
     */
    subjectText: string;
};
/**
 * What a verified `good` staple reports. Every other outcome throws; there is no boolean.
 */
export type OcspVerdict = {
    status: "good";
    /**
     * epoch ms
     */
    producedAt: number;
    /**
     * epoch ms
     */
    thisUpdate: number;
    /**
     * epoch ms
     */
    nextUpdate: number | null;
    /**
     * whether a delegated responder certificate signed, rather than
     * the CA key itself
     */
    delegated: boolean;
};
