/** Where these anchors came from. */
export const provenance: Readonly<{
    source: "ccadb:IncludedRootsPEMTxt?TrustBitsInclude=Websites";
    retrievedAt: "2026-07-30";
    upstreamSha256: "1813222850e0d3efb875b2978e61acbcb5fcdce93d5c4358443050e9659394bd";
    anchorCount: 121;
}>;
export namespace systemAnchors {
    /**
     * @param {Uint8Array} dnBytes exact subject DN DER of the issuer being resolved
     * @returns {Promise<StoredAnchor[]>}
     */
    function forIssuer(dnBytes: Uint8Array): Promise<StoredAnchor[]>;
}
export type PackedAnchor = {
    name: string;
    s: string;
    spki: string;
    ski: string | null;
    nc: string | null;
    nb: number;
    na: number;
};
/**
 * An unpacked anchor record, shaped for path validation's normalizeAnchor: name constraints
 * stay raw (`nameConstraintsBytes`) so only the anchor a handshake lands on pays for parsing.
 */
export type StoredAnchor = {
    subjectText: string;
    subjectBytes: Uint8Array;
    spkiDer: Uint8Array;
    subjectKeyIdentifier: Uint8Array | null;
    nameConstraintsBytes: Uint8Array | null;
    notBefore: number;
    notAfter: number;
};
