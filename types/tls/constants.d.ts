export namespace RECORD_TYPE {
    let change_cipher_spec: number;
    let alert: number;
    let handshake: number;
    let application_data: number;
}
export namespace HANDSHAKE_TYPE {
    let client_hello: number;
    let server_hello: number;
    let new_session_ticket: number;
    let end_of_early_data: number;
    let encrypted_extensions: number;
    let certificate: number;
    let server_key_exchange: number;
    let certificate_request: number;
    let server_hello_done: number;
    let certificate_verify: number;
    let client_key_exchange: number;
    let finished: number;
    let certificate_status: number;
    let key_update: number;
    let message_hash: number;
}
/** Legacy record-layer version. Always 0x0303 on the wire after ClientHello (RFC 8446 s5.1). */
export const LEGACY_VERSION: 771;
export const TLS12: 771;
export const TLS13: 772;
export const VERSION_NAME: {
    768: string;
    769: string;
    770: string;
    771: string;
    772: string;
};
export namespace EXTENSION {
    let server_name: number;
    let status_request: number;
    let supported_groups: number;
    let ec_point_formats: number;
    let signature_algorithms: number;
    let alpn: number;
    let signed_certificate_timestamp: number;
    let extended_master_secret: number;
    let session_ticket: number;
    let pre_shared_key: number;
    let early_data: number;
    let supported_versions: number;
    let cookie: number;
    let psk_key_exchange_modes: number;
    let certificate_authorities: number;
    let signature_algorithms_cert: number;
    let key_share: number;
    let renegotiation_info: number;
}
export namespace CIPHER {
    let TLS_AES_128_GCM_SHA256: number;
    let TLS_AES_256_GCM_SHA384: number;
    let TLS_CHACHA20_POLY1305_SHA256: number;
    let TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: number;
    let TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: number;
    let TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: number;
    let TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: number;
}
/** Reverse map for error messages. A server that picks something unlisted still gets a hex code. */
export const CIPHER_NAME: {
    [k: string]: string;
};
/** Offered in ClientHello, in preference order. */
export const TLS13_CIPHERS: number[];
/**
 * curl 8.21.0 / OpenSSL 3.6.3 offers its TLS 1.3 suites in this exact order — AES-256-GCM,
 * ChaCha20-Poly1305, AES-128-GCM — captured off the wire 2026-08-01 (`0x1302 0x1303 0x1301`).
 * ChaCha20 is SECOND, right after AES-256-GCM; that is "curl's position" for it.
 *
 * TLS13_CIPHERS above leads with AES-128, which is the order this package has always offered and
 * which the offline test server keys its default suite selection off; reordering it would change
 * the negotiated suite across the whole suite. So this curl-faithful order is used ONLY when a
 * ChaCha20 implementation has been injected — i.e. when the caller has opted into being able to
 * perform every suite curl offers — and never otherwise. See connect.js.
 */
export const TLS13_CIPHERS_WITH_CHACHA: number[];
export const TLS12_CIPHERS: number[];
/**
 * Per-suite parameters. `hash` drives the whole key schedule; `keyLen` the AEAD key size.
 * @typedef {object} CipherParams
 * @property {'SHA-256' | 'SHA-384'} hash the only hashes any negotiable suite selects
 * @property {number} hashLen
 * @property {number} keyLen
 * @property {number} ivLen
 * @property {number} tagLen
 * @property {number} [fixedIvLen] TLS 1.2 only: the 4-byte implicit GCM salt of RFC 5288
 * @property {'ecdsa' | 'rsa'} [sig] TLS 1.2 only: the authentication family the suite names
 */
/** @type {{ [suite: number]: CipherParams }} */
export const CIPHER_PARAMS: {
    [suite: number]: CipherParams;
};
export namespace GROUP {
    let secp256r1: number;
    let secp384r1: number;
    let secp521r1: number;
    let x25519: number;
    let x448: number;
    let ffdhe2048: number;
    let x25519mlkem768: number;
}
export const GROUP_NAME: {
    [k: string]: string;
};
/**
 * Offered in preference order. X25519 first because it is the modern default and the runtime's
 * WebCrypto has it; secp256r1 second because RFC 8446 s9.1 makes it mandatory to implement, so
 * offering both means no compliant server can fail to find a match.
 */
export const SUPPORTED_GROUPS: number[];
/**
 * WebCrypto parameters per group, discriminated on `kind` because X25519 sizes its shared
 * secret in bytes while ECDH sizes it in bits, and the ML-KEM hybrid is not a WebCrypto
 * primitive at all — it carries wire sizes only, and hybrid.js owns the crypto.
 * @typedef {{ kind: 'x25519', algorithm: { name: string }, publicLen: number, secretLen: number }
 *   | { kind: 'ec', algorithm: { name: string, namedCurve: string }, publicLen: number,
 *       secretBits: number }
 *   | { kind: 'hybrid', clientShareLen: number, serverShareLen: number, secretLen: number,
 *       mlkemPublicLen: number, mlkemSecretKeyLen: number, mlkemCiphertextLen: number,
 *       classicalPublicLen: number, classicalSecretLen: number }} GroupParams
 */
/**
 * WebCrypto parameters per group. x448 and the finite-field groups are absent by design.
 * @type {{ [group: number]: GroupParams }}
 */
export const GROUP_PARAMS: {
    [group: number]: GroupParams;
};
export namespace SIG_SCHEME {
    let rsa_pkcs1_sha256: number;
    let rsa_pkcs1_sha384: number;
    let rsa_pkcs1_sha512: number;
    let ecdsa_secp256r1_sha256: number;
    let ecdsa_secp384r1_sha384: number;
    let ecdsa_secp521r1_sha512: number;
    let rsa_pss_rsae_sha256: number;
    let rsa_pss_rsae_sha384: number;
    let rsa_pss_rsae_sha512: number;
    let ed25519: number;
    let ed448: number;
    let rsa_pss_pss_sha256: number;
    let rsa_pss_pss_sha384: number;
    let rsa_pss_pss_sha512: number;
    let rsa_pkcs1_sha1: number;
    let ecdsa_sha1: number;
}
export const SIG_SCHEME_NAME: {
    [k: string]: string;
};
/**
 * Offered in signature_algorithms. SHA-1 schemes are deliberately absent: they are forbidden in
 * TLS 1.3 handshake signatures and are not worth accepting in 1.2 either.
 */
export const SUPPORTED_SIG_SCHEMES: number[];
/**
 * How to verify one signature scheme with WebCrypto. `format: 'ecdsa-der'` marks the schemes
 * whose wire signatures need the DER-to-P1363 conversion before subtle.verify will take them.
 * @typedef {object} SigSchemeParams
 * @property {{ name: string, namedCurve?: string, hash?: string }} import importKey algorithm
 * @property {{ name: string, hash?: string, saltLength?: number }} verify verify() algorithm
 * @property {'ecdsa-der'} [format]
 * @property {number} [curveOrderLen] byte width of the curve order, ECDSA only
 */
/**
 * How to verify each scheme with WebCrypto. Absent entries are rejected with a named error.
 * @type {{ [scheme: number]: SigSchemeParams }}
 */
export const SIG_SCHEME_PARAMS: {
    [scheme: number]: SigSchemeParams;
};
export namespace ALERT_LEVEL {
    let warning: number;
    let fatal: number;
}
export const ALERT_DESC: {
    0: string;
    10: string;
    20: string;
    21: string;
    22: string;
    40: string;
    41: string;
    42: string;
    43: string;
    44: string;
    45: string;
    46: string;
    47: string;
    48: string;
    49: string;
    50: string;
    51: string;
    70: string;
    71: string;
    80: string;
    86: string;
    90: string;
    109: string;
    110: string;
    112: string;
    113: string;
    115: string;
    116: string;
    120: string;
};
/** RFC 8446 s5.1: plaintext fragments are at most 2^14 bytes; ciphertext adds at most 256. */
export const MAX_PLAINTEXT: number;
export const MAX_CIPHERTEXT: number;
/** The only protocol we will negotiate. Offering h2 we cannot speak would be a footgun. */
export const ALPN_HTTP11: "http/1.1";
/**
 * RFC 8446 s4.1.3: a TLS 1.2 server that is really 1.3-aware signals a downgrade attempt by
 * planting these in the last 8 bytes of ServerHello.random. A 1.3-capable client that lands on
 * 1.2 must abort when it sees them.
 */
export const DOWNGRADE_SENTINEL_12: Uint8Array<ArrayBuffer>;
export const DOWNGRADE_SENTINEL_11: Uint8Array<ArrayBuffer>;
/** RFC 8446 s4.1.3: HelloRetryRequest is a ServerHello whose random is this fixed value. */
export const HELLO_RETRY_REQUEST_RANDOM: Uint8Array<ArrayBuffer>;
/**
 * Per-suite parameters. `hash` drives the whole key schedule; `keyLen` the AEAD key size.
 */
export type CipherParams = {
    /**
     * the only hashes any negotiable suite selects
     */
    hash: "SHA-256" | "SHA-384";
    hashLen: number;
    keyLen: number;
    ivLen: number;
    tagLen: number;
    /**
     * TLS 1.2 only: the 4-byte implicit GCM salt of RFC 5288
     */
    fixedIvLen?: number | undefined;
    /**
     * TLS 1.2 only: the authentication family the suite names
     */
    sig?: "ecdsa" | "rsa" | undefined;
};
/**
 * WebCrypto parameters per group, discriminated on `kind` because X25519 sizes its shared
 * secret in bytes while ECDH sizes it in bits, and the ML-KEM hybrid is not a WebCrypto
 * primitive at all — it carries wire sizes only, and hybrid.js owns the crypto.
 */
export type GroupParams = {
    kind: "x25519";
    algorithm: {
        name: string;
    };
    publicLen: number;
    secretLen: number;
} | {
    kind: "ec";
    algorithm: {
        name: string;
        namedCurve: string;
    };
    publicLen: number;
    secretBits: number;
} | {
    kind: "hybrid";
    clientShareLen: number;
    serverShareLen: number;
    secretLen: number;
    mlkemPublicLen: number;
    mlkemSecretKeyLen: number;
    mlkemCiphertextLen: number;
    classicalPublicLen: number;
    classicalSecretLen: number;
};
/**
 * How to verify one signature scheme with WebCrypto. `format: 'ecdsa-der'` marks the schemes
 * whose wire signatures need the DER-to-P1363 conversion before subtle.verify will take them.
 */
export type SigSchemeParams = {
    /**
     * importKey algorithm
     */
    import: {
        name: string;
        namedCurve?: string;
        hash?: string;
    };
    /**
     * verify() algorithm
     */
    verify: {
        name: string;
        hash?: string;
        saltLength?: number;
    };
    format?: "ecdsa-der" | undefined;
    /**
     * byte width of the curve order, ECDSA only
     */
    curveOrderLen?: number | undefined;
};
