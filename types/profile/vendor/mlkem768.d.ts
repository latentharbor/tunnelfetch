export const buildId: "e17c38843d1e";
export namespace mlkem768 {
    export { PK_B as publicKeyBytes };
    export { SK_B as secretKeyBytes };
    export { CT_B as cipherTextBytes };
    export let sharedSecretBytes: number;
    /** keygen(seed?) — seed is d||z (64 bytes) for ML-KEM.KeyGen_internal; omitted = fresh CSPRNG */
    export function keygen(seed: any): {
        publicKey: Uint8Array<ArrayBuffer>;
        secretKey: Uint8Array<ArrayBuffer>;
    };
    /** encapsulate(publicKey, msg?) — msg is m (32 bytes) for ML-KEM.Encaps_internal */
    export function encapsulate(publicKey: any, msg: any): {
        cipherText: Uint8Array<ArrayBuffer>;
        sharedSecret: Uint8Array<ArrayBuffer>;
    };
    /** decapsulate(cipherText, secretKey) -> sharedSecret (implicit rejection per FIPS 203) */
    export function decapsulate(cipherText: any, secretKey: any): Uint8Array<ArrayBuffer>;
}
declare const PK_B: any;
declare const SK_B: any;
declare const CT_B: any;
export {};
