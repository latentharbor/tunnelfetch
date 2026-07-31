export const WARMUP_HOSTNAME: "warmup.invalid";
export const WARMUP_NOW: 1893456000000;
export namespace WARMUP_FIXTURE {
    function clientPrivPkcs8(): Uint8Array<ArrayBuffer>;
    function clientPubRaw(): Uint8Array<ArrayBuffer>;
    function clientRandom(): Uint8Array<ArrayBuffer>;
    function legacySessionId(): Uint8Array<ArrayBuffer>;
    function clientHello(): Uint8Array<ArrayBuffer>;
    function serverBytes(): Uint8Array<ArrayBuffer>;
    function rootDer(): Uint8Array<ArrayBuffer>;
}
