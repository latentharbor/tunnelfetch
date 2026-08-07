/**
 * Wrap a proxy handshake's buffered reader plus its socket as one byte stream.
 *
 * @param {{ readable: ReadableStream<Uint8Array> }} socket the raw transport
 * @param {import('../util/bytes.js').ByteReader} reader the handshake's reader, possibly holding
 *   bytes that belong to the tunnel
 * @returns {ReadableStream<Uint8Array>}
 */
export function tunnelReadable(socket: {
    readable: ReadableStream<Uint8Array>;
}, reader: import("../util/bytes.js").ByteReader): ReadableStream<Uint8Array>;
