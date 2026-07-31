// HTTP/2 (RFC 9113) over a byte duplex: frame layer, HPACK (RFC 7541), and the multiplexing
// connection engine. This barrel is the layer's public face; client.js drives it, and the pieces
// are individually importable for testing.
//
// The whole reason this exists is access, not speed: some sites treat HTTP/1.1 as a bot signal and
// let curl's HTTP/2 through, so the client posture here is matched to curl's on the wire. It is not
// a performance win on a CPU-billed runtime — HPACK is work HTTP/1.1 does not do. See the README.

export { Http2Connection, Http2Retryable, buildRequestFields } from './connection.js';
export { HpackDecoder, encodeHeaderBlock } from './hpack.js';
export { huffmanDecode, huffmanEncode } from './huffman.js';
export {
  readFrame,
  serializeFrame,
  settingsFrame,
  windowUpdateFrame,
  dataFrame,
  headersFrame,
  parseSettings,
} from './frames.js';
export { ALPN_H2, ALPN_HTTP11 } from './constants.js';
