// The TLS layer as a standalone transport: give it a byte duplex, get a plaintext one back.
//
// Exported separately because the layering is the point — anyone with a socket-shaped thing and a
// trust policy can use this without the HTTP client above it, and every layer in this package is
// testable over an in-memory pipe for exactly that reason.

export { connectTls } from './connect.js';
export { handshakeTls13 } from './handshake.js';
export { handshakeTls12 } from './handshake12.js';
export { RecordLayer } from './record.js';
export { Transcript } from './transcript.js';
export { createAead, buildNonce } from './aead.js';

export {
  ALPN_HTTP11,
  CIPHER,
  CIPHER_NAME,
  CIPHER_PARAMS,
  GROUP,
  GROUP_NAME,
  SIG_SCHEME,
  SIG_SCHEME_NAME,
  SUPPORTED_GROUPS,
  SUPPORTED_SIG_SCHEMES,
  TLS12,
  TLS12_CIPHERS,
  TLS13,
  TLS13_CIPHERS,
  VERSION_NAME,
} from './constants.js';

export {
  buildClientHello,
  deriveSharedSecret,
  generateKeyShare,
  negotiateCipher,
  negotiateVersion,
  parseServerHello,
  verifyHandshakeSignature,
} from './handshake-messages.js';
