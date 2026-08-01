// TLS handshake message parsing. These run on bytes that arrive BEFORE the peer has been
// authenticated — the ServerHello that picks the version and cipher, the Certificate message that
// carries the chain, the CertificateVerify that is supposed to prove possession of its key. There
// is no earlier check to fall back on: whatever these parsers do with hostile input is the first
// thing that happens.

import {
  parseServerHello,
  parseNewSessionTicket,
  parseCertificateStatus,
  parseCertificate13,
  parseCertificate12,
  parseCertificateVerify,
  parseServerKeyExchangeEcdhe,
} from '../../../src/tls/handshake-messages.js';
import { TlsError } from '../../../src/errors.js';
import { RFC8448_1RTT } from '../../tls/_vectors.js';
import { caFixture } from '../../trust/_certs.js';

const fx = caFixture();
const u16 = (n) => [n >> 8, n & 0xff];
const u24 = (n) => [n >> 16, (n >> 8) & 0xff, n & 0xff];

/** A TLS 1.3 Certificate body: context, then a CertificateList of (cert, extensions) entries. */
function certificate13Body(ders) {
  const entries = ders.flatMap((d) => [...u24(d.length), ...d, ...u16(0)]);
  return Uint8Array.from([0, ...u24(entries.length), ...entries]);
}

/** A TLS 1.2 Certificate body: one length-prefixed list of length-prefixed certificates. */
function certificate12Body(ders) {
  const list = ders.flatMap((d) => [...u24(d.length), ...d]);
  return Uint8Array.from([...u24(list.length), ...list]);
}

// The ServerHello vector is the handshake message with its 4-byte header; the parsers take bodies.
const serverHelloBody = RFC8448_1RTT.serverHello.subarray(4);
const chain = [fx.leaf.der, fx.intermediate.der];

export default {
  name: 'tls.handshakeMessages',
  corpus: [
    serverHelloBody,
    certificate13Body(chain),
    certificate12Body(chain),
    // CertificateVerify: scheme + length-prefixed signature.
    Uint8Array.from([0x08, 0x04, ...u16(64), ...new Uint8Array(64).fill(0x5a)]),
    // NewSessionTicket: lifetime, age_add, nonce, ticket, extensions.
    Uint8Array.from([0, 0, 0x1c, 0x20, 0, 0, 0, 0, 8, ...new Uint8Array(8).fill(1),
      ...u16(16), ...new Uint8Array(16).fill(2), ...u16(0)]),
    // CertificateStatus: type 1 (ocsp) + a 3-byte-length OCSP response.
    Uint8Array.from([1, ...u24(8), ...new Uint8Array(8).fill(0x30)]),
    // ServerKeyExchange, named_curve + a P-256 point, then scheme and signature.
    Uint8Array.from([3, ...u16(23), 65, 4, ...new Uint8Array(64).fill(7),
      0x04, 0x03, ...u16(70), ...new Uint8Array(70).fill(0x30)]),
  ],
  // Every parser sees every case: which message a byte string "is" is exactly what an attacker
  // gets to lie about, and a parser must refuse input shaped for a different message rather than
  // read it as its own.
  run: (input) => {
    let accepted = false;
    let refusal = null;
    for (const parse of [
      parseServerHello,
      parseNewSessionTicket,
      parseCertificateStatus,
      parseCertificate13,
      parseCertificate12,
      parseCertificateVerify,
      (b) => parseServerKeyExchangeEcdhe(b, 0x0303),
    ]) {
      try {
        parse(input);
        accepted = true;
      } catch (err) {
        // An untyped throw is the finding; surface it at once, from the parser that produced it.
        if (!(err instanceof TlsError)) throw err;
        refusal = err;
      }
    }
    // Every parser refused, which is the normal outcome once a mutation has broken the shape. Pass
    // one refusal up so the engine records a rejection: swallowing them all made every case look
    // ACCEPTED, and the engine's own "no input was ever rejected" guard caught that — which is
    // what that guard is for.
    if (!accepted && refusal) throw refusal;
  },
};
