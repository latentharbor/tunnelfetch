// TLS 1.2 client handshake driver.
//
// This driver exists for servers that never learned TLS 1.3; it is a fallback, not a peer of
// handshake.js in importance, but it must meet exactly the same bar: on this runtime nothing
// below us verifies a tunnelled peer, so every guarantee the caller gets is manufactured here.
// The negotiable surface is deliberately tiny — ECDHE key exchange and AES-GCM only (see
// constants.js for the reasoning) — and three refusals are absolute:
//
//   * No renegotiation. A HelloRequest at any point is an error, never a trigger. Renegotiation
//     is the mechanism behind the 2009 prefix-injection MITM (CVE-2009-3555), and a client that
//     only ever dials out has no legitimate use for it.
//   * No resumption. We send a throwaway session id (middlebox camouflage, same as 1.3); a
//     server echoing it announces an abbreviated handshake that skips authentication, which is
//     not a handshake we are willing to have. Every connection pays for the full flight.
//   * No ServerKeyExchange, no connection. Without it there is no ephemeral key: the selected
//     suite would degenerate into static key transport with no forward secrecy, which this
//     package refuses to implement.
//
// Two ordering rules are load-bearing, mirroring the 1.3 driver:
//
//   1. The certificate chain is validated by the injected trust layer BEFORE the
//      ServerKeyExchange signature is checked against the leaf's key, and both happen before any
//      key material or Finished leaves this side. Signature-then-trust would only prove that
//      whoever holds the socket also holds a key — no evidence at all.
//   2. TLS 1.2 signs only client_random || server_random || ServerECDHParams — the ServerHello
//      and the chosen suite are NOT covered by that signature, only (eventually) by Finished. So
//      the transcript must be byte-exact at both Finished computations, and when the server
//      supports extended master secret (RFC 7627) the master secret itself is bound to the
//      session hash, closing the triple-handshake gap that the plain randoms-based derivation
//      leaves open. EMS is preferred whenever offered back; a server that declines is accepted,
//      but the downgrade is reported in info.extendedMasterSecret so callers can see it.
//
// The ClientHello/ServerHello preamble lives in connect.js, shared with the 1.3 driver so that
// one hello can offer both versions; continueTls12 below is everything that happens after the
// ServerHello routed the connection here. handshakeTls12 remains the single-version entry: it is
// connectTls with the offer pinned to [TLS 1.2], which keeps the hello free of every 1.3
// extension exactly as this driver always sent it.
//
// Verification is injected rather than imported, for the same reasons as the 1.3 driver: this
// module holds no trust policy, and the handshake must be replayable offline.

import { TlsError, TlsUnsupportedError, codes, hex8, hex16 } from '../errors.js';
import {
  CIPHER_NAME,
  EXTENSION,
  HANDSHAKE_TYPE,
  SIG_SCHEME,
  TLS12,
} from './constants.js';
import {
  extendedMasterSecret12,
  keyBlock12,
  masterSecret12,
  verifyData12,
} from './keyschedule.js';
import {
  buildClientKeyExchange,
  buildFinished,
  checkAlpn,
  checkFinished,
  deriveSharedSecret,
  generateKeyShare,
  parseCertificate12,
  parseServerKeyExchangeEcdhe,
  serverKeyExchangeContent,
  verifyHandshakeSignature,
} from './handshake-messages.js';
import { describeSigScheme, rejectUnofferedExtensions } from './extensions.js';
import { equal } from '../util/bytes.js';
import { handshakeMessage, vector } from './wire.js';
import { connectTls } from './connect.js';

const HS_NAME = Object.fromEntries(Object.entries(HANDSHAKE_TYPE).map(([k, v]) => [v, k]));

/** HelloRequest has no entry in HANDSHAKE_TYPE because no other module may ever act on one. */
const HELLO_REQUEST = 0;

const describeType = (t) => `${hex8(t)} (${HS_NAME[t] ?? 'unknown'})`;
const describeSuite = (s) => `${hex16(s)}${CIPHER_NAME[s] ? ` (${CIPHER_NAME[s]})` : ''}`;

/**
 * Which authentication family a signature scheme proves. The cipher suite name pins the server
 * certificate's key type (ECDHE_RSA vs ECDHE_ECDSA, with EdDSA folded into the ECDSA family by
 * RFC 8422 s5.10), but the ServerKeyExchange signature does not cover the ServerHello — so this
 * check is the only thing tying the signature algorithm to the suite the server claims to be
 * honouring until Finished lands.
 */
const SIG_KIND = {
  [SIG_SCHEME.ecdsa_secp256r1_sha256]: 'ecdsa',
  [SIG_SCHEME.ecdsa_secp384r1_sha384]: 'ecdsa',
  [SIG_SCHEME.ecdsa_secp521r1_sha512]: 'ecdsa',
  [SIG_SCHEME.ed25519]: 'ecdsa',
  [SIG_SCHEME.rsa_pkcs1_sha256]: 'rsa',
  [SIG_SCHEME.rsa_pkcs1_sha384]: 'rsa',
  [SIG_SCHEME.rsa_pkcs1_sha512]: 'rsa',
  [SIG_SCHEME.rsa_pss_rsae_sha256]: 'rsa',
  [SIG_SCHEME.rsa_pss_rsae_sha384]: 'rsa',
  [SIG_SCHEME.rsa_pss_rsae_sha512]: 'rsa',
};

/**
 * The one refusal that must fire regardless of which message was expected. Exported for
 * connect.js, whose ServerHello wait is the earliest point a 1.2 server can spring one.
 */
export function refuseHelloRequest() {
  throw new TlsError(
    codes.TLS_HANDSHAKE,
    'server sent HelloRequest; renegotiation is refused. Renegotiation lets a MITM splice an ' +
      'attacker-controlled prefix onto the authenticated stream (CVE-2009-3555), and this ' +
      'client has no use for it',
    { type: HELLO_REQUEST },
  );
}

/** Demand a specific handshake message, turning every other outcome into a named failure. */
function expect(msg, type, where) {
  if (msg === null) {
    throw new TlsError(
      codes.TLS_TRUNCATED,
      `server closed the connection during the handshake while ${where} was expected`,
      { expected: HS_NAME[type] ?? type },
    );
  }
  if (msg.ccs) {
    throw new TlsError(codes.TLS_RECORD, `change_cipher_spec arrived where ${where} was expected`, {
      expected: HS_NAME[type] ?? type,
    });
  }
  if (msg.type === HELLO_REQUEST) refuseHelloRequest();
  if (msg.type !== type) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server sent handshake type ${describeType(msg.type)} where ${where} was expected`,
      { got: msg.type, expected: type },
    );
  }
  return msg;
}

/** Demand the server's ChangeCipherSpec, which in 1.2 is a real key-change signal. */
function expectCcs(msg) {
  if (msg === null) {
    throw new TlsError(
      codes.TLS_TRUNCATED,
      'server closed the connection while its ChangeCipherSpec was expected',
    );
  }
  if (msg.ccs) return;
  if (msg.type === HELLO_REQUEST) refuseHelloRequest();
  throw new TlsError(
    codes.TLS_HANDSHAKE,
    `server sent handshake type ${describeType(msg.type)} where its ChangeCipherSpec was ` +
      'expected; a Finished before the key change would arrive unprotected',
    { got: msg.type },
  );
}

/**
 * TLS carries ECDSA signatures as DER Ecdsa-Sig-Value (RFC 8422 s5.10), but WebCrypto verifies
 * the raw IEEE P1363 r||s form, each half left-padded to the curve order length. The conversion
 * is strict — every historical "accept sloppy DER" allowance became a signature-malleability
 * bug somewhere — and it rejects rather than truncates anything that does not parse exactly.
 * Exported for direct testing; SIG_SCHEME_PARAMS carries the per-scheme orderLen.
 */
export function ecdsaDerToRaw(sig, orderLen) {
  const fail = (why) => {
    throw new TlsError(codes.TLS_HANDSHAKE, `malformed DER ECDSA signature: ${why}`, {
      length: sig.byteLength,
    });
  };
  let pos = 0;
  const byte = () => {
    if (pos >= sig.byteLength) fail('truncated');
    return sig[pos++];
  };
  const length = () => {
    const first = byte();
    if (first < 0x80) return first;
    // Two INTEGERs of at most orderLen+1 bytes each never need more than one length octet.
    if (first !== 0x81) fail(`unsupported length form ${hex8(first)}`);
    const n = byte();
    if (n < 0x80) fail('non-minimal long-form length');
    return n;
  };
  if (byte() !== 0x30) fail('not a SEQUENCE');
  if (length() !== sig.byteLength - pos) fail('SEQUENCE length disagrees with the signature length');
  const integer = (name) => {
    if (byte() !== 0x02) fail(`${name} is not an INTEGER`);
    const n = length();
    if (n === 0) fail(`${name} is empty`);
    if (sig.byteLength - pos < n) fail(`${name} is truncated`);
    let v = sig.subarray(pos, pos + n);
    pos += n;
    if (v[0] & 0x80) fail(`${name} is negative`);
    if (n > 1 && v[0] === 0x00 && !(v[1] & 0x80)) fail(`${name} is not minimally encoded`);
    if (v[0] === 0x00) v = v.subarray(1);
    if (v.byteLength > orderLen) fail(`${name} is wider than the ${orderLen}-byte curve order`);
    return v;
  };
  const r = integer('r');
  const s = integer('s');
  if (pos !== sig.byteLength) fail('trailing bytes after s');
  const out = new Uint8Array(orderLen * 2);
  out.set(r, orderLen - r.byteLength);
  out.set(s, orderLen * 2 - s.byteLength);
  return out;
}

/**
 * Run a TLS 1.2 handshake over a byte duplex and return the plaintext duplex above it.
 *
 * @param {object} args
 * @param {{readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>}} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {(chain: Uint8Array[], hostname: string) => Promise<{spki: {spkiDer: Uint8Array}}>} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key this
 *   handshake will accept a ServerKeyExchange signature from.
 * @param {object} [args.options]
 * @param {{randomBytes?: (n:number)=>Uint8Array, generateKeyPair?: Function}} [args.deps]
 */
export async function handshakeTls12({ transport, hostname, verifyPeer, options = {}, deps = {} }) {
  if (typeof verifyPeer !== 'function') {
    // Refusing to start is the only safe default. A missing verifier must never read as "skip".
    throw new TlsError(
      codes.CONFIG_INVALID,
      'handshakeTls12 requires a verifyPeer function; there is no unverified mode',
    );
  }
  // The offer is pinned to [TLS 1.2]: no supported_versions, no key_share, no PSK modes. A
  // 1.3-capable ClientHello answered by this driver would mean the version dispatch above us
  // routed wrongly, and the 1.3 downgrade protections (sentinel, supported_versions echo) would
  // silently not apply — so the offer itself must make that state unrepresentable.
  return connectTls({
    transport,
    hostname,
    verifyPeer,
    deps,
    options: { ...options, versions: [TLS12] },
  });
}

/**
 * Continue a TLS 1.2 handshake from the ServerHello. Called by connect.js once negotiation
 * routed the connection here; `ctx` carries the record layer (already pinned to 1.2 semantics),
 * the transcript (created under the negotiated suite's PRF hash, ClientHello already folded in),
 * the ClientHello metadata, the parsed ServerHello with its raw bytes, and the offer.
 */
export async function continueTls12(ctx) {
  const { record, transcript, hello, serverHello: sh, rawServerHello, suite, params } = ctx;
  const { hostname, verifyPeer, deps } = ctx;
  const { alpn, groups } = ctx.offer;
  const hash = params.hash;

  // RFC 5246 s7.4.1.3: a server echoing the client's session id is announcing an abbreviated
  // handshake — ChangeCipherSpec and Finished next, no certificate, keys from a cached master
  // secret we do not hold. Ours is a throwaway id, so an echo is either a broken cache or an
  // attempt to skip authentication; the CCS guard below would catch the flight shape anyway,
  // but naming the cause here beats "change_cipher_spec arrived where Certificate was expected".
  if (
    hello.legacySessionId.byteLength > 0 &&
    equal(sh.legacySessionIdEcho, hello.legacySessionId)
  ) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'server echoed our session id, which announces an abbreviated (resumed) handshake; ' +
        'session resumption is not supported and the handshake is never abbreviated',
    );
  }

  // RFC 5246 s7.4.1.4: the ServerHello may only carry extensions the ClientHello offered. An
  // unoffered one (session_ticket is the classic) would commit us to protocol behaviour we do
  // not implement, so it is refused before any of its semantics can be presumed.
  rejectUnofferedExtensions(sh.extensions, hello.offeredExtensions, 'ServerHello');

  // When the ClientHello offered 1.3 as well, the 1.3-only extensions WERE offered, so the
  // check above can no longer catch a server echoing them while negotiating 1.2. RFC 8446
  // s4.1.4 permits key_share in a ServerHello only when 1.3 was selected, and
  // psk_key_exchange_modes may never appear in one at all; a server that answers the 1.3 half
  // of the offer while refusing the 1.3 that gives it meaning is confused at best and splicing
  // two handshakes at worst. (supported_versions cannot reach this driver: negotiateVersion
  // either routed it to 1.3 or refused it outright.)
  for (const type of [EXTENSION.key_share, EXTENSION.psk_key_exchange_modes]) {
    if (sh.extensions.has(type)) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `server echoed the TLS 1.3-only extension ${hex16(type)} in a ServerHello that ` +
          'negotiates TLS 1.2',
        { extension: type },
      );
    }
  }

  const reneg = sh.extensions.get(EXTENSION.renegotiation_info);
  if (reneg && !(reneg.byteLength === 1 && reneg[0] === 0x00)) {
    // RFC 5746 s3.4: on an initial handshake the server's renegotiated_connection must be
    // empty. Anything else means the server believes this connection is a renegotiation.
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'server sent a non-empty renegotiation_info, treating this connection as a ' +
        'renegotiation; renegotiation is refused',
      { length: reneg.byteLength },
    );
  }

  const emsEcho = sh.extensions.get(EXTENSION.extended_master_secret);
  if (emsEcho && emsEcho.byteLength !== 0) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `extended_master_secret extension_data must be empty, got ${emsEcho.byteLength} bytes`,
      { length: emsEcho.byteLength },
    );
  }
  const extendedMasterSecret = emsEcho !== undefined;

  // In 1.2 the ALPN answer lives in the ServerHello — there is no EncryptedExtensions.
  const alpnProtocol = checkAlpn(sh.extensions, alpn, 'ServerHello');
  transcript.update(rawServerHello);

  // --- server flight -------------------------------------------------------------------------
  const certMsg = expect(
    await record.nextHandshakeMessage(),
    HANDSHAKE_TYPE.certificate,
    'Certificate',
  );
  transcript.update(certMsg.raw);
  const chain = parseCertificate12(certMsg.body);

  let next = await record.nextHandshakeMessage();
  if (
    next !== null &&
    !next.ccs &&
    (next.type === HANDSHAKE_TYPE.certificate_request ||
      next.type === HANDSHAKE_TYPE.server_hello_done)
  ) {
    // The flight skipped straight past ServerKeyExchange. For every suite this package offers
    // that message carries the ephemeral key, so its absence is not a variant — it is the
    // server trying to run the suite as static key transport.
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server omitted ServerKeyExchange under ${describeSuite(suite)}. Every suite this ` +
        'package offers is ECDHE: without ServerKeyExchange there is no ephemeral key and no ' +
        'forward secrecy, and static-RSA key transport is deliberately not implemented',
      { cipherSuite: suite, got: next.type },
    );
  }
  const skeMsg = expect(next, HANDSHAKE_TYPE.server_key_exchange, 'ServerKeyExchange');
  transcript.update(skeMsg.raw);
  const ske = parseServerKeyExchangeEcdhe(skeMsg.body);
  if (!groups.includes(ske.group)) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server chose group ${hex16(ske.group)} in ServerKeyExchange, which was not offered in ` +
        'supported_groups',
      { group: ske.group },
    );
  }

  let certificateRequested = false;
  next = await record.nextHandshakeMessage();
  if (next !== null && !next.ccs && next.type === HANDSHAKE_TYPE.certificate_request) {
    // We hold no client certificate, so the body's demands are irrelevant — the answer is an
    // empty Certificate in the client flight either way (RFC 5246 s7.4.6) — but the message
    // still has to be remembered and folded into the transcript at this exact point.
    certificateRequested = true;
    transcript.update(next.raw);
    next = await record.nextHandshakeMessage();
  }
  const done = expect(next, HANDSHAKE_TYPE.server_hello_done, 'ServerHelloDone');
  if (done.body.byteLength !== 0) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `ServerHelloDone must have an empty body, got ${done.body.byteLength} bytes`,
      { length: done.body.byteLength },
    );
  }
  transcript.update(done.raw);

  // --- trust, then the ServerKeyExchange signature -------------------------------------------
  // Trust first. The signature check below is only meaningful once the key performing it has
  // been tied by the trust layer to a chain we accept for this hostname; done the other way
  // round it merely proves that whoever holds the socket also holds a key, which is no evidence
  // at all. Nothing of ours — no key share, no Finished — has been sent yet, so a failure here
  // leaks nothing but the ClientHello.
  const peer = await verifyPeer(chain, hostname);
  const spki = peer?.spki?.spkiDer;
  if (!spki) {
    throw new TlsError(
      codes.CONFIG_INVALID,
      'verifyPeer must resolve with the validated leaf certificate, including spki.spkiDer',
    );
  }

  const scheme = ske.signatureAlgorithm;
  if (!hello.offeredSigSchemes.includes(scheme)) {
    // RFC 5246 s7.4.3: the server must sign with an algorithm from our signature_algorithms.
    throw new TlsUnsupportedError(
      codes.TLS_SIGALG_UNSUPPORTED,
      `server signed ServerKeyExchange with ${describeSigScheme(scheme)}, which was not ` +
        'offered in signature_algorithms',
      { scheme },
    );
  }
  if (SIG_KIND[scheme] !== params.sig) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `cipher suite ${describeSuite(suite)} authenticates with ${params.sig}, but ` +
        `ServerKeyExchange is signed with ${describeSigScheme(scheme)}`,
      { cipherSuite: suite, scheme },
    );
  }
  // The signature goes to verifyHandshakeSignature in the form it arrived in. That function owns
  // the DER-to-P1363 conversion for ECDSA, so both handshake drivers share one implementation of
  // it — converting here as well would hand it an already-converted signature to re-parse.
  await verifyHandshakeSignature({
    scheme,
    spki,
    signature: ske.signature,
    content: serverKeyExchangeContent(hello.clientRandom, sh.random, ske.signedParams),
  });

  // --- key exchange --------------------------------------------------------------------------
  // The server's point is validated (length, uncompressed form, on-curve via the WebCrypto
  // import) before anything of ours goes on the wire.
  const share = await generateKeyShare(ske.group, deps);
  const preMaster = await deriveSharedSecret(ske.group, share.privateKey, ske.publicKey);

  // --- client flight -------------------------------------------------------------------------
  const clientFlight = [];
  if (certificateRequested) {
    // RFC 5246 s7.4.6: no credentials means a Certificate message with an empty
    // certificate_list — and, because the list is empty, no CertificateVerify afterwards.
    const empty = handshakeMessage(HANDSHAKE_TYPE.certificate, vector(3, new Uint8Array(0)));
    clientFlight.push(empty);
    transcript.update(empty);
  }
  const cke = buildClientKeyExchange(share.keyExchange);
  clientFlight.push(cke);
  transcript.update(cke);
  await record.writeHandshake(clientFlight);

  // RFC 7627: with EMS the master secret is bound to the session hash — the transcript through
  // ClientKeyExchange, hashed right here, before Finished joins it — so it cannot be replayed
  // onto a different handshake (the triple-handshake attack). Without the extension the RFC 5246
  // derivation over the two randoms is all there is; that acceptance is recorded in
  // info.extendedMasterSecret rather than hidden.
  const master = extendedMasterSecret
    ? await extendedMasterSecret12(hash, preMaster, await transcript.hash())
    : await masterSecret12(hash, preMaster, hello.clientRandom, sh.random);

  // RFC 5246 s6.3 puts MAC keys first in the key_block, but AEAD suites have none — a stray
  // MAC-key slot would silently shift every later slice into the wrong bytes, so the layout is
  // asserted rather than trusted.
  const kb = await keyBlock12(hash, master, hello.clientRandom, sh.random, {
    keyLen: params.keyLen,
    fixedIvLen: params.fixedIvLen,
  });
  if (
    kb.clientWriteMacKey !== undefined ||
    kb.clientWriteKey.byteLength !== params.keyLen ||
    kb.serverWriteKey.byteLength !== params.keyLen ||
    kb.clientWriteIv.byteLength !== params.fixedIvLen ||
    kb.serverWriteIv.byteLength !== params.fixedIvLen
  ) {
    throw new TlsError(
      codes.CONFIG_INVALID,
      'key_block layout is wrong for an AEAD suite; a MAC-key slot would shift every slice',
      { cipherSuite: suite },
    );
  }

  // Our ChangeCipherSpec, then Finished under the new keys. The verify_data covers everything
  // through ClientKeyExchange; the Finished message itself then joins the transcript because
  // the server's Finished must cover ours (RFC 5246 s7.4.9).
  await record.writeChangeCipherSpec();
  await record.setSendKeys({ cipher: suite, key: kb.clientWriteKey, iv: kb.clientWriteIv });
  const finished = buildFinished(
    await verifyData12(hash, master, 'client finished', await transcript.hash()),
  );
  transcript.update(finished);
  await record.writeHandshake([finished]);

  // --- server ChangeCipherSpec and Finished --------------------------------------------------
  // The {ccs: true} event is the record layer telling us the peer switched keys — a real
  // signal in 1.2, unlike the 1.3 compatibility noise — and receive keys are installed only in
  // response to it. The record layer separately guarantees no handshake message spans the
  // change and that a second CCS (renegotiation's opening move) is fatal.
  expectCcs(await record.nextHandshakeMessage());
  await record.setReceiveKeys({ cipher: suite, key: kb.serverWriteKey, iv: kb.serverWriteIv });

  const sf = expect(await record.nextHandshakeMessage(), HANDSHAKE_TYPE.finished, 'server Finished');
  checkFinished(sf.body, await verifyData12(hash, master, 'server finished', await transcript.hash()));

  record.markHandshakeComplete();
  const duplex = record.plaintextDuplex();
  return {
    readable: duplex.readable,
    writable: duplex.writable,
    record,
    peer,
    info: {
      version: TLS12,
      cipherSuite: suite,
      group: ske.group,
      alpnProtocol: alpnProtocol ?? null,
      certificateRequested,
      extendedMasterSecret,
      hostname,
    },
    close: () => record.close(),
  };
}
