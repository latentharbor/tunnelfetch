// TLS 1.3 client handshake driver.
//
// This is the file that has to be right. On this runtime the platform will not verify a tunnelled
// peer for us — it checks the certificate against whatever hostname was passed to connect(), which
// inside a proxy tunnel is the proxy, so the platform's own answer is structurally the wrong
// question. Everything protecting the caller from a hostile proxy therefore happens here and in
// the trust layer, and nothing may reach the application before it has.
//
// Three ordering rules are load-bearing:
//
//   1. The certificate chain is validated, and CertificateVerify checked against the very key that
//      validation blessed, BEFORE the client's Finished is sent and before any application byte
//      moves in either direction. No code path returns a usable duplex otherwise.
//   2. Every message is folded into the transcript at the exact point RFC 8446 says. The
//      transcript is what binds the certificate to this connection; an off-by-one-message
//      transcript still looks like a working handshake against an honest server and provides no
//      security at all against a dishonest one.
//   3. The transcript's hash is chosen by the cipher suite, which is not known until ServerHello.
//      So ClientHello is held as raw bytes and the transcript is constructed once, with the right
//      hash, rather than started under a guess and rebuilt — rebuilding cannot reproduce the
//      HelloRetryRequest substitution, and a transcript that is subtly wrong only after an HRR is
//      the kind of bug that survives every test against a server that never sends one.
//
// The ClientHello/ServerHello preamble that rules 3 rests on lives in connect.js, shared with the
// 1.2 driver so that one hello can offer both versions; continueTls13 below is everything that
// happens after the ServerHello routed the connection here. handshakeTls13 remains the
// single-version entry: it is connectTls with the offer pinned to [TLS 1.3].
//
// Verification is injected rather than imported so this module has no opinion about trust policy,
// and so the handshake can be exercised offline against a scripted peer.

import { TlsError, TlsUnsupportedError, codes, hex8, hex16 } from '../errors.js';
import { EXTENSION, HANDSHAKE_TYPE, SUPPORTED_GROUPS, TLS13 } from './constants.js';
import {
  applicationTrafficSecrets,
  deriveHandshakeSecret,
  deriveMasterSecret,
  earlySecret,
  finishedVerifyData,
  handshakeTrafficSecrets,
} from './keyschedule.js';
import {
  buildClientHello,
  certificateVerifyContent,
  checkAlpn,
  checkFinished,
  checkSessionIdEcho,
  deriveSharedSecret,
  generateKeyShare,
  negotiateCipher,
  negotiateVersion,
  parseCertificate13,
  parseCertificateVerify,
  parseHelloRetryRequest,
  parseServerHello,
  selectServerKeyShare,
  verifyHandshakeSignature,
} from './handshake-messages.js';
import { decodeExtensionBlock, describeVersion, rejectUnofferedExtensions } from './extensions.js';
import { Builder, Cursor, handshakeMessage } from './wire.js';
import { connectTls } from './connect.js';

const HS_NAME = Object.fromEntries(Object.entries(HANDSHAKE_TYPE).map(([k, v]) => [v, k]));

/**
 * Only one key share is offered by default. A second costs a key generation and 30-odd bytes for
 * a group the server is unlikely to prefer; a HelloRetryRequest recovers the rare case at the
 * cost of one round trip.
 */
export const DEFAULT_OFFER_GROUPS = [SUPPORTED_GROUPS[0]];

const describeType = (t) => `${hex8(t)} (${HS_NAME[t] ?? 'unknown'})`;

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
  if (msg.type !== type) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server sent handshake type ${describeType(msg.type)} where ${where} was expected`,
      { got: msg.type, expected: type },
    );
  }
  return msg;
}

/**
 * Run a TLS 1.3 handshake over a byte duplex and return the plaintext duplex above it.
 *
 * @param {object} args
 * @param {{readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>}} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {(chain: Uint8Array[], hostname: string) => Promise<{spki: {spkiDer: Uint8Array}}>} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key this
 *   handshake will accept a CertificateVerify signature from.
 * @param {object} [args.options]
 * @param {{randomBytes?: (n:number)=>Uint8Array, generateKeyPair?: Function}} [args.deps]
 */
export async function handshakeTls13({ transport, hostname, verifyPeer, options = {}, deps = {} }) {
  if (typeof verifyPeer !== 'function') {
    // Refusing to start is the only safe default. A missing verifier must never read as "skip".
    throw new TlsError(
      codes.CONFIG_INVALID,
      'handshakeTls13 requires a verifyPeer function; there is no unverified mode',
    );
  }
  // The offer is pinned to [TLS 1.3] no matter what options.versions says: callers of THIS
  // function chose the version by choosing the function, and a widened offer sneaking in through
  // options would silently change which downgrade guards apply.
  return connectTls({
    transport,
    hostname,
    verifyPeer,
    deps,
    options: { ...options, versions: [TLS13] },
  });
}

/**
 * Continue a TLS 1.3 handshake from the first ServerHello (which may be a HelloRetryRequest).
 * Called by connect.js once negotiation routed the connection here; `ctx` carries the record
 * layer, the transcript (created under the negotiated suite's hash, ClientHello already folded
 * in), the ClientHello metadata, the parsed ServerHello with its raw bytes, and the offer that
 * produced them.
 */
export async function continueTls13(ctx) {
  const { record, transcript, hostname, verifyPeer, options, deps } = ctx;
  const { versions, ciphers, groups, offerGroups, alpn } = ctx.offer;
  let { hello, serverHello: sh, rawServerHello, suite, params } = ctx;
  let { keyShares } = ctx.offer;
  let hash = params.hash;

  // --- HelloRetryRequest ---------------------------------------------------------------------
  if (sh.isHelloRetryRequest) {
    const { group, cookie } = parseHelloRetryRequest(sh, { offeredGroups: groups });
    if (offerGroups.includes(group)) {
      throw new TlsError(
        codes.TLS_HANDSHAKE,
        `HelloRetryRequest demanded group ${hex16(group)}, for which a key share was already ` +
          'sent; the server is looping',
        { group },
      );
    }
    checkSessionIdEcho(sh, hello.legacySessionId);

    await transcript.replaceWithMessageHash();
    transcript.update(rawServerHello);

    keyShares = [await generateKeyShare(group, deps)];
    // RFC 8446 s4.1.2: ClientHello2 reuses the random and the legacy session id verbatim — and
    // everything else about the offer, including the full VERSION list. If both versions were
    // offered, ClientHello2 offers both again; changing the extension set between hellos is not
    // among the modifications s4.1.2 permits, and a strict server checks.
    hello = buildClientHello({
      hostname,
      keyShares,
      groups,
      alpn,
      ciphers,
      versions,
      random: hello.clientRandom,
      legacySessionId: hello.legacySessionId,
      extraExtensions: cookie ? [cookieExtension(cookie)] : [],
      randomBytes: deps.randomBytes,
    });
    transcript.update(hello.message);
    await record.writeHandshake([hello.message]);

    const second = expect(
      await record.nextHandshakeMessage(),
      HANDSHAKE_TYPE.server_hello,
      'ServerHello',
    );
    rawServerHello = second.raw;
    sh = parseServerHello(second.body);
    if (sh.isHelloRetryRequest) {
      throw new TlsError(codes.TLS_HANDSHAKE, 'server sent a second HelloRetryRequest');
    }
    // RFC 8446 s4.1.4: the real ServerHello must keep the suite the HelloRetryRequest named,
    // otherwise the transcript hash we already committed to would be the wrong one.
    const again = negotiateCipher(sh, { offeredCiphers: ciphers, version: TLS13 });
    if (again.suite !== suite) {
      throw new TlsError(
        codes.TLS_CIPHER_UNSUPPORTED,
        `ServerHello selected ${hex16(again.suite)} after HelloRetryRequest selected ${hex16(suite)}`,
        { hrr: suite, serverHello: again.suite },
      );
    }
    ({ suite, params } = again);
    hash = params.hash;

    // The HelloRetryRequest pinned this connection to 1.3, but the real ServerHello must still
    // say so itself. negotiateVersion runs with the full offered list so the downgrade guards
    // stay live; when 1.2 was also offered it can legitimately RETURN TLS 1.2 for a hello with
    // no supported_versions, and that answer — a version change across the retry — is a splice.
    const version = negotiateVersion(sh, { offeredVersions: versions });
    if (version !== TLS13) {
      throw new TlsUnsupportedError(
        codes.TLS_VERSION_UNSUPPORTED,
        `server negotiated ${describeVersion(version)} in the ServerHello after its ` +
          'HelloRetryRequest; a HelloRetryRequest exists only in TLS 1.3, so the connection ' +
          'cannot continue at any other version',
        { version },
      );
    }
  }

  // --- negotiation ---------------------------------------------------------------------------
  // The non-HRR ServerHello already went through negotiateVersion in connect.js with the full
  // offered list — that is what routed the connection here.
  checkSessionIdEcho(sh, hello.legacySessionId);
  transcript.update(rawServerHello);

  const server = selectServerKeyShare(sh, keyShares);
  const shared = await deriveSharedSecret(server.group, server.privateKey, server.keyExchange);

  const early = await earlySecret(hash);
  const handshakeSecret = await deriveHandshakeSecret(hash, early, shared);
  const hsSecrets = await handshakeTrafficSecrets(hash, handshakeSecret, await transcript.hash());

  // From here the server speaks encrypted. Our send direction stays plaintext until the client
  // Finished, which is why the send key is installed later rather than here.
  await record.setReceiveKeys({ cipher: suite, secret: hsSecrets.server });

  // --- server flight -------------------------------------------------------------------------
  const ee = expect(
    await record.nextHandshakeMessage(),
    HANDSHAKE_TYPE.encrypted_extensions,
    'EncryptedExtensions',
  );
  transcript.update(ee.raw);
  const eeCursor = new Cursor(ee.body, 'EncryptedExtensions');
  const eeExts = decodeExtensionBlock(eeCursor.vector(2, 'extensions'), 'EncryptedExtensions');
  eeCursor.end('EncryptedExtensions');
  rejectUnofferedExtensions(eeExts, hello.offeredExtensions, 'EncryptedExtensions');
  const alpnProtocol = checkAlpn(eeExts, alpn, 'EncryptedExtensions');

  let next = await record.nextHandshakeMessage();
  let certificateRequested = false;
  if (next && !next.ccs && next.type === HANDSHAKE_TYPE.certificate_request) {
    // We hold no client certificate, but the protocol still demands an answer: an empty
    // Certificate message and no CertificateVerify (RFC 8446 s4.4.2).
    certificateRequested = true;
    transcript.update(next.raw);
    next = await record.nextHandshakeMessage();
  }

  const certMsg = expect(next, HANDSHAKE_TYPE.certificate, 'Certificate');
  transcript.update(certMsg.raw);
  const chain = parseCertificate13(certMsg.body);
  const transcriptThroughCertificate = await transcript.hash();

  const cv = expect(
    await record.nextHandshakeMessage(),
    HANDSHAKE_TYPE.certificate_verify,
    'CertificateVerify',
  );
  const { algorithm, signature } = parseCertificateVerify(cv.body);
  transcript.update(cv.raw);

  // Trust first. The signature check below is only meaningful once the key performing it has been
  // tied by the trust layer to a chain we accept for this hostname; done the other way round it
  // merely proves that whoever holds the socket also holds a key, which is no evidence at all.
  const peer = await verifyPeer(chain, hostname);
  const spki = peer?.spki?.spkiDer;
  if (!spki) {
    throw new TlsError(
      codes.CONFIG_INVALID,
      'verifyPeer must resolve with the validated leaf certificate, including spki.spkiDer',
    );
  }
  await verifyHandshakeSignature({
    scheme: algorithm,
    spki,
    signature,
    content: certificateVerifyContent(transcriptThroughCertificate, true),
  });

  const sf = expect(await record.nextHandshakeMessage(), HANDSHAKE_TYPE.finished, 'server Finished');
  const expectedFinished = await finishedVerifyData(hash, hsSecrets.server, await transcript.hash());
  checkFinished(sf.body, expectedFinished);
  transcript.update(sf.raw);

  // Application secrets are bound to the transcript through the server Finished (RFC 8446 s7.1),
  // so they are derived here, before anything the client sends is folded in.
  const masterSecret = await deriveMasterSecret(hash, handshakeSecret);
  const appSecrets = await applicationTrafficSecrets(hash, masterSecret, await transcript.hash());

  // --- client flight -------------------------------------------------------------------------
  if (options.compatibilityCcs !== false) await record.writeChangeCipherSpec();
  await record.setSendKeys({ cipher: suite, secret: hsSecrets.client });

  const clientFlight = [];
  if (certificateRequested) {
    const empty = handshakeMessage(
      HANDSHAKE_TYPE.certificate,
      new Builder().vector(1, new Uint8Array(0)).vector(3, new Uint8Array(0)).build(),
    );
    clientFlight.push(empty);
    transcript.update(empty);
  }
  clientFlight.push(
    handshakeMessage(
      HANDSHAKE_TYPE.finished,
      await finishedVerifyData(hash, hsSecrets.client, await transcript.hash()),
    ),
  );
  await record.writeHandshake(clientFlight);

  await record.setSendKeys({ cipher: suite, secret: appSecrets.client });
  await record.setReceiveKeys({ cipher: suite, secret: appSecrets.server });
  record.markHandshakeComplete();

  const duplex = record.plaintextDuplex();
  return {
    readable: duplex.readable,
    writable: duplex.writable,
    record,
    peer,
    info: {
      version: TLS13,
      cipherSuite: suite,
      group: server.group,
      alpnProtocol: alpnProtocol ?? null,
      certificateRequested,
      hostname,
    },
    close: () => record.close(),
  };
}

/** A HelloRetryRequest cookie must be echoed verbatim in ClientHello2 (RFC 8446 s4.2.2). */
function cookieExtension(cookie) {
  return new Builder().u16(EXTENSION.cookie).vector(2, cookie).build();
}
