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
  resumptionMasterSecret,
  resumptionPsk,
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
  parseNewSessionTicket,
  parseServerHello,
  selectServerKeyShare,
  setPskBinder,
  verifyHandshakeSignature,
} from './handshake-messages.js';
import {
  decodeExtensionBlock,
  decodeServerPreSharedKey,
  describeVersion,
  rejectUnofferedExtensions,
} from './extensions.js';
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

/**
 * The injected trust decision. Must throw to reject; resolves with the validated leaf, whose
 * SPKI is the only key a driver will accept a handshake signature from. `details.ocspResponse`
 * is the peer's stapled DER OCSPResponse when it sent one — delivered here, at the same moment
 * as the chain, because revocation is part of deciding whether to believe the certificate and
 * must be settled before anything of ours goes on the wire.
 * @typedef {(chain: Uint8Array[], hostname: string,
 *   details?: { ocspResponse: Uint8Array | null })
 *   => Promise<{ spki: { spkiDer: Uint8Array } }>} VerifyPeer
 */

/**
 * Driver context assembled by connect.js after the ServerHello routed the connection: the
 * record layer, the transcript (created under the negotiated suite's hash, ClientHello already
 * folded in), the ClientHello metadata, the parsed ServerHello with its raw bytes, and the
 * offer that produced them. Both continue* drivers consume exactly this shape.
 * @typedef {object} HandshakeContext
 * @property {import('./record.js').RecordLayer} record
 * @property {import('./transcript.js').Transcript} transcript
 * @property {import('./handshake-messages.js').ClientHello} hello
 * @property {import('./handshake-messages.js').ServerHello} serverHello
 * @property {Uint8Array} rawServerHello
 * @property {number} suite
 * @property {import('./constants.js').CipherParams} params
 * @property {string} hostname
 * @property {VerifyPeer} verifyPeer
 * @property {import('./connect.js').TlsOptions} options
 * @property {import('./connect.js').TlsDeps} deps
 * @property {{ versions: number[], ciphers: number[], groups: number[], offerGroups: number[],
 *   alpn: string[], keyShares: import('./handshake-messages.js').KeyShare[],
 *   psk: OfferedPsk | null }} offer
 */

/**
 * The resumption PSK as prepared by connect.js: the caller's offer plus the secrets derived
 * from it once (Early Secret, binder key) so neither hello build nor acceptance re-derives.
 * @typedef {object} OfferedPsk
 * @property {Uint8Array} identity
 * @property {Uint8Array} psk
 * @property {import('./keyschedule.js').ScheduleHash} hash
 * @property {() => number} obfuscatedTicketAge
 * @property {object | null} peer
 * @property {Uint8Array} earlySecret
 * @property {Uint8Array} binderKey
 * @property {number} binderLen
 */

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
 * @param {import('./connect.js').ByteDuplex} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {VerifyPeer} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key this
 *   handshake will accept a CertificateVerify signature from.
 * @param {import('./connect.js').TlsOptions} [args.options] `versions` is ignored: this entry
 *   pins the offer to [TLS 1.3]
 * @param {import('./connect.js').TlsDeps} [args.deps]
 * @returns {Promise<import('./connect.js').TlsSession>}
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
 * Called by connect.js once negotiation routed the connection here.
 * @param {HandshakeContext} ctx
 * @returns {Promise<import('./connect.js').TlsSession>}
 */
export async function continueTls13(ctx) {
  const { record, transcript, hostname, verifyPeer, options, deps } = ctx;
  const { versions, ciphers, groups, offerGroups, alpn } = ctx.offer;
  let { hello, serverHello: sh, rawServerHello, suite, params } = ctx;
  let { keyShares } = ctx.offer;
  let hash = params.hash;
  // The PSK the CURRENT hello carries. Starts as what connect.js offered in ClientHello1 and
  // can only narrow: a HelloRetryRequest that pins a suite of a different hash removes it from
  // ClientHello2 (s4.1.4), and every acceptance check below runs against this variable — never
  // against the original offer — so a server cannot select what the live hello does not carry.
  let offeredPsk = ctx.offer.psk ?? null;

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

    // s4.1.4: the second hello SHOULD NOT offer a PSK whose hash differs from the suite the
    // HelloRetryRequest just pinned — the server could never legally select it, and computing
    // its binder would need a second transcript under the other hash. Dropping it here is what
    // makes a later pre_shared_key in the real ServerHello provably a violation.
    if (offeredPsk && offeredPsk.hash !== params.hash) offeredPsk = null;

    keyShares = [await generateKeyShare(group, deps)];
    // RFC 8446 s4.1.2: ClientHello2 reuses the random and the legacy session id verbatim — and
    // everything else about the offer, including the full VERSION list. If both versions were
    // offered, ClientHello2 offers both again; changing the extension set between hellos is not
    // among the modifications s4.1.2 permits (recomputing obfuscated_ticket_age and the binder
    // IS: s4.1.2 lists "pre_shared_key" as one of the fields a second hello updates), and a
    // strict server checks.
    hello = buildClientHello({
      hostname,
      keyShares,
      groups,
      alpn,
      ciphers,
      versions,
      // The retry must reproduce the first hello's extension set AND order: s4.1.2 does not list
      // either among the modifications a second ClientHello may make, and a strict server checks.
      extensionOrder: options.extensionOrder,
      sigSchemes: options.sigSchemes,
      grease: options.grease ?? false,
      random: hello.clientRandom,
      legacySessionId: hello.legacySessionId,
      // The caller's extras must be reproduced too, for the same reason the order is: s4.1.2 does
      // not permit a second hello to change its extension SET, and a retry that quietly dropped
      // them would present one fingerprint on the first flight and a different one on the second —
      // a difference that is itself a signal.
      extraExtensions: [
        ...(options.extraExtensions ?? []),
        ...(cookie ? [cookieExtension(cookie)] : []),
      ],
      psk: offeredPsk && {
        identity: offeredPsk.identity,
        obfuscatedTicketAge: offeredPsk.obfuscatedTicketAge(),
        binderLen: offeredPsk.binderLen,
      },
      randomBytes: deps.randomBytes,
    });
    if (offeredPsk) {
      // The ClientHello2 binder covers Transcript-Hash(message_hash(CH1) || HRR ||
      // Truncate(CH2)) (s4.2.11.2). The transcript object holds exactly the first two at this
      // point, and hashWith appends the truncation without ever folding it in — the transcript
      // proper receives the full patched hello below. The suite's hash and the PSK's hash are
      // equal here by the drop above, so one digest serves both bookkeepings.
      const truncatedHash = await transcript.hashWith(
        hello.message.subarray(0, hello.truncatedLength));
      setPskBinder(hello,
        await finishedVerifyData(offeredPsk.hash, offeredPsk.binderKey, truncatedHash));
    }
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

  // Did the server take the PSK? Every check is against the CURRENT hello's offer (s4.2.11:
  // "Clients MUST verify that the server's selected_identity is within the range supplied by
  // the client [and] that the server selected a cipher suite indicating a Hash associated with
  // the PSK"). Fail closed on each: continuing after any of these means client and server
  // disagree about which secret protects the connection.
  let acceptedPsk = null;
  const pskExt = sh.extensions.get(EXTENSION.pre_shared_key);
  if (pskExt !== undefined) {
    if (!offeredPsk) {
      throw new TlsError(
        codes.TLS_PSK,
        'ServerHello selected a pre-shared key, but the ClientHello it answers offered none',
      );
    }
    const selected = decodeServerPreSharedKey(pskExt);
    if (selected !== 0) {
      // Exactly one identity is ever offered, so the only selectable index is 0.
      throw new TlsError(
        codes.TLS_PSK,
        `ServerHello selected pre-shared key identity ${selected}, but only one identity ` +
          '(index 0) was offered',
        { selected },
      );
    }
    if (params.hash !== offeredPsk.hash) {
      throw new TlsError(
        codes.TLS_PSK,
        `ServerHello accepted the offered PSK but selected cipher suite ${hex16(suite)} ` +
          `(${params.hash}), while the PSK was minted under ${offeredPsk.hash}; a PSK may only ` +
          'be used with the hash it was derived for (RFC 8446 s4.2.11)',
        { suite, suiteHash: params.hash, pskHash: offeredPsk.hash },
      );
    }
    acceptedPsk = offeredPsk;
  }
  // No pre_shared_key in the ServerHello means the server declined: the FULL handshake — with
  // Certificate, CertificateVerify, and chain validation — continues on this same connection.
  // No reconnect, no re-offer, no downgrade dance; declining costs nothing but the bytes.

  // Only psk_dhe_ke is ever offered (s4.2.9), so a key exchange happens whether or not the PSK
  // was taken; selectServerKeyShare fails closed on a ServerHello without key_share.
  const server = selectServerKeyShare(sh, keyShares);
  const shared = await deriveSharedSecret(server.group, server.privateKey, server.keyExchange, deps);

  // s7.1: with a PSK in use the Early Secret is extracted from it; otherwise from zeros. The
  // accepted offer already carries that extraction (connect.js derived it for the binder), and
  // its hash equals the negotiated hash by the acceptance check above.
  const early = acceptedPsk ? acceptedPsk.earlySecret : await earlySecret(hash);
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
  if (eeExts.has(EXTENSION.status_request)) {
    // We DID offer status_request, so the unoffered-extension check above cannot catch this —
    // but RFC 8446 s4.2 places the server's answer in the leaf's CertificateEntry, never in
    // EncryptedExtensions, and an extension in a message it is not specified for is a fatal
    // illegal_parameter, not a tolerable relocation. Accepting a staple from here would also
    // move it outside the certificate it is supposed to be bound to.
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'server sent status_request in EncryptedExtensions; in TLS 1.3 a stapled certificate ' +
        "status belongs in the leaf's CertificateEntry (RFC 8446 s4.4.2.1)",
      { extension: EXTENSION.status_request },
    );
  }
  const alpnProtocol = checkAlpn(eeExts, alpn, 'EncryptedExtensions');

  let next = await record.nextHandshakeMessage();
  let certificateRequested = false;
  let peer;
  if (acceptedPsk) {
    // Resumed: the server authenticates by proving it holds the PSK — its Finished MAC, under
    // keys extracted from that PSK, is the proof — and s4.3.2 forbids it from sending
    // CertificateRequest (and s2.2 from re-authenticating with a certificate) in this handshake.
    // A server that sends either after selecting the PSK is not confused about framing, it is
    // violating the PSK contract, so the error names that rather than a generic wrong-type.
    if (next && !next.ccs &&
        (next.type === HANDSHAKE_TYPE.certificate ||
         next.type === HANDSHAKE_TYPE.certificate_request)) {
      throw new TlsError(
        codes.TLS_PSK,
        `server resumed with the offered pre-shared key but then sent ${describeType(next.type)}; ` +
          'a PSK handshake must not carry certificate messages (RFC 8446 s2.2, s4.3.2)',
        { type: next.type },
      );
    }
    // The certificate validated in the ORIGINAL handshake vouches for this connection, exactly
    // as far as the ticket store's keying lets it: the store binds tickets to the full trust
    // configuration, so this peer was validated under the same policy this caller asked for.
    peer = acceptedPsk.peer;
  } else {
    if (next && !next.ccs && next.type === HANDSHAKE_TYPE.certificate_request) {
      // We hold no client certificate, but the protocol still demands an answer: an empty
      // Certificate message and no CertificateVerify (RFC 8446 s4.4.2).
      certificateRequested = true;
      transcript.update(next.raw);
      next = await record.nextHandshakeMessage();
    }

    const certMsg = expect(next, HANDSHAKE_TYPE.certificate, 'Certificate');
    transcript.update(certMsg.raw);
    // The leaf's CertificateEntry may carry a stapled OCSP response (RFC 8446 s4.4.2.1); it rides
    // to the trust layer alongside the chain and is judged there, under the same fail-closed rules.
    const { chain, ocspResponse } = parseCertificate13(certMsg.body, {
      offeredExtensions: hello.offeredExtensions,
    });
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
    peer = await verifyPeer(chain, hostname, { ocspResponse });
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

    next = await record.nextHandshakeMessage();
  }

  const sf = expect(next, HANDSHAKE_TYPE.finished, 'server Finished');
  const expectedFinished = await finishedVerifyData(hash, hsSecrets.server, await transcript.hash());
  checkFinished(sf.body, expectedFinished);
  transcript.update(sf.raw);

  // Application secrets are bound to the transcript through the server Finished (RFC 8446 s7.1),
  // so they are derived here, before anything the client sends is folded in.
  const masterSecret = await deriveMasterSecret(hash, handshakeSecret);
  // No exporter interface is exposed, so exporter_master_secret would be dead work every handshake.
  const appSecrets = await applicationTrafficSecrets(hash, masterSecret, await transcript.hash(),
    { exporter: false });

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
  const clientFinished = handshakeMessage(
    HANDSHAKE_TYPE.finished,
    await finishedVerifyData(hash, hsSecrets.client, await transcript.hash()),
  );
  clientFlight.push(clientFinished);
  // Our own Finished joins the transcript too: resumption_master_secret is derived from the
  // transcript THROUGH the client Finished (s7.1), so without this line every PSK minted from a
  // ticket would be wrong — and wrong in a way a loopback test with the same omission on both
  // sides would never notice.
  transcript.update(clientFinished);
  await record.writeHandshake(clientFlight);

  await record.setSendKeys({ cipher: suite, secret: appSecrets.client });
  await record.setReceiveKeys({ cipher: suite, secret: appSecrets.server });
  record.markHandshakeComplete();

  if (options.onSessionTicket) {
    // NewSessionTicket arrives under application keys at the server's leisure; the record layer
    // surfaces it here. Everything is derived lazily on the first ticket so a connection whose
    // server never sends one pays nothing, and resumption_master_secret is computed once then
    // reused — one server flight routinely carries two tickets. Parse or derivation failures
    // propagate out of the read path and fail the connection: a peer whose post-handshake
    // messages are malformed does not get to keep talking (same stance as KeyUpdate).
    //
    // 0-RTT, stated as a decision and not an omission: a ticket may advertise early_data, and
    // this client records but never uses it. Early data is replayable by design — an attacker
    // who captures the flight can replay it, and the server may accept both copies — which is
    // unsafe for exactly the requests a proxy client carries (a caller's POST must not be
    // executable twice by a third party). No option enables it.
    let resMaster = null;
    record.setPostHandshake(async ({ body }) => {
      const t = parseNewSessionTicket(body);
      resMaster ??= await resumptionMasterSecret(hash, masterSecret, await transcript.hash());
      options.onSessionTicket({
        identity: t.ticket,
        psk: await resumptionPsk(hash, resMaster, t.nonce),
        hash,
        cipherSuite: suite,
        lifetimeSec: t.lifetimeSec,
        ageAdd: t.ageAdd,
        maxEarlyDataSize: t.maxEarlyDataSize,
        alpnProtocol: alpnProtocol ?? null,
        peer,
      });
    });
  }

  // The duplex is created on first access, not eagerly: consumers that drive the record layer
  // directly (record.readAppData/writeAppData) never need the platform-stream wrappers, and the
  // runtime this package targets forbids even CONSTRUCTING platform streams in global scope —
  // where the opt-in warmup replay runs. Memoized, so every consumer sees one stable pair.
  let duplex = null;
  const lazyDuplex = () => (duplex ??= record.plaintextDuplex());
  return {
    get readable() {
      return lazyDuplex().readable;
    },
    get writable() {
      return lazyDuplex().writable;
    },
    record,
    peer,
    info: {
      version: TLS13,
      cipherSuite: suite,
      group: server.group,
      alpnProtocol: alpnProtocol ?? null,
      certificateRequested,
      hostname,
      // True only when the server took the offered PSK. A declined offer reports false: the
      // connection ran the full handshake and was authenticated by certificate, and a caller
      // reading this field is usually asking "was the chain re-validated on this connection".
      resumed: acceptedPsk !== null,
    },
    close: () => record.close(),
  };
}

/** A HelloRetryRequest cookie must be echoed verbatim in ClientHello2 (RFC 8446 s4.2.2). */
function cookieExtension(cookie) {
  return new Builder().u16(EXTENSION.cookie).vector(2, cookie).build();
}
