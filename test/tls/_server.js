// A minimal TLS 1.3 server, for tests only.
//
// It speaks just enough of RFC 8446 to complete a handshake with the client under test — and,
// crucially, it VERIFIES what the client sends rather than humouring it: the client Finished is
// checked against the server's own transcript, so a client with an off-by-one-message transcript
// or a key installed one flight too early fails here instead of "passing" against a pushover.
//
// It is built on the same RecordLayer / Transcript / key-schedule modules as the client, which
// is deliberate for framing and key derivation (those are symmetric, and their byte-level
// behaviour is pinned elsewhere against RFC 8448 traces), but every MESSAGE this server emits is
// encoded here, by hand — including the ServerHello supported_versions extension as a bare
// uint16 (the client-side encoder writes the length-prefixed LIST form, which in a ServerHello
// would be wrong; sharing the encoder would hide exactly that asymmetry).
//
// Every step is parameterisable so the negative tests can make the server misbehave in ONE
// specific way at a time; with no options it is an honest, if minimal, server.

import { RecordLayer } from '../../src/tls/record.js';
import { Transcript } from '../../src/tls/transcript.js';
import {
  certificateVerifyContent,
  deriveSharedSecret,
  generateKeyShare,
} from '../../src/tls/handshake-messages.js';
import { decodeExtensionBlock, encodeAlpn } from '../../src/tls/extensions.js';
import {
  applicationTrafficSecrets,
  deriveHandshakeSecret,
  deriveMasterSecret,
  earlySecret,
  finishedVerifyData,
  handshakeTrafficSecrets,
  resumptionBinderKey,
  resumptionMasterSecret,
  resumptionPsk,
} from '../../src/tls/keyschedule.js';
import { Builder, Cursor, handshakeMessage, vector } from '../../src/tls/wire.js';
import {
  ALERT_LEVEL,
  CIPHER_PARAMS,
  EXTENSION,
  HANDSHAKE_TYPE,
  HELLO_RETRY_REQUEST_RANDOM,
  SUPPORTED_GROUPS,
  LEGACY_VERSION,
  TLS13,
  TLS13_CIPHERS,
} from '../../src/tls/constants.js';
import { concat, timingSafeEqual, toHex, u8, u16, u24, u32 } from '../../src/util/bytes.js';

const EMPTY = new Uint8Array(0);

/** `extension_type || extension_data<0..2^16-1>`, shared with the tests for misbehaviour. */
export function rawExtension(type, data) {
  return new Builder().u16(type).vector(2, data).build();
}

/**
 * A status_request CertificateEntry extension carrying a DER OCSPResponse (RFC 8446 s4.4.2.1:
 * the extension body is the RFC 6066 CertificateStatus shape). Exported so tests can plant
 * staples on arbitrary entries through `entryExtensions`.
 */
export function stapleEntryExtension(ocspDer) {
  return rawExtension(EXTENSION.status_request, new Builder().u8(1).vector(3, ocspDer).build());
}

/**
 * Parse a ClientHello body. Strict about the parts a real server must be strict about
 * (legacy_version, null-only compression) so a client regression in those fields fails the
 * handshake instead of being absorbed by a permissive test double.
 */
function parseClientHello(body) {
  const c = new Cursor(body, 'ClientHello');
  const legacyVersion = c.u16('legacy_version');
  if (legacyVersion !== LEGACY_VERSION) {
    throw new Error(`test server: ClientHello legacy_version 0x${legacyVersion.toString(16)}`);
  }
  const random = c.take(32, 'random').slice();
  const sessionId = c.vector(1, 'legacy_session_id').slice();
  const suites = c.sub(2, 'cipher_suites');
  const cipherSuites = [];
  while (!suites.done) cipherSuites.push(suites.u16('cipher_suite'));
  const compression = c.vector(1, 'legacy_compression_methods');
  if (compression.byteLength !== 1 || compression[0] !== 0) {
    throw new Error('test server: ClientHello must offer exactly the null compression method');
  }
  const extensions = decodeExtensionBlock(c.vector(2, 'extensions'), 'ClientHello');
  c.end('ClientHello');

  const keyShares = [];
  const ks = extensions.get(EXTENSION.key_share);
  if (ks) {
    const kc = new Cursor(ks, 'client key_share');
    const list = kc.sub(2, 'client_shares');
    while (!list.done) {
      const group = list.u16('group');
      keyShares.push({ group, keyExchange: list.vector(2, 'key_exchange').slice() });
    }
    kc.end('client key_share');
  }
  const versions = [];
  const sv = extensions.get(EXTENSION.supported_versions);
  if (sv) {
    // ClientHello form: a length-prefixed LIST — the asymmetry with our ServerHello encoding.
    const vc = new Cursor(sv, 'client supported_versions');
    const list = vc.sub(1, 'versions');
    while (!list.done) versions.push(list.u16('version'));
    vc.end('client supported_versions');
  }
  const alpn = [];
  const al = extensions.get(EXTENSION.alpn);
  if (al) {
    const ac = new Cursor(al, 'client alpn');
    const list = ac.sub(2, 'protocol_name_list');
    while (!list.done) alpn.push(new TextDecoder().decode(list.vector(1, 'protocol_name')));
    ac.end('client alpn');
  }
  let serverName = null;
  const sni = extensions.get(EXTENSION.server_name);
  if (sni) {
    const sc = new Cursor(sni, 'server_name');
    const list = sc.sub(2, 'server_name_list');
    if (list.u8('name_type') === 0) {
      serverName = new TextDecoder().decode(list.vector(2, 'host_name'));
    }
  }
  // Kept as raw extension_data (inner length prefix and all) so cookie echo can be compared
  // verbatim against what the HelloRetryRequest carried.
  const cookie = extensions.get(EXTENSION.cookie)?.slice() ?? null;

  // pre_shared_key, decoded the way a real server must: identities, binders, and — because the
  // binder transcript is "the hello truncated just before the binders list" — the exact number
  // of trailing bytes that list occupies, computed HERE from the decoded entry lengths rather
  // than imported from the client's builder. If the client's truncation arithmetic is wrong,
  // this server's independent arithmetic disagrees and the binder check fails, which is the
  // entire reason this code does not share that helper.
  let psk = null;
  const pk = extensions.get(EXTENSION.psk_key_exchange_modes);
  const pskModes = [];
  if (pk) {
    const mc = new Cursor(pk, 'psk_key_exchange_modes');
    const list = mc.sub(1, 'ke_modes');
    while (!list.done) pskModes.push(list.u8('ke_mode'));
    mc.end('psk_key_exchange_modes');
  }
  const pskExt = extensions.get(EXTENSION.pre_shared_key);
  if (pskExt) {
    const pc = new Cursor(pskExt, 'pre_shared_key');
    const identities = [];
    const ids = pc.sub(2, 'identities');
    while (!ids.done) {
      const identity = ids.vector(2, 'identity').slice();
      const obfuscatedAge = ids.u32('obfuscated_ticket_age');
      identities.push({ identity, obfuscatedAge });
    }
    const binders = [];
    let bindersListLength = 2; // the binders list's own u16 length prefix
    const bs = pc.sub(2, 'binders');
    while (!bs.done) {
      const b = bs.vector(1, 'binder').slice();
      binders.push(b);
      bindersListLength += 1 + b.byteLength;
    }
    pc.end('pre_shared_key');
    psk = {
      identities,
      binders,
      bindersListLength,
      // RFC 8446 s4.2.11 obliges a server to CHECK that pre_shared_key came last; recording
      // the actual last type lets tests assert the client keeps that promise.
      isLastExtension: [...extensions.keys()].pop() === EXTENSION.pre_shared_key,
    };
  }

  return {
    legacyVersion, random, sessionId, cipherSuites, extensions,
    keyShares, versions, alpn, serverName, cookie, psk, pskModes,
  };
}

/**
 * The server's own binder computation, from first principles: hash the transcript prefix pieces
 * plus the ClientHello truncated at the offset ITS OWN parse derived, then run the RFC 8446
 * s4.2.11.2 HMAC. The key-derivation helpers are shared with the client (their byte behaviour
 * is pinned against the RFC 8448 section 4 trace elsewhere); the truncation — the part a client
 * and server can only get "accidentally compatible" by sharing code — is not.
 */
async function computeBinder(chRaw, chPsk, psk, hash, prefixPieces) {
  const truncated = chRaw.subarray(0, chRaw.byteLength - chPsk.bindersListLength);
  const transcriptHash = new Uint8Array(
    await crypto.subtle.digest(hash, concat([...prefixPieces, truncated])),
  );
  const binderKey = await resumptionBinderKey(hash, await earlySecret(hash, psk));
  return finishedVerifyData(hash, binderKey, transcriptHash);
}

/** ServerHello/HelloRetryRequest share one wire shape; only the random distinguishes them. */
function buildServerHello({ random, sessionIdEcho, cipher, extensions }) {
  const body = new Builder()
    .u16(LEGACY_VERSION)
    .push(random)
    .vector(1, sessionIdEcho)
    .u16(cipher)
    .u8(0) // legacy_compression_method
    .push(vector(2, concat(extensions.filter(Boolean))))
    .build();
  return handshakeMessage(HANDSHAKE_TYPE.server_hello, body);
}

async function expectHs(record, type, what) {
  const msg = await record.nextHandshakeMessage();
  if (msg === null) throw new Error(`test server: peer closed while waiting for ${what}`);
  if (msg.ccs) throw new Error(`test server: unexpected CCS event while waiting for ${what}`);
  if (msg.type !== type) {
    throw new Error(`test server: got handshake type ${msg.type} while waiting for ${what}`);
  }
  return msg;
}

/**
 * Keep reading (and discarding) after a scripted stop. This is not politeness: duplexPair() is
 * a TransformStream, where a write only completes once the peer reads it. The client's failure
 * path writes one final fatal alert and awaits it; a scripted server that simply returned
 * would leave that write parked forever and turn an expected rejection into a deadlocked test.
 * A real network behaves like the drain (the kernel accepts the alert), so this also keeps the
 * simulation honest. Exits on the first error (usually the client's alert) or EOF.
 */
function drainQuietly(record) {
  void (async () => {
    try {
      for (;;) {
        if ((await record.nextHandshakeMessage()) === null) return;
      }
    } catch {
      /* the client's parting alert, a truncation, or nothing at all */
    }
  })();
}

/**
 * Wrap a transport so the server can slam the connection shut mid-flight — an EOF with no
 * close_notify, which is what a cut cable or an attacker snipping the stream looks like. The
 * RecordLayer owns its writer lock, so the only way to close under it is to interpose here.
 */
function killableTransport({ readable, writable }) {
  const writer = writable.getWriter();
  let dead = false;
  return {
    transport: {
      readable,
      writable: new WritableStream({
        async write(chunk) {
          if (!dead) await writer.write(chunk);
        },
        async close() {
          if (!dead) {
            dead = true;
            await writer.close();
          }
        },
        async abort(reason) {
          if (!dead) {
            dead = true;
            await writer.abort(reason).catch(() => {});
          }
        },
      }),
    },
    kill: async () => {
      if (!dead) {
        dead = true;
        await writer.close();
      }
    },
  };
}

/**
 * Run a TLS 1.3 server handshake over `transport`, presenting `identity` (from _testca.js).
 *
 * Returns `{ record, state, done }` immediately. `done` resolves with `state` once the client
 * Finished has been read AND VERIFIED; after that the test drives application data through
 * `record` (readAppData / writeAppData / close). `state` is also live during a failing
 * handshake so negative tests can assert how far the client let the server get.
 *
 * Honest by default. Options, one misbehaviour each:
 *   cipher                  suite to negotiate (default: client's first of TLS13_CIPHERS)
 *   wireCipher              suite value written into ServerHello only (keys still use `cipher`)
 *   group / serverKeyPair / serverRandom / sessionIdEcho
 *   shareGroup              put a key_share for this group in ServerHello even if the client
 *                           sent no share for it (stops after ServerHello: nothing to derive)
 *   omitSupportedVersions   plain TLS 1.2-shaped ServerHello (legacy_version 0x0303, no ext)
 *   compatCcs               send the middlebox-compatibility CCS after ServerHello
 *   alpn                    protocol to select in EncryptedExtensions (absent = no ALPN ext)
 *   eeExtra                 raw extension blobs appended to EncryptedExtensions
 *   extraChain              extra DER certs after the leaf; emptyCertificateList sends none
 *   staple                  DER OCSPResponse to attach to the LEAF CertificateEntry as a
 *                           status_request extension (RFC 8446 s4.4.2.1)
 *   entryExtensions         { [index]: rawBytes } raw extension-block bytes per CertificateEntry,
 *                           overriding `staple` for that index — for malformed and misplaced
 *                           staples
 *   cvTranscript            'throughEncryptedExtensions' signs the WRONG transcript point
 *   signWith / cvScheme     sign CertificateVerify with a different key / claim a scheme
 *   corruptFinished         flip a byte of the server Finished verify_data
 *   flightOrder             'certificateFirst' swaps Certificate before EncryptedExtensions
 *   alertAfter              'encryptedExtensions': send fatal `alertDesc` instead of Certificate
 *   closeAfter              'encryptedExtensions': hard-close the transport mid-flight
 *   fragmentFlight          (msgs: Uint8Array[]) => Uint8Array[] — each returned slice becomes
 *                           its own record, so tests control message/record alignment exactly
 *   earlyAppData            bytes to send under application keys right after server Finished
 *                           (0.5-RTT), before the client Finished has arrived
 *   hrr                     { group, cookie?, cipher?, cipherAfter?, second? } force a
 *                           HelloRetryRequest demanding `group` first
 *
 * Resumption (RFC 8446 s2.2, s4.2.11, s4.6.1):
 *   tickets                 [{ ticket, lifetime?, ageAdd?, nonce?, extensions?, rawBody? }]
 *                           NewSessionTickets to issue once the handshake completes. Each
 *                           derived PSK is recorded in `sessionCache` so a LATER startServer
 *                           sharing the cache can accept it. rawBody sends those exact bytes
 *                           instead (for malformed-NST tests) and caches nothing.
 *   sessionCache            Map, shared across startServer calls: toHex(ticket) -> {psk, hash}.
 *                           Required for issuing or accepting tickets.
 *   declinePsk              ignore a pre_shared_key offer; full handshake on the same connection
 *   resumeCipher            accept the PSK but negotiate THIS suite even if its hash disagrees
 *                           with the PSK's (the client must refuse the mismatch)
 *   pskSelectedIdentity     selected_identity value to send instead of 0
 *   pskSelectUnoffered      send pre_shared_key in ServerHello although none was offered
 *   resumeSendCertificate   accept the PSK but still send the Certificate flight (forbidden)
 *
 * A hello offering a known ticket has its binder VERIFIED here, against a truncation offset
 * this file derives from its own parse of the wire bytes — deliberately not shared with the
 * client's builder, so a truncation bug cannot cancel itself out. A bad binder aborts with
 * decrypt_error, exactly as s4.2.11.2 demands of a real server.
 */
export function startServer(transport, identity, opts = {}) {
  let t = transport;
  let kill = async () => {};
  if (opts.closeAfter) ({ transport: t, kill } = killableTransport(transport));
  const record = new RecordLayer(t);
  record.setVersion(TLS13);
  const state = {
    clientHellos: [], // parsed ClientHello(s), each with .raw attached
    hrrRaw: null,
    hrrCookieSent: null, // extension_data of the cookie we sent, for verbatim-echo assertions
    transcriptHashAfterCh2: null,
    flightLengths: null, // [ee, certificate, certificateVerify, finished] message byte lengths
    finishedVerified: false, // set ONLY after the client Finished MAC checked out
    binderVerified: null, // null: no known PSK offered; true/false: the binder's verdict
    negotiated: null, // includes `resumed` once the handshake settles
    stopped: null, // scripted early stops ('alert', 'closed', ...) so tests can tell why
  };
  const done = drive(record, identity, opts, state, kill).then(() => state);
  // Negative tests abandon the server mid-protest; its rejection is expected there and must
  // not surface as an unhandled rejection. Positive tests still `await done` and see failures.
  done.catch(() => {});
  return { record, state, done };
}

async function drive(record, identity, opts, state, kill) {
  // --- ClientHello (and possibly a HelloRetryRequest round) --------------------------------
  const ch1Msg = await expectHs(record, HANDSHAKE_TYPE.client_hello, 'ClientHello');
  let ch = parseClientHello(ch1Msg.body);
  ch.raw = ch1Msg.raw.slice();
  state.clientHellos.push(ch);

  /**
   * Judge a hello's pre_shared_key against the session cache. Returns null to decline (full
   * handshake — never a connection error), `{ badBinder: true }` when the binder fails (the
   * one outcome RFC 8446 s4.2.11.2 makes fatal), or `{ psk, hash }` to resume with. Structural
   * promises the client is required to keep (extension last, psk_dhe_ke offered) throw: a test
   * client breaking those is a bug to surface, not a preference to accommodate.
   */
  const evaluatePsk = async (hello, prefixPieces, pinnedSuite) => {
    if (!hello.psk || opts.declinePsk || opts.pskSelectUnoffered) return null;
    if (!hello.psk.isLastExtension) {
      throw new Error('test server: pre_shared_key is not the last ClientHello extension');
    }
    if (!hello.pskModes.includes(1)) {
      throw new Error('test server: pre_shared_key offered without psk_dhe_ke');
    }
    const known = opts.sessionCache?.get(toHex(hello.psk.identities[0].identity));
    if (!known) return null; // an unknown or expired ticket is declined, like a real server
    const expected = await computeBinder(hello.raw, hello.psk, known.psk, known.hash, prefixPieces);
    if (!timingSafeEqual(hello.psk.binders[0], expected)) {
      state.binderVerified = false;
      return { badBinder: true };
    }
    state.binderVerified = true;
    // An honest server only selects a PSK alongside a suite of the PSK's hash; when the suite
    // is pinned to a different hash it declines (resumeCipher overrides to script the
    // mismatched-acceptance misbehaviour the client must catch).
    if (pinnedSuite && CIPHER_PARAMS[pinnedSuite].hash !== known.hash && !opts.resumeCipher) {
      return null;
    }
    return { psk: known.psk, hash: known.hash };
  };

  let resumption = await evaluatePsk(ch, [], opts.cipher ?? null);
  if (resumption?.badBinder) {
    // RFC 8446 s4.2.11.2: a binder that does not validate MUST abort the handshake.
    await record.sendAlert(ALERT_LEVEL.fatal, 51); // decrypt_error
    state.stopped = 'bad-binder';
    drainQuietly(record);
    return;
  }

  let suite;
  if (opts.cipher) suite = opts.cipher;
  else if (resumption) {
    suite = opts.resumeCipher ??
      TLS13_CIPHERS.find((c) => ch.cipherSuites.includes(c) &&
        CIPHER_PARAMS[c].hash === resumption.hash);
  } else suite = TLS13_CIPHERS.find((c) => ch.cipherSuites.includes(c));
  if (!suite) throw new Error('test server: no mutually supported cipher suite');
  let hash = CIPHER_PARAMS[suite].hash;
  // The transcript hash is fixed by the suite the server just chose — same reasoning as the
  // client, from the other side of the table.
  const transcript = new Transcript(hash);
  transcript.update(ch.raw);

  if (opts.hrr) {
    // RFC 8446 s4.4.1: the HRR transcript replaces ClientHello1 with message_hash(Hash(CH1)).
    await transcript.replaceWithMessageHash();
    const hrr = buildServerHello({
      random: HELLO_RETRY_REQUEST_RANDOM,
      sessionIdEcho: ch.sessionId,
      cipher: opts.hrr.cipher ?? suite,
      extensions: [
        rawExtension(EXTENSION.supported_versions, u16(TLS13)),
        rawExtension(EXTENSION.key_share, u16(opts.hrr.group)), // bare group, no key
        opts.hrr.cookie ? rawExtension(EXTENSION.cookie, vector(2, opts.hrr.cookie)) : null,
      ],
    });
    state.hrrRaw = hrr;
    if (opts.hrr.cookie) state.hrrCookieSent = vector(2, opts.hrr.cookie);
    transcript.update(hrr);
    await record.writeHandshake([hrr]);

    const ch2Msg = await expectHs(record, HANDSHAKE_TYPE.client_hello, 'second ClientHello');
    ch = parseClientHello(ch2Msg.body);
    ch.raw = ch2Msg.raw.slice();
    state.clientHellos.push(ch);

    if (opts.hrr.second) {
      // A second HelloRetryRequest is forbidden (RFC 8446 s4.1.4); the client must abort.
      await record.writeHandshake([hrr]);
      state.stopped = 'second-hrr';
      drainQuietly(record);
      return;
    }

    // The ClientHello2 binder covers Transcript-Hash(message_hash(CH1) || HRR ||
    // Truncate(CH2)). The prefix is rebuilt here BY HAND — the message_hash framing included —
    // rather than through the Transcript class, so the client's s4.4.1 substitution is
    // cross-checked by arithmetic it does not share. Re-evaluated from scratch: the client may
    // legitimately have dropped the PSK if the HRR pinned a suite of a different hash.
    const ch1Digest = new Uint8Array(
      await crypto.subtle.digest(hash, state.clientHellos[0].raw));
    const hrrBinderPrefix = [
      concat([u8(HANDSHAKE_TYPE.message_hash), u24(ch1Digest.byteLength), ch1Digest]),
      hrr,
    ];
    resumption = await evaluatePsk(ch, hrrBinderPrefix, suite);
    if (resumption?.badBinder) {
      await record.sendAlert(ALERT_LEVEL.fatal, 51); // decrypt_error
      state.stopped = 'bad-binder';
      drainQuietly(record);
      return;
    }

    transcript.update(ch.raw);
    // Captured so the test can recompute this hash independently of the Transcript class:
    // client and server sharing one substitution bug must not be able to vouch for each other.
    state.transcriptHashAfterCh2 = await transcript.hash();
    suite = opts.hrr.cipherAfter ?? suite;
    hash = CIPHER_PARAMS[suite].hash;
  }

  // --- ServerHello -------------------------------------------------------------------------
  const group = opts.hrr
    ? opts.hrr.group
    // The first key_share this server can actually do, not simply the first one offered. A real
    // Chrome ClientHello leads with a GREASE entry (RFC 8701 requires a server to ignore it —
    // picking it is exactly what GREASE exists to catch, and it caught this server) followed by
    // X25519MLKEM768, and only then x25519.
    : (opts.shareGroup ?? opts.group ??
       ch.keyShares.find((k) => SUPPORTED_GROUPS.includes(k.group))?.group);
  if (group === undefined) throw new Error('test server: client offered no key share at all');
  const serverShare = opts.serverKeyPair ?? (await generateKeyShare(group, {}));

  const sh = buildServerHello({
    random: opts.serverRandom ?? crypto.getRandomValues(new Uint8Array(32)),
    sessionIdEcho: opts.sessionIdEcho ?? ch.sessionId,
    cipher: opts.wireCipher ?? suite,
    extensions: [
      // ServerHello form: a BARE uint16 selected_version — not the ClientHello list form.
      opts.omitSupportedVersions ? null : rawExtension(EXTENSION.supported_versions, u16(TLS13)),
      rawExtension(
        EXTENSION.key_share,
        concat([u16(group), vector(2, serverShare.keyExchange)]), // one KeyShareEntry, no list
      ),
      // pre_shared_key: a bare selected_identity (s4.2.11). pskSelectedIdentity scripts a
      // selection outside the offered range; pskSelectUnoffered a selection with no offer at
      // all. Both are the client's job to refuse.
      resumption || opts.pskSelectUnoffered
        ? rawExtension(EXTENSION.pre_shared_key, u16(opts.pskSelectedIdentity ?? 0))
        : null,
    ],
  });
  transcript.update(sh);
  await record.writeHandshake([sh]);
  if (opts.compatCcs) await record.writeChangeCipherSpec();

  const clientShare = ch.keyShares.find((k) => k.group === group);
  if (!clientShare) {
    // Scripted misbehaviour (shareGroup): the ServerHello named a group the client sent no
    // share for. There is nothing to derive; the client is now obliged to abort.
    state.stopped = 'no-client-share';
    drainQuietly(record);
    return;
  }

  // --- key schedule ------------------------------------------------------------------------
  const shared = await deriveSharedSecret(group, serverShare.privateKey, clientShare.keyExchange);
  // psk_dhe_ke: the Early Secret comes from the PSK when resuming, and the ECDHE share always
  // feeds the Handshake Secret — resumption changes the first extraction, nothing else.
  const early = await earlySecret(hash, resumption?.psk ?? null);
  const handshakeSecret = await deriveHandshakeSecret(hash, early, shared);
  const hsSecrets = await handshakeTrafficSecrets(hash, handshakeSecret, await transcript.hash());
  await record.setSendKeys({ cipher: suite, secret: hsSecrets.server });

  // --- server flight -----------------------------------------------------------------------
  const eeParts = [];
  if (opts.alpn) eeParts.push(encodeAlpn([opts.alpn]));
  for (const extra of opts.eeExtra ?? []) eeParts.push(extra);
  const ee = handshakeMessage(HANDSHAKE_TYPE.encrypted_extensions, vector(2, concat(eeParts)));

  let msgs;
  if (resumption && !opts.resumeSendCertificate) {
    // Resumed: the PSK authenticates, so the flight is EncryptedExtensions then Finished —
    // no Certificate, no CertificateVerify (RFC 8446 s2.2). resumeSendCertificate scripts the
    // violation of that rule, which the client must refuse.
    transcript.update(ee);
    const vd = await finishedVerifyData(hash, hsSecrets.server, await transcript.hash());
    if (opts.corruptFinished) vd[0] ^= 0xff;
    const fin = handshakeMessage(HANDSHAKE_TYPE.finished, vd);
    transcript.update(fin);
    state.flightLengths = [ee, fin].map((m) => m.byteLength);
    msgs = [ee, fin];
  } else {
    const chain = opts.emptyCertificateList ? [] : [identity.certDer, ...(opts.extraChain ?? [])];
    const entries = concat(chain.map((der, i) => {
      let exts = i === 0 && opts.staple ? stapleEntryExtension(opts.staple) : EMPTY;
      if (opts.entryExtensions?.[i] !== undefined) exts = opts.entryExtensions[i];
      return new Builder().vector(3, der).vector(2, exts).build();
    }));
    const certMsg = handshakeMessage(
      HANDSHAKE_TYPE.certificate,
      new Builder().vector(1, EMPTY).vector(3, entries).build(),
    );

    // CertificateVerify signs the transcript THROUGH Certificate; Finished MACs it THROUGH
    // CertificateVerify. The transcript itself always advances honestly — the wrong-transcript
    // misbehaviour lies only about which hash gets signed, which is exactly the attack shape.
    transcript.update(ee);
    const hashThroughEe = await transcript.hash();
    transcript.update(certMsg);
    const hashThroughCert = await transcript.hash();
    const signedHash =
      opts.cvTranscript === 'throughEncryptedExtensions' ? hashThroughEe : hashThroughCert;
    const signer = opts.signWith ?? identity.sign;
    const cv = handshakeMessage(
      HANDSHAKE_TYPE.certificate_verify,
      new Builder()
        .u16(opts.cvScheme ?? identity.scheme)
        .vector(2, signer(certificateVerifyContent(signedHash, true)))
        .build(),
    );
    transcript.update(cv);

    const vd = await finishedVerifyData(hash, hsSecrets.server, await transcript.hash());
    if (opts.corruptFinished) vd[0] ^= 0xff;
    const fin = handshakeMessage(HANDSHAKE_TYPE.finished, vd);
    transcript.update(fin);
    state.flightLengths = [ee, certMsg, cv, fin].map((m) => m.byteLength);

    msgs = [ee, certMsg, cv, fin];
    if (opts.flightOrder === 'certificateFirst') msgs = [certMsg, ee, cv, fin];
  }

  if (opts.alertAfter === 'encryptedExtensions') {
    await record.writeHandshake([ee]);
    await record.sendAlert(ALERT_LEVEL.fatal, opts.alertDesc ?? 40);
    state.stopped = 'alert';
    drainQuietly(record);
    return;
  }
  if (opts.closeAfter === 'encryptedExtensions') {
    await record.writeHandshake([ee]);
    await kill(); // EOF with no close_notify: a truncation, and the client must say so
    state.stopped = 'closed';
    drainQuietly(record);
    return;
  }
  if (opts.fragmentFlight) {
    // One record per slice: the test dictates exactly how messages align with records.
    for (const slice of opts.fragmentFlight(msgs)) await record.writeHandshake(slice);
  } else {
    await record.writeHandshake(msgs);
  }

  // --- application keys and the client's flight --------------------------------------------
  // Application secrets bind the transcript through the server Finished (RFC 8446 s7.1). The
  // server may send under them immediately (0.5-RTT) — which is precisely what makes "nothing
  // is readable before the client verified the chain" worth asserting from the client side.
  const masterSecret = await deriveMasterSecret(hash, handshakeSecret);
  const appSecrets = await applicationTrafficSecrets(hash, masterSecret, await transcript.hash());
  await record.setSendKeys({ cipher: suite, secret: appSecrets.server });
  if (opts.earlyAppData) await record.writeAppData(opts.earlyAppData);

  await record.setReceiveKeys({ cipher: suite, secret: hsSecrets.client });
  const clientFin = await expectHs(record, HANDSHAKE_TYPE.finished, 'client Finished');
  const expected = await finishedVerifyData(hash, hsSecrets.client, await transcript.hash());
  if (!timingSafeEqual(clientFin.body, expected)) {
    // A test server that accepted any Finished would let a client with a wrong transcript or
    // wrong keys "pass" every positive test. This check is the other half of the suite.
    throw new Error('test server: client Finished verify_data does not match the transcript');
  }
  state.finishedVerified = true;
  transcript.update(clientFin.raw);
  await record.setReceiveKeys({ cipher: suite, secret: appSecrets.client });
  record.markHandshakeComplete();
  state.negotiated = { cipher: suite, group, alpn: opts.alpn ?? null, resumed: Boolean(resumption) };

  // --- NewSessionTicket(s) ------------------------------------------------------------------
  // Issued from the server's OWN resumption_master_secret: its transcript, through the client
  // Finished it just verified. If the client's derivation differs — a transcript missing its
  // own Finished is the classic — the PSKs disagree and the next connection's binder fails
  // here, on independent arithmetic. Writes are queued but not awaited: the record layer's
  // write chain keeps them ordered before any later app data, and awaiting them would deadlock
  // a zero-buffer loopback whose client has not started reading (a real server does not block
  // its accept path on ticket delivery either). The cache is populated before the write is
  // queued, so a test may reconnect the moment `done` resolves.
  for (const [i, spec] of (opts.tickets ?? []).entries()) {
    if (spec.rawBody) {
      // Malformed-NST scripting: the bytes go out exactly as given, nothing is cached.
      record.writeHandshake([handshakeMessage(HANDSHAKE_TYPE.new_session_ticket, spec.rawBody)])
        .catch(() => {});
      continue;
    }
    const nonce = spec.nonce ?? u8(i);
    const resMaster = await resumptionMasterSecret(hash, masterSecret, await transcript.hash());
    const psk = await resumptionPsk(hash, resMaster, nonce);
    opts.sessionCache?.set(toHex(spec.ticket), { psk, hash });
    const body = new Builder()
      .push(u32(spec.lifetime ?? 3600))
      .push(u32(spec.ageAdd ?? 0))
      .vector(1, nonce)
      .vector(2, spec.ticket)
      .vector(2, spec.extensions ?? EMPTY)
      .build();
    record.writeHandshake([handshakeMessage(HANDSHAKE_TYPE.new_session_ticket, body)])
      .catch(() => {});
  }
}
