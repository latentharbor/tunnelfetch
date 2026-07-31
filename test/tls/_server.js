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
} from '../../src/tls/keyschedule.js';
import { Builder, Cursor, handshakeMessage, vector } from '../../src/tls/wire.js';
import {
  ALERT_LEVEL,
  CIPHER_PARAMS,
  EXTENSION,
  HANDSHAKE_TYPE,
  HELLO_RETRY_REQUEST_RANDOM,
  LEGACY_VERSION,
  TLS13,
  TLS13_CIPHERS,
} from '../../src/tls/constants.js';
import { concat, timingSafeEqual, u16 } from '../../src/util/bytes.js';

const EMPTY = new Uint8Array(0);

/** `extension_type || extension_data<0..2^16-1>`, shared with the tests for misbehaviour. */
export function rawExtension(type, data) {
  return new Builder().u16(type).vector(2, data).build();
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

  return {
    legacyVersion, random, sessionId, cipherSuites, extensions,
    keyShares, versions, alpn, serverName, cookie,
  };
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
    negotiated: null,
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

  let suite = opts.cipher ?? TLS13_CIPHERS.find((c) => ch.cipherSuites.includes(c));
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
    : (opts.shareGroup ?? opts.group ?? ch.keyShares[0]?.group);
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
  const early = await earlySecret(hash);
  const handshakeSecret = await deriveHandshakeSecret(hash, early, shared);
  const hsSecrets = await handshakeTrafficSecrets(hash, handshakeSecret, await transcript.hash());
  await record.setSendKeys({ cipher: suite, secret: hsSecrets.server });

  // --- server flight -----------------------------------------------------------------------
  const eeParts = [];
  if (opts.alpn) eeParts.push(encodeAlpn([opts.alpn]));
  for (const extra of opts.eeExtra ?? []) eeParts.push(extra);
  const ee = handshakeMessage(HANDSHAKE_TYPE.encrypted_extensions, vector(2, concat(eeParts)));

  const chain = opts.emptyCertificateList ? [] : [identity.certDer, ...(opts.extraChain ?? [])];
  const entries = concat(chain.map((der) => new Builder().vector(3, der).vector(2, EMPTY).build()));
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

  let msgs = [ee, certMsg, cv, fin];
  if (opts.flightOrder === 'certificateFirst') msgs = [certMsg, ee, cv, fin];

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
  state.negotiated = { cipher: suite, group, alpn: opts.alpn ?? null };
}
