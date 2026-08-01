// TLS version negotiation: one ClientHello, one ServerHello, one dispatch.
//
// This is the entry point that offers TLS 1.3 and TLS 1.2 together, the way every real client
// does: a single ClientHello carrying supported_versions [1.3, 1.2], both cipher-suite sets, a
// key_share for 1.3, and the 1.2 compatibility extensions (extended_master_secret,
// ec_point_formats, renegotiation_info). The server picks; we continue down the matching driver
// on the SAME connection.
//
// What this file must never become is "try 1.3, and on failure reconnect at 1.2". That insecure
// fallback dance is the one browsers tore out (POODLE was its harvest): an attacker who can
// inject a TCP reset or a handshake_failure alert gets to choose the client's version. Here a
// failure is a failure — there is no code path that dials again, at any version, for any reason.
//
// Offering 1.2 next to 1.3 is exactly the configuration RFC 8446's downgrade protections exist
// for, and both run in this file's negotiation with the REAL offered list:
//
//   * the s4.1.3 sentinel in ServerHello.random — a 1.3-capable server pushed down to 1.2 by a
//     stripped ClientHello brands its random, and negotiateVersion aborts on the brand;
//   * the "selected version was not offered" check, which is what keeps 1.0/1.1 out entirely.
//
// The transcript rule from the drivers carries over unchanged and is the reason the preamble is
// shaped the way it is: the transcript hash is chosen by the negotiated cipher suite, which is
// only known from the ServerHello. So the ClientHello is held as raw bytes and the transcript is
// constructed here exactly once, under the right hash — never started under a guess and rebuilt,
// because rebuilding cannot reproduce the HelloRetryRequest substitution the 1.3 driver may have
// to perform on it.

import { TlsError, TlsUnsupportedError, codes, hex8 } from '../errors.js';
import { RecordLayer } from './record.js';
import { Transcript } from './transcript.js';
import {
  ALPN_HTTP11,
  CIPHER_PARAMS,
  HANDSHAKE_TYPE,
  SUPPORTED_GROUPS,
  TLS12,
  TLS12_CIPHERS,
  TLS13,
  TLS13_CIPHERS,
} from './constants.js';
import {
  buildClientHello,
  generateKeyShare,
  negotiateCipher,
  negotiateVersion,
  parseServerHello,
  setPskBinder,
} from './handshake-messages.js';
import { describeVersion } from './extensions.js';
import {
  earlySecret,
  finishedVerifyData,
  hashLength,
  resumptionBinderKey,
} from './keyschedule.js';
import { DEFAULT_OFFER_GROUPS, continueTls13 } from './handshake.js';
import { continueTls12, refuseHelloRequest } from './handshake12.js';

const DEFAULT_VERSIONS = [TLS13, TLS12];

/**
 * Validate and canonicalise the offer list. Newest first, always: supported_versions is a
 * preference list, and there is no configuration in which preferring 1.2 while also offering
 * 1.3 is anything but a downgrade written into the offer itself.
 */
function normalizeVersions(input) {
  if (input === undefined) return DEFAULT_VERSIONS;
  if (!Array.isArray(input) || input.length === 0) {
    throw new TlsError(
      codes.CONFIG_INVALID,
      'options.versions must be a non-empty array of TLS versions to offer',
    );
  }
  const out = [];
  for (const v of input) {
    if (v !== TLS13 && v !== TLS12) {
      throw new TlsUnsupportedError(
        codes.TLS_VERSION_UNSUPPORTED,
        `cannot offer ${describeVersion(v)}: only TLS 1.3 and TLS 1.2 are implemented. ` +
          'TLS 1.0 and 1.1 have no AEAD cipher suites, and SSL is long dead.',
        { version: v },
      );
    }
    if (!out.includes(v)) out.push(v);
  }
  return out.sort((a, b) => b - a);
}

/**
 * Demand that the first handshake message is a ServerHello. The one type refused BY NAME is
 * HelloRequest, and only when 1.2 is on the table: a 1.2 server may legally emit one at any
 * time, and the refusal must say "renegotiation" rather than "unknown type" (handshake12.js
 * owns that stance and its wording).
 */
function expectServerHello(msg, offers12) {
  if (msg === null) {
    throw new TlsError(
      codes.TLS_TRUNCATED,
      'server closed the connection during the handshake while ServerHello was expected',
      { expected: 'server_hello' },
    );
  }
  if (msg.ccs) {
    // In no version of TLS is a key change legal before the ServerHello; even 1.3's
    // compatibility CCS is specified to follow the server's first handshake message.
    throw new TlsError(codes.TLS_RECORD, 'change_cipher_spec arrived where ServerHello was expected', {
      expected: 'server_hello',
    });
  }
  if (offers12 && msg.type === 0) refuseHelloRequest(); // 0 = HelloRequest, deliberately unnamed
  if (msg.type !== HANDSHAKE_TYPE.server_hello) {
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      `server sent handshake type ${hex8(msg.type)} where ServerHello was expected`,
      { got: msg.type, expected: HANDSHAKE_TYPE.server_hello },
    );
  }
  return msg;
}

/**
 * A byte duplex: what every layer in this package consumes and produces.
 * @typedef {{ readable: ReadableStream<Uint8Array>,
 *             writable: WritableStream<Uint8Array> }} ByteDuplex
 */

/**
 * Handshake knobs. Every one of these narrows what is offered; none can widen it beyond what
 * `constants.js` permits, so no option here can talk the client into a suite it refuses.
 *
 * @typedef {object} TlsOptions
 * @property {number[]} [versions] versions to offer, from `TLS13` / `TLS12`. Default both.
 * @property {string[]} [alpn] ALPN protocols to offer. Default `['http/1.1']`.
 * @property {number[]} [groups] supported_groups, in preference order.
 * @property {number[]} [offerGroups] groups to send an actual key_share for. Default the first
 *   supported group; a HelloRetryRequest recovers any other choice at the cost of a round trip.
 * @property {number[]} [ciphers] cipher suites to offer, in preference order.
 * @property {number[]} [sigSchemes] signature_algorithms to offer, in preference order.
 * @property {number[]} [extensionOrder] ClientHello extension types, in the order to emit them.
 *   JA3 and JA4 hash the extension list in WIRE ORDER, so this is most of what a fingerprinter
 *   reads. Defaults to curl's order (`CURL_EXTENSION_ORDER`). Extensions not named keep their
 *   natural position at the end; `pre_shared_key` is always last whatever is asked, because RFC
 *   8446 s4.2.11 defines the binder transcript as the hello truncated just before the binders.
 * @property {Uint8Array} [clientRandom] fixed ClientHello.random, for reproducible handshakes.
 * @property {Uint8Array} [legacySessionId] fixed legacy_session_id, likewise.
 * @property {boolean} [compatibilityCcs] send the middlebox-compatibility ChangeCipherSpec.
 *   Default true.
 * @property {number} [maxHandshakeMessage] per-message cap; certificate chains dominate sizing.
 * @property {number} [maxKeyUpdates] received KeyUpdates tolerated before it is called a flood.
 * @property {number} [maxTranscriptBytes] cap on buffered handshake transcript.
 * @property {ResumptionOffer} [psk] offer this resumption PSK (TLS 1.3 only; requires 1.3 in
 *   the offered versions). The server may decline, in which case the full handshake continues
 *   on this same connection — there is no reconnect at any layer.
 * @property {(ticket: CapturedTicket) => void} [onSessionTicket] receive each NewSessionTicket
 *   this connection yields, already reduced to a usable PSK per RFC 8446 s7.1. Without this the
 *   tickets are read and discarded, exactly as before.
 */

/**
 * A resumption PSK ready to offer, as produced by the ticket store from a CapturedTicket.
 * `obfuscatedTicketAge` is a closure, not a number, because the age must be current at the
 * moment each hello is BUILT — a HelloRetryRequest builds a second hello later — and because
 * clock policy belongs to the store, not to this layer (which otherwise never reads a clock).
 * `peer` rides along opaquely: it is whatever the original session's verifyPeer resolved with,
 * and a resumed session (which has no Certificate message to verify) reports it as its own —
 * sound only because the ticket store keys tickets by the full trust configuration.
 * @typedef {object} ResumptionOffer
 * @property {Uint8Array} identity the ticket
 * @property {Uint8Array} psk
 * @property {import('./keyschedule.js').ScheduleHash} hash the hash the PSK was minted under
 * @property {() => number} obfuscatedTicketAge uint32 per RFC 8446 s4.2.11.1
 * @property {object} [peer]
 */

/**
 * What a NewSessionTicket becomes by the time a caller sees it: the wire fields that govern
 * offering (lifetime, age_add) plus the derived PSK and everything needed to check a future
 * selection against it. `maxEarlyDataSize` is recorded for honesty but never acted on: 0-RTT
 * is deliberately not implemented (see the driver's note).
 * @typedef {object} CapturedTicket
 * @property {Uint8Array} identity
 * @property {Uint8Array} psk
 * @property {import('./keyschedule.js').ScheduleHash} hash
 * @property {number} cipherSuite
 * @property {number} lifetimeSec
 * @property {number} ageAdd
 * @property {number | null} maxEarlyDataSize
 * @property {string | null} alpnProtocol
 * @property {object} peer
 */

/**
 * Injectable nondeterminism. Supplying these makes a handshake byte-for-byte reproducible, which
 * is what allows a recorded session to be replayed in an offline test.
 * @typedef {object} TlsDeps
 * @property {(n: number) => Uint8Array} [randomBytes]
 * @property {(algorithm: object, group: number) => Promise<CryptoKeyPair>} [generateKeyPair]
 */

/**
 * What a completed handshake reports about itself.
 * @typedef {object} TlsSessionInfo
 * @property {number} version negotiated version, `0x0304` or `0x0303`
 * @property {number} cipherSuite negotiated suite
 * @property {number} group negotiated key-exchange group
 * @property {string | null} alpnProtocol
 * @property {string} hostname the identity the certificate was required to prove
 * @property {boolean} [extendedMasterSecret] TLS 1.2 only: whether RFC 7627 was in effect
 * @property {boolean} [resumed] TLS 1.3 only: the server accepted the offered resumption PSK,
 *   so no certificate crossed the wire on THIS connection; the identity is the one validated
 *   by the original handshake the ticket came from
 */

/**
 * A live TLS session: a plaintext duplex plus what was negotiated to get it.
 * @typedef {object} TlsSession
 * @property {ReadableStream<Uint8Array>} readable
 * @property {WritableStream<Uint8Array>} writable
 * @property {import('./record.js').RecordLayer} record
 * @property {object} peer whatever `verifyPeer` resolved with: the validated leaf
 * @property {TlsSessionInfo} info
 * @property {() => Promise<void>} close
 */

/**
 * Run a TLS handshake over a byte duplex, negotiating the version, and return the plaintext
 * duplex above it. The default offer is [TLS 1.3, TLS 1.2]; `options.versions` narrows it.
 *
 * @param {object} args
 * @param {ByteDuplex} args.transport
 * @param {string} args.hostname the identity the certificate must prove, and the SNI sent
 * @param {import('./handshake.js').VerifyPeer} args.verifyPeer
 *   Must throw to reject. Resolves with the validated leaf; its SPKI is the only key either
 *   driver will accept a handshake signature from. Receives the peer's stapled OCSP response,
 *   when there is one, as its third argument.
 * @param {TlsOptions} [args.options]
 * @param {TlsDeps} [args.deps]
 * @returns {Promise<TlsSession>}
 */
export async function connectTls({ transport, hostname, verifyPeer, options = {}, deps = {} }) {
  if (typeof verifyPeer !== 'function') {
    // Refusing to start is the only safe default. A missing verifier must never read as "skip".
    throw new TlsError(
      codes.CONFIG_INVALID,
      'connectTls requires a verifyPeer function; there is no unverified mode',
    );
  }
  const versions = normalizeVersions(options.versions);
  const record = new RecordLayer(transport, {
    maxHandshakeMessage: options.maxHandshakeMessage,
    maxKeyUpdates: options.maxKeyUpdates,
  });
  // Until the ServerHello picks, the record layer speaks the LOWEST version offered. The two
  // semantics that differ before any ServerHello are alert tolerance and CCS handling, and the
  // 1.2 discipline is right for both while 1.2 is a version we are willing to end up on: a 1.2
  // server may send warning alerts (unrecognized_name, famously) that must not kill an offer
  // that includes 1.2, and a CCS before ServerHello is fatal in every version — surfaced as an
  // event here and refused by expectServerHello above. Once the ServerHello lands the version
  // is pinned for real, before any key is installed.
  record.setVersion(versions.includes(TLS12) ? TLS12 : TLS13);
  try {
    return await drive({ record, hostname, verifyPeer, options, deps, versions });
  } catch (err) {
    // Leaving a peer waiting on a half-open connection is a real interop problem, and the alert
    // is the only signal a server operator gets about why we hung up. Best effort: the transport
    // may already be gone, and the original error is what the caller needs.
    try {
      await record.abort();
    } catch {
      /* transport already unusable */
    }
    throw err;
  }
}

async function drive({ record, hostname, verifyPeer, options, deps, versions }) {
  const offers13 = versions.includes(TLS13);
  const offers12 = versions.includes(TLS12);
  const alpn = options.alpn ?? [ALPN_HTTP11];
  const groups = options.groups ?? SUPPORTED_GROUPS;
  const offerGroups = options.offerGroups ?? DEFAULT_OFFER_GROUPS;
  // Suites for every offered version, 1.3 first. negotiateCipher later re-checks the family of
  // the server's pick against the negotiated version, so a union offer cannot be abused to run
  // a 1.3 suite under 1.2 or the reverse.
  const ciphers = options.ciphers ?? [
    ...(offers13 ? TLS13_CIPHERS : []),
    ...(offers12 ? TLS12_CIPHERS : []),
  ];

  // --- resumption offer ----------------------------------------------------------------------
  // Everything about the offered PSK that later steps need is derived once, up front: the Early
  // Secret and binder key here (they depend only on the PSK), the binder itself per hello (it
  // depends on each hello's bytes). psk_dhe_ke is the only mode ever offered, so acceptance
  // still runs a fresh key exchange and a leaked ticket cannot unlock recorded traffic.
  let pskOffer = null;
  if (options.psk) {
    const { identity, psk, hash, obfuscatedTicketAge, peer } = options.psk;
    if (!offers13) {
      throw new TlsError(codes.CONFIG_INVALID,
        'options.psk offers a TLS 1.3 resumption PSK but TLS 1.3 is not among the offered versions');
    }
    // The PSK can only be selected together with a suite of its own hash (RFC 8446 s4.2.11).
    // Offering one no offered suite could carry is a wiring bug upstream, not a server choice,
    // and must fail here rather than surface as a mysteriously-always-full handshake.
    const usable = ciphers.some((c) => CIPHER_PARAMS[c]?.hash === hash);
    if (!usable) {
      throw new TlsError(codes.CONFIG_INVALID,
        `options.psk was minted under ${hash} but no offered cipher suite uses that hash`,
        { hash, ciphers });
    }
    const early = await earlySecret(hash, psk);
    pskOffer = {
      identity, psk, hash, obfuscatedTicketAge, peer: peer ?? null,
      earlySecret: early,
      binderKey: await resumptionBinderKey(hash, early),
      binderLen: hashLength(hash),
    };
  }

  // --- ClientHello ---------------------------------------------------------------------------
  // ONE hello for every offered version. Key shares ride in a 1.3-only extension, so they are
  // generated only when 1.3 is on the table; a 1.2-only offer must not pay for a key it can
  // never use (and must stay byte-identical to what handshakeTls12 always sent).
  const keyShares = [];
  if (offers13) {
    for (const g of offerGroups) keyShares.push(await generateKeyShare(g, deps));
  }
  const hello = buildClientHello({
    hostname,
    keyShares,
    groups,
    alpn,
    ciphers,
    versions,
    extensionOrder: options.extensionOrder,
    sigSchemes: options.sigSchemes,
    random: options.clientRandom,
    legacySessionId: options.legacySessionId,
    psk: pskOffer && {
      identity: pskOffer.identity,
      obfuscatedTicketAge: pskOffer.obfuscatedTicketAge(),
      binderLen: pskOffer.binderLen,
    },
    randomBytes: deps.randomBytes,
  });
  if (pskOffer) {
    // The binder (RFC 8446 s4.2.11.2): an HMAC under the binder key over the transcript of THIS
    // hello truncated just before the binders list, hashed with the PSK's OWN hash — the
    // negotiated suite does not exist yet and has no say. For the first hello that transcript
    // is just the truncated message; no Transcript object exists this early, deliberately (its
    // hash is the suite's, chosen later). The patched message is what the transcript and the
    // wire both get, so the binder is inside every later hash of this hello.
    const truncatedHash = new Uint8Array(await crypto.subtle.digest(
      pskOffer.hash, hello.message.subarray(0, hello.truncatedLength)));
    setPskBinder(hello, await finishedVerifyData(pskOffer.hash, pskOffer.binderKey, truncatedHash));
  }
  await record.writeHandshake([hello.message]);

  // --- ServerHello: the server picks, we dispatch --------------------------------------------
  const first = expectServerHello(await record.nextHandshakeMessage(), offers12);
  const sh = parseServerHello(first.body);

  if (sh.isHelloRetryRequest && !offers13) {
    // The HelloRetryRequest random is a fixed TLS 1.3 constant; an honest 1.2 server hits it
    // with probability 2^-256. Seeing it means a 1.3 message was spliced into this handshake.
    throw new TlsError(
      codes.TLS_HANDSHAKE,
      'ServerHello.random is the TLS 1.3 HelloRetryRequest sentinel, which cannot occur in an ' +
        'honest TLS 1.2 handshake',
    );
  }

  // HelloRetryRequest is TLS 1.3 only, so an HRR decides the version by itself; the 1.3 driver
  // re-runs negotiateVersion on the real ServerHello that follows it. Otherwise the ServerHello
  // decides here — and this call, with the full offered list, is what makes the RFC 8446 s4.1.3
  // downgrade sentinel and the not-offered check live.
  const version = sh.isHelloRetryRequest
    ? TLS13
    : negotiateVersion(sh, { offeredVersions: versions });

  // The suite is known now, from either the HelloRetryRequest or the real ServerHello, so the
  // transcript can be created exactly once under the correct hash. It is fed the ClientHello
  // only; folding in the ServerHello is the driver's job, because the 1.3 driver may first have
  // to replace the ClientHello with its message_hash form (RFC 8446 s4.4.1).
  const { suite, params } = negotiateCipher(sh, { offeredCiphers: hello.offeredCiphers, version });
  const transcript = new Transcript(params.hash, { maxBytes: options.maxTranscriptBytes });
  transcript.update(hello.message);

  const ctx = {
    record,
    transcript,
    hello,
    serverHello: sh,
    rawServerHello: first.raw,
    suite,
    params,
    hostname,
    verifyPeer,
    options,
    deps,
    offer: { versions, ciphers: hello.offeredCiphers, groups, offerGroups, alpn, keyShares,
      psk: pskOffer },
  };

  if (version === TLS13) {
    // Pin the record layer before the driver reads on: a 1.3 server's compatibility CCS may
    // arrive right behind the ServerHello and must be dropped, not surfaced as a 1.2 key-change
    // event. No keys exist yet, so the pin is still legal.
    record.setVersion(TLS13);
    return continueTls13(ctx);
  }
  // version can only be TLS12 here (negotiateVersion refuses anything unoffered), and the
  // record layer is already in 1.2 mode: TLS12 ∈ versions is what put it there.
  return continueTls12(ctx);
}
