// TLS 1.3 session resumption: NewSessionTicket capture, the PSK binder, offer/accept/decline,
// and the ticket store's keying discipline.
//
// Two independent authorities police the binder, because it is the piece a loopback test is
// structurally unable to vouch for on its own — truncate the transcript at the wrong offset on
// both sides and every self-test still passes:
//
//  * RFC 8448 section 4 pins the derivation byte-for-byte: the PSK minted from the section 3
//    trace must produce the trace's own binder over the trace's own ClientHello, whose 477-byte
//    truncation the RFC prints separately from the 512-byte message.
//  * The scripted server in _server.js recomputes the truncation offset from ITS OWN parse of
//    the wire bytes and rejects a bad binder with decrypt_error, exactly as s4.2.11.2 requires
//    of a real server — so the positive loopbacks prove interop, not self-consistency.
//
// The store tests are the security heart: a ticket is a credential, and the store must refuse
// to hand one across trust configurations, across proxies, or past its lifetime.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sign as nodeSign } from 'node:crypto';

import { handshakeTls13 } from '../../src/tls/handshake.js';
import {
  buildClientHello,
  generateKeyShare,
  parseNewSessionTicket,
  parseServerHello,
  setPskBinder,
} from '../../src/tls/handshake-messages.js';
import { decodeServerPreSharedKey, pskBinderTrailerLength } from '../../src/tls/extensions.js';
import {
  earlySecret,
  finishedKey,
  finishedVerifyData,
  resumptionBinderKey,
  resumptionPsk,
} from '../../src/tls/keyschedule.js';
import { TicketStore } from '../../src/tls/tickets.js';
import { poolKey } from '../../src/pool.js';
import { Client } from '../../src/client.js';
import { CIPHER, EXTENSION, GROUP, SIG_SCHEME, TLS12 } from '../../src/tls/constants.js';
import { codes } from '../../src/errors.js';
import { Builder, Cursor } from '../../src/tls/wire.js';
import { concat, latin1, toHex, u16, u32, utf8 } from '../../src/util/bytes.js';
import { duplexPair, rejectsWithCode } from '../_harness.js';
import { rawExtension, startServer } from './_server.js';
import { testIdentity } from './_testca.js';
import { caFixture, makeOcspResponse } from '../trust/_certs.js';
import { RFC8448_1RTT, RFC8448_RESUMED } from './_vectors.js';

const HOST = 'server.test';
const AES128 = CIPHER.TLS_AES_128_GCM_SHA256;
const AES256 = CIPHER.TLS_AES_256_GCM_SHA384;
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);
const EMPTY = new Uint8Array(0);

// ================================================================ RFC 8448 section 4 pins

test('the section 3 PSK reproduces the section 4 early secret and binder key', async () => {
  const early = await earlySecret('SHA-256', RFC8448_1RTT.resumptionPsk);
  eq(early, RFC8448_RESUMED.earlySecretWithPsk, 'Early Secret extracted from the PSK');
  const bk = await resumptionBinderKey('SHA-256', early);
  eq(bk, RFC8448_RESUMED.binderKey, 'binder_key (Derive-Secret "res binder")');
  eq(await finishedKey('SHA-256', bk), RFC8448_RESUMED.binderFinishedKey,
    'the binder finished key');
});

test('the binder transcript is the hello truncated at length minus the binders list', async () => {
  const ch = RFC8448_RESUMED.clientHello;
  assert.equal(ch.byteLength, 512);
  // One SHA-256 binder: 2 (list length) + 1 (entry length) + 32. The RFC prints the truncation
  // it hashed as a separate 477-octet value; our arithmetic must land on the same bytes.
  assert.equal(pskBinderTrailerLength(32), 35);
  const truncated = ch.subarray(0, ch.byteLength - pskBinderTrailerLength(32));
  eq(truncated, RFC8448_RESUMED.clientHelloPrefix, 'truncated ClientHello');
  const th = new Uint8Array(await crypto.subtle.digest('SHA-256', truncated));
  eq(th, RFC8448_RESUMED.binderHash, 'binder transcript hash');

  const early = await earlySecret('SHA-256', RFC8448_1RTT.resumptionPsk);
  const bk = await resumptionBinderKey('SHA-256', early);
  const binder = await finishedVerifyData('SHA-256', bk, th);
  eq(binder, RFC8448_RESUMED.binder, 'the binder itself');
  // And the trace's hello carries exactly that binder as its trailing bytes.
  eq(ch.subarray(ch.byteLength - 32), RFC8448_RESUMED.binder, 'binder in the wire image');
});

test('parseNewSessionTicket reads the section 3 ticket; its PSK matches the trace', async () => {
  const body = RFC8448_1RTT.newSessionTicket.subarray(4); // strip the handshake header
  const t = parseNewSessionTicket(body);
  assert.equal(t.lifetimeSec, 30);
  assert.equal(t.ageAdd, 0xfad6aac5);
  eq(t.nonce, RFC8448_1RTT.resumptionNonce, 'ticket_nonce');
  assert.equal(t.ticket.byteLength, 178);
  // The trace's ticket permits 0-RTT; we record the advertisement and never use it.
  assert.equal(t.maxEarlyDataSize, 1024);
  eq(await resumptionPsk('SHA-256', RFC8448_1RTT.resumptionMaster, t.nonce),
    RFC8448_1RTT.resumptionPsk, 'PSK minted from the ticket');
  // The identity offered in the section 4 hello is this very ticket.
  assert.ok(toHex(RFC8448_RESUMED.clientHello).includes(toHex(t.ticket)),
    'the resumed hello offers the ticket as its PSK identity');
});

test('decodeServerPreSharedKey reads the resumed-trace ServerHello: identity 0', () => {
  const sh = parseServerHello(RFC8448_RESUMED.serverHello.subarray(4));
  const ext = sh.extensions.get(EXTENSION.pre_shared_key);
  assert.ok(ext, 'the resumed ServerHello carries pre_shared_key');
  assert.equal(decodeServerPreSharedKey(ext), 0);
});

// ================================================================ hello construction

/** Walk a built ClientHello to its extension list: [{type, data}], in wire order. */
function helloExtensions(message) {
  const c = new Cursor(message.subarray(4), 'ClientHello');
  c.u16('legacy_version');
  c.take(32, 'random');
  c.vector(1, 'session id');
  c.vector(2, 'cipher suites');
  c.vector(1, 'compression');
  const block = new Cursor(c.vector(2, 'extensions'), 'extensions');
  const out = [];
  while (!block.done) out.push({ type: block.u16('type'), data: block.vector(2, 'data') });
  return out;
}

test('buildClientHello puts pre_shared_key last, placeholder zeroed, offsets exact', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  const identity = utf8('ticket-ticket-ticket');
  const hello = buildClientHello({
    hostname: HOST, keyShares: [share],
    psk: { identity, obfuscatedTicketAge: 0x11223344, binderLen: 32 },
  });
  assert.equal(hello.message.byteLength - hello.binderOffset, 32);
  assert.equal(hello.truncatedLength, hello.message.byteLength - 35);
  assert.ok(hello.offeredExtensions.has(EXTENSION.pre_shared_key));
  assert.ok(hello.offeredExtensions.has(EXTENSION.psk_key_exchange_modes));

  const exts = helloExtensions(hello.message);
  assert.equal(exts[exts.length - 1].type, EXTENSION.pre_shared_key,
    'pre_shared_key must be the last extension (RFC 8446 s4.2.11)');
  const data = exts[exts.length - 1].data;
  const pc = new Cursor(data, 'pre_shared_key');
  const ids = pc.sub(2, 'identities');
  eq(ids.vector(2, 'identity'), identity, 'offered identity');
  assert.equal(ids.u32('obfuscated age'), 0x11223344);
  ids.end('identities');
  const binders = pc.sub(2, 'binders');
  const placeholder = binders.vector(1, 'binder');
  assert.ok(placeholder.every((b) => b === 0), 'binder is zeroed until patched');
  pc.end('pre_shared_key');

  const binder = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  setPskBinder(hello, binder);
  eq(hello.message.subarray(hello.binderOffset), binder, 'patched binder');
  // Wrong-length patches must throw rather than silently corrupt the message.
  assert.throws(() => setPskBinder(hello, new Uint8Array(31)), (e) => e.code === codes.CONFIG_INVALID);
  // And a hello with no placeholder refuses any patch.
  const plain = buildClientHello({ hostname: HOST, keyShares: [share] });
  assert.throws(() => setPskBinder(plain, binder), (e) => e.code === codes.CONFIG_INVALID);
});

test('a hello without a PSK is byte-identical to before the feature existed', async () => {
  // The recorded warmup handshake and every non-resuming caller depend on this.
  const share = await generateKeyShare(GROUP.x25519);
  const a = buildClientHello({
    hostname: HOST, keyShares: [share],
    random: new Uint8Array(32), legacySessionId: new Uint8Array(32),
  });
  const b = buildClientHello({
    hostname: HOST, keyShares: [share],
    random: new Uint8Array(32), legacySessionId: new Uint8Array(32), psk: null,
  });
  eq(a.message, b.message, 'psk: null must not perturb the encoding');
  assert.equal(a.binderOffset, undefined);
});

test('offering a PSK without TLS 1.3, or without a suite of its hash, is refused', async () => {
  const share = await generateKeyShare(GROUP.x25519);
  assert.throws(
    () => buildClientHello({
      hostname: HOST, keyShares: [], versions: [TLS12],
      psk: { identity: utf8('t'), obfuscatedTicketAge: 0, binderLen: 32 },
    }),
    (e) => e.code === codes.CONFIG_INVALID,
  );
  // A PSK minted under SHA-384 offered alongside SHA-256-only suites can never be selected;
  // that is a wiring bug and must fail loudly at connect time, not read as a server decline.
  const { a } = duplexPair();
  await rejectsWithCode(
    () => handshakeTls13({
      transport: a, hostname: HOST, verifyPeer: async () => ({ spki: { spkiDer: new Uint8Array(1) } }),
      options: {
        ciphers: [AES128],
        psk: { identity: utf8('t'), psk: new Uint8Array(48), hash: 'SHA-384',
          obfuscatedTicketAge: () => 0 },
      },
    }),
    codes.CONFIG_INVALID, /SHA-384/);
  void share;
});

// ================================================================ loopback plumbing

/** verifyPeer stub: records calls, accepts, returns the identity's real SPKI. */
function acceptStub(identity) {
  const verifyPeer = async (chain, hostname) => {
    verifyPeer.calls.push({ hostname });
    return { spki: { spkiDer: identity.spkiDer }, stub: true };
  };
  verifyPeer.calls = [];
  return verifyPeer;
}

/** One loopback handshake that must succeed; the server is scripted by `server`. */
async function connect13({ identity, server = {}, options = {}, verifyPeer }) {
  const { a, b } = duplexPair();
  const srv = startServer(b, identity, server);
  const vp = verifyPeer ?? acceptStub(identity);
  const tls = await handshakeTls13({ transport: a, hostname: HOST, verifyPeer: vp, options });
  const state = await srv.done;
  return { tls, srv, state, verifyPeer: vp };
}

/**
 * Drain queued NewSessionTickets through the client. The client read is started FIRST: on a
 * zero-buffer loopback the server's app-data write only completes once the client pulls the
 * queued ticket records through, so awaiting the write before reading would deadlock.
 */
async function pumpTickets(tls, srv) {
  const read = tls.record.readAppData();
  await srv.record.writeAppData(utf8('*'));
  assert.equal(latin1(await read), '*');
}

/** Full handshake against a ticket-issuing server; returns the tickets the client captured. */
async function establish({ identity, sessionCache, tickets, options = {} }) {
  const captured = [];
  const r = await connect13({
    identity,
    server: { sessionCache, tickets },
    options: { ...options, onSessionTicket: (t) => captured.push(t) },
  });
  await pumpTickets(r.tls, r.srv);
  return { ...r, captured };
}

const KEY = 'test-key';

/** A ResumptionOffer built the way the Client builds one: through the store. */
function offerFrom(captured, { now = () => 1000 } = {}) {
  const store = new TicketStore({ now });
  assert.equal(store.put(KEY, captured), true);
  const offer = store.take(KEY);
  assert.ok(offer, 'the freshly stored ticket must be offerable');
  return offer;
}

// ================================================================ the loopback handshakes

test('a captured ticket resumes the next connection: no certificate, no verifyPeer', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const first = await establish({
    identity, sessionCache,
    tickets: [
      { ticket: utf8('ticket-alpha'), lifetime: 3600, ageAdd: 0x01020304 },
      { ticket: utf8('ticket-beta'), lifetime: 7200, ageAdd: 0x0a0b0c0d },
    ],
  });
  assert.equal(first.tls.info.resumed, false);
  assert.equal(first.verifyPeer.calls.length, 1, 'the first connection validates the chain');
  assert.equal(first.captured.length, 2);
  const [alpha, beta] = first.captured;
  assert.equal(latin1(alpha.identity), 'ticket-alpha');
  assert.equal(alpha.lifetimeSec, 3600);
  assert.equal(alpha.ageAdd, 0x01020304);
  assert.equal(alpha.hash, 'SHA-256');
  assert.equal(alpha.cipherSuite, AES128);
  assert.equal(alpha.maxEarlyDataSize, null);
  assert.equal(alpha.psk.byteLength, 32);
  assert.equal(alpha.peer.stub, true, 'the validated peer rides with the ticket');
  assert.notEqual(toHex(alpha.psk), toHex(beta.psk), 'each nonce mints a distinct PSK');

  // Second connection: offer the newest ticket. The server verifies the binder against its own
  // independently computed truncation, selects identity 0, and sends no certificate at all.
  const offer = offerFrom(beta);
  const second = await connect13({
    identity, server: { sessionCache }, options: { psk: offer },
  });
  assert.equal(second.tls.info.resumed, true);
  assert.equal(second.state.negotiated.resumed, true);
  assert.equal(second.state.binderVerified, true, 'the server actually checked the binder');
  assert.equal(second.verifyPeer.calls.length, 0,
    'a resumed handshake must not invoke chain validation');
  assert.equal(second.state.flightLengths.length, 2,
    'the resumed server flight is EncryptedExtensions and Finished only');
  assert.equal(second.tls.peer, beta.peer,
    'the resumed session reports the peer the ORIGINAL handshake validated');
  // The offer's bookkeeping: obfuscated age at a frozen clock is exactly the age_add.
  assert.equal(second.state.clientHellos[0].psk.identities[0].obfuscatedAge, 0x0a0b0c0d);
  assert.equal(second.state.clientHellos[0].psk.isLastExtension, true);

  // Application data flows both ways on the resumed session. Reads start before the peer's
  // write is awaited: on the zero-buffer loopback a write only completes once the peer reads.
  const read = second.tls.record.readAppData();
  await second.srv.record.writeAppData(utf8('pong'));
  assert.equal(latin1(await read), 'pong');
  const echo = second.srv.record.readAppData();
  await second.tls.record.writeAppData(utf8('ping'));
  assert.equal(latin1(await echo), 'ping');
});

test('a declined PSK continues the full handshake on the same connection', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const first = await establish({
    identity, sessionCache, tickets: [{ ticket: utf8('spurned'), lifetime: 3600 }],
  });
  const offer = offerFrom(first.captured[0]);
  const second = await connect13({
    identity, server: { sessionCache, declinePsk: true }, options: { psk: offer },
  });
  assert.equal(second.tls.info.resumed, false);
  assert.equal(second.state.negotiated.resumed, false);
  assert.equal(second.verifyPeer.calls.length, 1,
    'a declined offer falls back to certificate validation, on this same connection');
  assert.equal(second.state.finishedVerified, true);
  assert.equal(second.state.flightLengths.length, 4, 'full certificate flight');
});

test('a resumed connection mints fresh tickets, chaining resumption', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const first = await establish({
    identity, sessionCache, tickets: [{ ticket: utf8('gen-one'), lifetime: 3600 }],
  });

  // Second connection resumes AND captures a new ticket minted on the resumed schedule —
  // its resumption master secret comes from a PSK-based early secret, which is exactly the
  // derivation a bug in the resumed key schedule would corrupt.
  const capturedTwo = [];
  const second = await connect13({
    identity,
    server: { sessionCache, tickets: [{ ticket: utf8('gen-two'), lifetime: 3600 }] },
    options: { psk: offerFrom(first.captured[0]), onSessionTicket: (t) => capturedTwo.push(t) },
  });
  assert.equal(second.tls.info.resumed, true);
  await pumpTickets(second.tls, second.srv);
  assert.equal(capturedTwo.length, 1);
  assert.equal(latin1(capturedTwo[0].identity), 'gen-two');

  // Third connection resumes from the second's ticket. If either side derived the resumed
  // resumption_master_secret wrong, the server's independent binder check fails here.
  const third = await connect13({
    identity, server: { sessionCache }, options: { psk: offerFrom(capturedTwo[0]) },
  });
  assert.equal(third.tls.info.resumed, true);
  assert.equal(third.state.binderVerified, true);
});

// ================================================================ server misbehaviour

async function establishOffer(identity, sessionCache, ticket = 'mut-ticket') {
  const first = await establish({
    identity, sessionCache, tickets: [{ ticket: utf8(ticket), lifetime: 3600 }],
  });
  return offerFrom(first.captured[0]);
}

test('a selected identity that was not offered is refused', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const offer = await establishOffer(identity, sessionCache);
  const { a, b } = duplexPair();
  startServer(b, identity, { sessionCache, pskSelectedIdentity: 7 });
  await rejectsWithCode(
    () => handshakeTls13({
      transport: a, hostname: HOST, verifyPeer: acceptStub(identity), options: { psk: offer },
    }),
    codes.TLS_PSK, /identity 7/);
});

test('pre_shared_key selected when none was offered is refused', async () => {
  const identity = testIdentity('ecdsa-p256');
  const { a, b } = duplexPair();
  startServer(b, identity, { pskSelectUnoffered: true });
  await rejectsWithCode(
    () => handshakeTls13({ transport: a, hostname: HOST, verifyPeer: acceptStub(identity) }),
    codes.TLS_PSK, /offered none/);
});

test('accepting the PSK under a suite of the wrong hash is refused', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const offer = await establishOffer(identity, sessionCache);
  const { a, b } = duplexPair();
  startServer(b, identity, { sessionCache, resumeCipher: AES256 });
  const err = await rejectsWithCode(
    () => handshakeTls13({
      transport: a, hostname: HOST, verifyPeer: acceptStub(identity), options: { psk: offer },
    }),
    codes.TLS_PSK, /SHA-384/);
  assert.match(err.message, /SHA-256/);
});

test('a certificate on the resumed path is refused', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const offer = await establishOffer(identity, sessionCache);
  const { a, b } = duplexPair();
  startServer(b, identity, { sessionCache, resumeSendCertificate: true });
  await rejectsWithCode(
    () => handshakeTls13({
      transport: a, hostname: HOST, verifyPeer: acceptStub(identity), options: { psk: offer },
    }),
    codes.TLS_PSK, /certificate/);
});

test('a wrong PSK fails the binder on the server side, which aborts', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const offer = await establishOffer(identity, sessionCache);
  offer.psk[0] ^= 0x01; // the identity is right; the secret is not
  const { a, b } = duplexPair();
  const srv = startServer(b, identity, { sessionCache });
  await rejectsWithCode(
    () => handshakeTls13({
      transport: a, hostname: HOST, verifyPeer: acceptStub(identity), options: { psk: offer },
    }),
    codes.TLS_ALERT, /decrypt_error/);
  assert.equal(srv.state.binderVerified, false);
  assert.equal(srv.state.stopped, 'bad-binder');
});

// ================================================================ HelloRetryRequest

test('resumption survives a HelloRetryRequest: the second hello re-binds', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const offer = await establishOffer(identity, sessionCache);
  const second = await connect13({
    identity,
    server: { sessionCache, hrr: { group: GROUP.secp256r1 } },
    options: { psk: offer },
  });
  assert.equal(second.tls.info.resumed, true);
  assert.equal(second.state.binderVerified, true,
    'the ClientHello2 binder verified against message_hash(CH1) || HRR || Truncate(CH2)');
  const [ch1, ch2] = second.state.clientHellos;
  assert.ok(ch1.psk && ch2.psk, 'both hellos carry the offer');
  assert.notEqual(toHex(ch1.psk.binders[0]), toHex(ch2.psk.binders[0]),
    'the second binder covers a different transcript and must differ');
});

test('an HRR that pins a different-hash suite drops the PSK from ClientHello2', async () => {
  const identity = testIdentity('ecdsa-p256');
  const sessionCache = new Map();
  const offer = await establishOffer(identity, sessionCache); // minted under SHA-256
  const second = await connect13({
    identity,
    server: { sessionCache, cipher: AES256, hrr: { group: GROUP.secp256r1 } },
    options: { psk: offer },
  });
  assert.equal(second.tls.info.resumed, false);
  assert.equal(second.verifyPeer.calls.length, 1, 'full handshake after the drop');
  const [ch1, ch2] = second.state.clientHellos;
  assert.ok(ch1.psk, 'the first hello offered the PSK');
  assert.equal(ch2.psk, null,
    's4.1.4: the second hello must not offer a PSK of a hash the pinned suite cannot use');
});

// ================================================================ malformed NewSessionTicket

async function rejectTicketBody(rawBody, code, msgMatch) {
  const identity = testIdentity('ecdsa-p256');
  const r = await connect13({
    identity,
    server: { tickets: [{ rawBody }] },
    options: { onSessionTicket: () => assert.fail('a malformed ticket must never be captured') },
  });
  // The queued ticket is the first thing the read pulls through; parsing it must fail the
  // connection right there — no server nudge needed, and none is sent, so the rejection is
  // handled the instant it exists.
  await rejectsWithCode(() => r.tls.record.readAppData(), code, msgMatch);
}

test('a zero-length ticket is refused', async () => {
  const body = new Builder()
    .push(u32(60)).push(u32(0)).vector(1, EMPTY).vector(2, EMPTY).vector(2, EMPTY).build();
  await rejectTicketBody(body, codes.TLS_TICKET, /zero-length ticket/);
});

test('a malformed early_data extension in a ticket is refused', async () => {
  const body = new Builder()
    .push(u32(60)).push(u32(0)).vector(1, EMPTY).vector(2, utf8('t'))
    .vector(2, rawExtension(EXTENSION.early_data, u16(5))) // 2 bytes; must be a uint32
    .build();
  await rejectTicketBody(body, codes.TLS_TICKET, /early_data/);
});

test('a truncated NewSessionTicket is refused', async () => {
  await rejectTicketBody(u32(60), codes.TLS_HANDSHAKE, /NewSessionTicket/);
});

test('an unrecognized ticket extension is ignored, as s4.6.1 requires', async () => {
  const identity = testIdentity('ecdsa-p256');
  const captured = [];
  const r = await connect13({
    identity,
    server: {
      sessionCache: new Map(),
      tickets: [{
        ticket: utf8('decorated'), lifetime: 60,
        extensions: rawExtension(0xff77, utf8('mystery')),
      }],
    },
    options: { onSessionTicket: (t) => captured.push(t) },
  });
  await pumpTickets(r.tls, r.srv);
  assert.equal(captured.length, 1);
  assert.equal(latin1(captured[0].identity), 'decorated');
});

// ================================================================ the ticket store

function capturedTicket(overrides = {}) {
  return {
    identity: utf8('stored-ticket'),
    psk: Uint8Array.from({ length: 32 }, (_, i) => i),
    hash: 'SHA-256',
    cipherSuite: AES128,
    lifetimeSec: 3600,
    ageAdd: 0x01020304,
    maxEarlyDataSize: null,
    alpnProtocol: null,
    peer: { stub: true },
    ...overrides,
  };
}

test('tickets are single-use: a second take finds nothing', () => {
  const store = new TicketStore({ now: () => 0 });
  store.put(KEY, capturedTicket());
  assert.ok(store.take(KEY));
  assert.equal(store.take(KEY), null);
});

test('a ticket past its lifetime is dropped, not offered', () => {
  let now = 0;
  const store = new TicketStore({ now: () => now });
  store.put(KEY, capturedTicket({ lifetimeSec: 10 }));
  now = 9_999;
  assert.ok(store.take(KEY), 'one millisecond inside the lifetime is usable');
  store.put(KEY, capturedTicket({ lifetimeSec: 10 }));
  now = 20_000;
  assert.equal(store.take(KEY), null, 'past ticket_lifetime the ticket is refused');
  assert.equal(store.size, 0, 'the expired ticket is gone, not lingering');
});

test('lifetime zero is discarded on arrival; lifetimes clamp at seven days', () => {
  let now = 0;
  const store = new TicketStore({ now: () => now });
  assert.equal(store.put(KEY, capturedTicket({ lifetimeSec: 0 })), false,
    's4.6.1: zero means discard immediately');
  assert.equal(store.size, 0);

  // A server claiming 70 days gets the protocol ceiling, not its claim.
  store.put(KEY, capturedTicket({ lifetimeSec: 70 * 24 * 3600 }));
  now = 604_800_000 - 1;
  assert.ok(store.take(KEY), 'usable just inside seven days');
  now = 0;
  store.put(KEY, capturedTicket({ lifetimeSec: 70 * 24 * 3600 }));
  now = 604_800_000;
  assert.equal(store.take(KEY), null, 'clients MUST NOT cache beyond seven days');
});

test('newest first, capped per key', () => {
  const store = new TicketStore({ now: () => 0 });
  store.put(KEY, capturedTicket({ identity: utf8('one') }));
  store.put(KEY, capturedTicket({ identity: utf8('two') }));
  store.put(KEY, capturedTicket({ identity: utf8('three') }));
  assert.equal(store.size, 2, 'default cap is two, matching a typical server flight');
  assert.equal(latin1(store.take(KEY).identity), 'three');
  assert.equal(latin1(store.take(KEY).identity), 'two');
  assert.equal(store.take(KEY), null, '"one" was evicted by the cap');
});

test('the obfuscated age tracks the clock and wraps mod 2^32', () => {
  let now = 5_000;
  const store = new TicketStore({ now: () => now });
  store.put(KEY, capturedTicket({ ageAdd: 0xfffffffe }));
  const offer = store.take(KEY);
  now = 6_234; // 1234 ms of age
  assert.equal(offer.obfuscatedTicketAge(), (1234 + 0xfffffffe) % 0x100000000);
  now = 6_235; // the closure reads the clock at each call — an HRR rebuilds the hello later
  assert.equal(offer.obfuscatedTicketAge(), (1235 + 0xfffffffe) % 0x100000000);
});

test('a structurally unusable capture is refused loudly', () => {
  const store = new TicketStore({ now: () => 0 });
  assert.throws(() => store.put(KEY, capturedTicket({ psk: EMPTY })),
    (e) => e.code === codes.TLS_TICKET);
  assert.throws(() => store.put(KEY, capturedTicket({ hash: 'SHA-1' })),
    (e) => e.code === codes.CONFIG_INVALID);
  assert.throws(() => store.put(KEY, capturedTicket({ lifetimeSec: 1.5 })),
    (e) => e.code === codes.TLS_TICKET);
});

test('a ticket never crosses trust configurations, proxies, or origins', () => {
  const base = {
    scheme: 'https:', hostname: 'origin.test', port: 443, proxy: null,
    trust: { mode: 'pinned', pins: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] },
    tls: {},
  };
  const pinnedKey = poolKey(base);
  const store = new TicketStore({ now: () => 0 });
  store.put(pinnedKey, capturedTicket());

  // The same origin under ANY other configuration must miss. Each variant changes one thing.
  const variants = [
    { ...base, trust: { mode: 'system' } },
    { ...base, trust: { mode: 'pinned', pins: ['sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='] } },
    { ...base, trust: { mode: 'none', insecureAcceptAnyCertificate: true } },
    { ...base, proxy: { protocol: 'http', hostname: 'proxy.test', port: 8080 } },
    { ...base, tls: { ciphers: [AES128] } },
    { ...base, port: 8443 },
    { ...base, hostname: 'other.test' },
  ];
  for (const v of variants) {
    const k = poolKey(v);
    assert.notEqual(k, pinnedKey, 'the key must distinguish this variant');
    assert.equal(store.take(k), null,
      `a ticket obtained under pinning must not resume ${JSON.stringify(v.trust ?? v)}`);
  }
  // And the matching configuration still finds it.
  assert.ok(store.take(poolKey(base)));
});

// ================================================================ through the Client

const fx = caFixture();
const NOW = Date.now();
const leafIdentity = {
  certDer: fx.leaf.der,
  spkiDer: fx.leaf.spkiDer,
  scheme: SIG_SCHEME.ecdsa_secp256r1_sha256,
  sign: (content) =>
    new Uint8Array(nodeSign('sha256', content, { key: fx.leaf.privateKey, dsaEncoding: 'der' })),
};

/**
 * A connect() factory whose every socket is a fresh TLS-terminating HTTP/1.1 server sharing one
 * session cache — so a second connection from the same Client can resume — that answers one
 * request and closes, forcing the Client to open (and ideally resume) a connection per fetch.
 */
function ticketingConnect(serverOpts = {}) {
  const sessionCache = new Map();
  let seq = 0;
  const connect = () => {
    const { a, b } = duplexPair();
    void (async () => {
      const srv = startServer(b, leafIdentity, {
        sessionCache,
        tickets: [{ ticket: utf8(`client-ticket-${seq++}`), lifetime: 3600 }],
        extraChain: [fx.intermediate.der],
        ...serverOpts,
      });
      try {
        await srv.done;
      } catch {
        return; // negative paths abort mid-handshake; nothing to serve
      }
      let head = new Uint8Array(0);
      while (!latin1(head).includes('\r\n\r\n')) {
        const chunk = await srv.record.readAppData();
        if (chunk === null) return;
        head = concat([head, chunk]);
      }
      await srv.record.writeAppData(
        utf8('HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok'));
      await srv.record.close();
    })();
    return {
      readable: a.readable, writable: a.writable,
      opened: Promise.resolve({}), close: () => {},
    };
  };
  return { connect, sessionCache };
}

test('a Client resumes its second connection to the same origin', async () => {
  const { connect } = ticketingConnect();
  const client = new Client({
    connect, forceTunnel: true, http2: false, keepAlive: false,
    trust: { mode: 'anchors', anchors: [fx.root.der] }, now: NOW,
  });
  try {
    const r1 = await client.fetch(`https://${HOST}/`);
    assert.equal(await r1.text(), 'ok');
    assert.equal(r1.tunnelfetch.tls.resumed, false);
    assert.ok(client.tickets.size >= 1, 'the ticket was captured and stored');

    const r2 = await client.fetch(`https://${HOST}/`);
    assert.equal(await r2.text(), 'ok');
    assert.equal(r2.tunnelfetch.tls.resumed, true,
      'the second connection must resume from the stored ticket');
  } finally {
    await client.close();
  }
  assert.equal(client.tickets.size, 0, 'close() drops stored credentials');
});

test('the Client stores tickets under the connection pool key, trust configuration included', async () => {
  const { connect } = ticketingConnect();
  const trust = { mode: 'anchors', anchors: [fx.root.der] };
  const client = new Client({
    connect, forceTunnel: true, http2: false, keepAlive: false, trust, now: NOW,
  });
  try {
    await (await client.fetch(`https://${HOST}/`)).text();
    assert.ok(client.tickets.size >= 1);

    // Keys that differ from the connection's in exactly one security-relevant input must all
    // miss. Misses do not consume, so probing them first is safe.
    const base = { scheme: 'https:', hostname: HOST, port: 443, proxy: null, trust, tls: {} };
    for (const wrong of [
      { ...base, trust: { mode: 'system' } },
      { ...base, trust: { mode: 'pinned', pins: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] } },
      { ...base, proxy: { protocol: 'http', hostname: 'proxy.test', port: 8080 } },
      { ...base, port: 8443 },
    ]) {
      assert.equal(client.tickets.take(poolKey(wrong)), null,
        'a key differing in trust, proxy or port must find nothing');
    }
    // And the exact pool key of the connection that earned the ticket finds it — proving the
    // Client keys its store by poolKey() and not by anything looser, through public API only.
    assert.ok(client.tickets.take(poolKey(base)),
      'the ticket must live under the full pool key, trust configuration included');
  } finally {
    await client.close();
  }
});

test("require-staple disables resumption: every connection re-proves revocation", async () => {
  const staple = makeOcspResponse({
    issuer: fx.intermediate, subject: fx.leaf,
    thisUpdate: NOW - 3600 * 1000, nextUpdate: NOW + 24 * 3600 * 1000,
  }).der;
  const { connect } = ticketingConnect({ staple });
  const client = new Client({
    connect, forceTunnel: true, http2: false, keepAlive: false,
    trust: { mode: 'anchors', anchors: [fx.root.der], revocation: 'require-staple' }, now: NOW,
  });
  try {
    const r1 = await client.fetch(`https://${HOST}/`);
    assert.equal(await r1.text(), 'ok');
    assert.equal(r1.tunnelfetch.tls.resumed, false);
    assert.equal(client.tickets.size, 0,
      'under require-staple the ticket must not even be stored');

    // A resumed handshake carries no certificate and no staple, so the check this caller made
    // mandatory could never run; the second connection must therefore be a full handshake.
    const r2 = await client.fetch(`https://${HOST}/`);
    assert.equal(await r2.text(), 'ok');
    assert.equal(r2.tunnelfetch.tls.resumed, false);
  } finally {
    await client.close();
  }
});
