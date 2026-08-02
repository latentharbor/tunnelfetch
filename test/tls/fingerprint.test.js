// The TLS client fingerprint: what a JA3 or JA4 hash is actually computed over.
//
// The h2 side of this package has been pinned byte-for-byte to curl since it was written; this side
// had nothing, which meant "presents curl's fingerprint" was true of the HTTP/2 preface and merely
// asserted of the ClientHello. These tests close that gap in the only way that survives: against
// bytes captured from a real curl rather than against anyone's recollection of one.
//
// Reference: **curl 8.21.0 / OpenSSL 3.6.3**, ClientHello captured on the wire, 2026-08-01.
// The TLS backend matters more than the curl version — the same curl built against SecureTransport
// or GnuTLS produces a completely different hello — so a reference without a backend is not a
// reference. OpenSSL is the build that fingerprinting discussions mean.
//
// What curl sent, in wire order:
//   renegotiation_info, server_name, ec_point_formats, supported_groups, ALPN, encrypt_then_mac,
//   extended_master_secret, post_handshake_auth, signature_algorithms, supported_versions,
//   psk_key_exchange_modes, key_share

import test from 'node:test';
import assert from 'node:assert/strict';
import { buildClientHello, CURL_EXTENSION_ORDER } from '../../src/tls/handshake-messages.js';
import { EXTENSION, TLS13, TLS12 } from '../../src/tls/constants.js';

/** Extension types in the order they appear on the wire — which is what JA3/JA4 hash. */
function extensionTypes(message) {
  const b = message;
  let p = 4 + 2 + 32; // handshake header, legacy_version, random
  p += 1 + b[p]; // legacy_session_id
  p += 2 + ((b[p] << 8) | b[p + 1]); // cipher_suites
  p += 1 + b[p]; // legacy_compression_methods
  const total = (b[p] << 8) | b[p + 1];
  p += 2;
  const end = p + total;
  const types = [];
  while (p < end) {
    types.push((b[p] << 8) | b[p + 1]);
    p += 4 + ((b[p + 2] << 8) | b[p + 3]);
  }
  return types;
}

const share = { group: 0x001d, keyExchange: new Uint8Array(32).fill(7) };
const hello = (extra = {}) =>
  buildClientHello({
    hostname: 'example.com',
    keyShares: [share],
    random: new Uint8Array(32).fill(1),
    legacySessionId: new Uint8Array(32).fill(2),
    alpn: ['h2', 'http/1.1'],
    versions: [TLS13, TLS12],
    ...extra,
  }).message;

test('the default extension order is curl\'s, for every extension both of them send', () => {
  const ours = extensionTypes(hello());
  // curl's order, with the two it sends and this package does not removed. Compared as a
  // SUBSEQUENCE relationship rather than by equality, because the package additionally sends
  // status_request — the assertion is that nothing shared is out of curl's relative order.
  const curlShared = [
    EXTENSION.renegotiation_info,
    EXTENSION.server_name,
    EXTENSION.ec_point_formats,
    EXTENSION.supported_groups,
    EXTENSION.alpn,
    EXTENSION.extended_master_secret,
    EXTENSION.signature_algorithms,
    EXTENSION.supported_versions,
    EXTENSION.psk_key_exchange_modes,
    EXTENSION.key_share,
  ];
  assert.deepEqual(
    ours.filter((t) => curlShared.includes(t)),
    curlShared,
    'the extensions this package shares with curl are no longer in curl\'s order',
  );
});

test('the exact ClientHello extension list is pinned, so any change is deliberate', () => {
  // Equality, not a subsequence: a new extension appearing — or one silently dropping out —
  // changes the fingerprint, and that must be a decision someone made rather than a side effect.
  assert.deepEqual(extensionTypes(hello()), [
    EXTENSION.renegotiation_info,
    EXTENSION.server_name,
    EXTENSION.status_request,
    EXTENSION.ec_point_formats,
    EXTENSION.supported_groups,
    EXTENSION.alpn,
    EXTENSION.extended_master_secret,
    EXTENSION.signature_algorithms,
    EXTENSION.supported_versions,
    EXTENSION.psk_key_exchange_modes,
    EXTENSION.key_share,
  ]);
});

// The differences that remain are capability, not formatting, and each is a deliberate refusal to
// claim something this package cannot do. An extension or a cipher suite in a ClientHello is an
// offer: a server may take it, and a client that cannot then complete the handshake has traded a
// fingerprint mismatch for a broken connection, which is strictly worse and fails silently.
//
// This test exists to make that list a decision rather than an accident. If the package ever gains
// one of these capabilities, this test fails and the documented delta has to be updated with it.
test('the known differences from curl are exactly the documented ones', () => {
  const ours = extensionTypes(hello());
  const CURL_ENCRYPT_THEN_MAC = 22;
  const CURL_POST_HANDSHAKE_AUTH = 49;

  // encrypt_then_mac applies only to CBC cipher suites, which are not offered — the package is
  // AEAD-only by design.
  assert.ok(!ours.includes(CURL_ENCRYPT_THEN_MAC));
  // post_handshake_auth invites a CertificateRequest after the handshake, which is not implemented.
  assert.ok(!ours.includes(CURL_POST_HANDSHAKE_AUTH));
  // status_request goes the other way: curl does not ask for a stapled OCSP response, and this
  // package must, because a staple is its only revocation signal.
  assert.ok(ours.includes(EXTENSION.status_request));
});

test('the extension order is configurable, and pre_shared_key stays last regardless', () => {
  // The whole point of exposing this: a caller matching some other client needs to place the
  // extensions where that client places them.
  const reversed = [...CURL_EXTENSION_ORDER].reverse();
  const got = extensionTypes(hello({ extensionOrder: reversed }));
  const shared = got.filter((t) => reversed.includes(t));
  assert.deepEqual(shared, reversed.filter((t) => shared.includes(t)));

  // RFC 8446 s4.2.11: the binder transcript is the hello truncated just before the binders, which
  // is a well-defined byte range only if nothing follows them. Not the caller's to override.
  const withPsk = extensionTypes(
    hello({
      extensionOrder: [EXTENSION.pre_shared_key, EXTENSION.server_name],
      psk: { identity: new Uint8Array(8), obfuscatedTicketAge: 0, binderLen: 32 },
    }),
  );
  assert.equal(
    withPsk.at(-1),
    EXTENSION.pre_shared_key,
    'a caller was able to move pre_shared_key off the end of the hello',
  );
});

test('an extension the order does not name still appears, at the end', () => {
  // A partial order must not silently drop anything: the offer is decided by capability, and the
  // order only decides where each piece goes.
  const got = extensionTypes(hello({ extensionOrder: [EXTENSION.key_share, EXTENSION.server_name] }));
  assert.equal(got[0], EXTENSION.key_share);
  assert.equal(got[1], EXTENSION.server_name);
  assert.equal(new Set(got).size, got.length, 'an extension was emitted twice');
  assert.ok(got.includes(EXTENSION.supported_versions), 'an unnamed extension was dropped');
});

// ---------------------------------------------------------------------------------------------
// Against a RECORDING, not against ourselves.
//
// Everything above compares the builder to constants in `src/`. That catches drift and it cannot
// catch the constants being wrong about curl — the test and the code read the same list, so both
// would have to be wrong together, which is exactly how a fingerprint claim goes bad. Until now no
// capture existed anywhere in this repository to check them against, so "captured off the wire" was
// an assertion with no artifact.
//
// `test/tls/_captured-hellos.js` is a ClientHello recorded from the real curl this package names,
// parsed by a parser that shares no code with `src/`. These tests read it.

import {
  CURL_CAPTURED_EXTENSION_ORDER,
  CURL_CAPTURED_CIPHERS,
  CURL_CAPTURE_PROVENANCE,
} from './_captured-hellos.js';

/** The three deviations this package documents and intends. Anything else is drift. */
const ENCRYPT_THEN_MAC = 22;
const POST_HANDSHAKE_AUTH = 49;

test('our extension order matches the RECORDED curl, once the documented deltas are applied', () => {
  // Real curl sends encrypt_then_mac and post_handshake_auth, which this package does not implement
  // and therefore must not advertise; and it does not send status_request, which this package does.
  // Removing exactly those three makes the two lists equal — INCLUDING the relative order of every
  // remaining extension, which is the part a JA3/JA4 hash actually reads.
  const theirs = CURL_CAPTURED_EXTENSION_ORDER.filter(
    (t) => t !== ENCRYPT_THEN_MAC && t !== POST_HANDSHAKE_AUTH,
  );
  const ours = extensionTypes(hello()).filter((t) => t !== EXTENSION.status_request);
  assert.deepEqual(
    ours,
    theirs,
    `our hello no longer matches the recording from ${CURL_CAPTURE_PROVENANCE.client}`,
  );
});

test('the three deviations from the recording are the three that are documented', () => {
  const theirs = new Set(CURL_CAPTURED_EXTENSION_ORDER);
  const ours = new Set(extensionTypes(hello()));
  const weOmit = [...theirs].filter((t) => !ours.has(t)).sort((a, b) => a - b);
  const weAdd = [...ours].filter((t) => !theirs.has(t)).sort((a, b) => a - b);
  // If this fails, either a capability was gained (stop omitting it) or a real difference appeared
  // that nobody wrote down. Both are decisions, and both should be made deliberately.
  assert.deepEqual(weOmit, [ENCRYPT_THEN_MAC, POST_HANDSHAKE_AUTH]);
  assert.deepEqual(weAdd, [EXTENSION.status_request]);
});

test('our cipher list is the recorded curl order with the unimplemented suites removed', () => {
  // The README claims "the AEAD suites this package implements, in curl's relative order". This
  // checks the claim against the recording rather than against the constant that produced it: our
  // list must be a SUBSEQUENCE of the real offer, which is what "in curl's relative order" means.
  // Local, because this file's other helper reads only extension types.
  const cipherSuites = (b) => {
    let q = 4 + 2 + 32;
    q += 1 + b[q];
    const len = (b[q] << 8) | b[q + 1];
    q += 2;
    const out = [];
    for (let i = 0; i < len; i += 2) out.push((b[q + i] << 8) | b[q + i + 1]);
    return out;
  };
  const ours = cipherSuites(hello());
  let i = 0;
  for (const c of CURL_CAPTURED_CIPHERS) if (ours[i] === c) i++;
  assert.equal(
    i,
    ours.length,
    `our ciphers are not a subsequence of the recorded curl offer: ${ours.map((c) => '0x' + c.toString(16)).join(' ')}`,
  );
});

// ---------------------------------------------------------------------------------------------
// The chrome profile against a RECORDED Chromium.
//
// Nothing in this repository asserted a single Chrome fingerprint value before. These read the
// recording, so a claim about Chromium is checked against Chromium.

import {
  CHROME_CAPTURED_CIPHERS,
  CHROME_CAPTURED_GROUPS,
  CHROME_CAPTURED_SIG_SCHEMES,
} from './_captured-hellos.js';
import { chrome as chromeProfile } from '../../src/profiles.js';

const notGrease = (v) => !((v & 0x0f0f) === 0x0a0a && v >>> 8 === (v & 0xff));

test('the chrome profile\'s cipher list is the recorded Chromium offer, in order', () => {
  // Chromium leads with a GREASE value, which the builder adds separately; the rest is a prefix of
  // the real offer. Order is the whole point — a JA3 hash reads it.
  const theirs = CHROME_CAPTURED_CIPHERS.filter(notGrease);
  const ours = [...chromeProfile.tls.ciphers];
  assert.deepEqual(theirs.slice(0, ours.length), ours, 'the profile no longer matches the recording');
});

test('the chrome profile\'s groups are the recorded Chromium groups, exactly', () => {
  assert.deepEqual([...chromeProfile.tls.groups], CHROME_CAPTURED_GROUPS.filter(notGrease));
});

test('the chrome profile omits Chromium\'s ML-DSA signature schemes, and that is recorded here', () => {
  // Real Chromium LEADS its signature_algorithms with 0x0904/0x0905/0x0906 — ML-DSA-44/65/87. This
  // package cannot verify an ML-DSA signature, and offering one a server may then use would trade a
  // fingerprint match for a dead connection, so omitting them is the same deliberate deviation the
  // curl profile makes for encrypt_then_mac.
  //
  // It was NOT written down anywhere, which is the part this test fixes: the difference is now
  // asserted, so gaining ML-DSA support without updating the profile fails the build, and so does
  // Chromium changing its list under us.
  const theirs = [...CHROME_CAPTURED_SIG_SCHEMES];
  const ours = [...chromeProfile.tls.sigSchemes];
  const MLDSA = [0x0904, 0x0905, 0x0906];
  assert.deepEqual(theirs.slice(0, 3), MLDSA, 'Chromium no longer leads with ML-DSA');
  assert.deepEqual(theirs.slice(3), ours, 'past ML-DSA the two lists must agree exactly');
  assert.ok(ours.every((s) => !MLDSA.includes(s)), 'we now offer a scheme we cannot verify');
});
