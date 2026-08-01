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
