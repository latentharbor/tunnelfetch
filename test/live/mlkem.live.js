// Live X25519MLKEM768 (and ChaCha20-Poly1305) interop against a real server that speaks them.
//
// Run explicitly with `npm run test:live`; never part of `npm test`. This is the verification the
// offline suite CANNOT be: an in-memory test server built on this package's own understanding of
// draft-kwiatkowski-tls-ecdhe-mlkem will happily agree with a matching mistake in the client — the
// two share code. A real server does not. If the client's key_share layout, the server-share split,
// or the shared-secret concatenation is in the wrong order, the derived secret differs and the
// handshake dies at Finished / EncryptedExtensions, never as a clean error. A completed handshake
// with a decrypted body is therefore proof the orders are right.
//
// It dials DIRECTLY (no proxy): the group is what is under test, not the tunnel, and a raw TCP
// connection to the target from a developer machine is enough. Cloudflare negotiates
// X25519MLKEM768 today; override the host with TUNNELFETCH_MLKEM_TARGET if that changes.
//
// The ML-KEM-768 and ChaCha20 implementations are INJECTED — WebCrypto has neither on the target
// runtime. This test uses the reference builds under wasmcrypto/ (ML-KEM validated against the NIST
// ACVP FIPS 203 KATs; ChaCha20 against RFC 8439). wasmcrypto/ is a local build artifact, not part
// of the published package, so a missing build FAILS loudly here rather than skipping.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/index.js';
import { nodeConnect } from './_nodenet.js';

const HYBRID = 0x11ec;
const CHACHA = 0x1303;
const TARGET = process.env.TUNNELFETCH_MLKEM_TARGET ?? 'cloudflare.com';
const timeouts = { connectMs: 20000, handshakeMs: 25000, headersMs: 25000, idleMs: 25000 };

async function crypto() {
  try {
    const [{ mlkem768 }, { chacha20poly1305 }] = await Promise.all([
      import('../../wasmcrypto/dist/mlkem768.wasm.js'),
      import('../../wasmcrypto/dist/chacha20poly1305.wasm.js'),
    ]);
    return { mlkem768, chacha20poly1305 };
  } catch (e) {
    throw new Error(
      'the injectable ML-KEM/ChaCha20 reference builds under wasmcrypto/dist are not present ' +
        `(${e.message}). They are a local build artifact, not part of the package; build them ` +
        'first. These live tests exercise the injected capabilities, so they cannot run without one.',
    );
  }
}

test(`X25519MLKEM768 completes against ${TARGET} and carries a real response`, async () => {
  const { mlkem768, chacha20poly1305 } = await crypto();
  const c = new Client({
    connect: nodeConnect(),
    forceTunnel: true, // exercise the userland TLS stack, never node's own fetch
    http2: false,
    timeouts,
    maxBodyBytes: 4 << 20,
    // supported_groups leads with the hybrid, and real key_shares are sent for it and x25519 — as
    // curl does — so the server can select the hybrid on the first flight with no HelloRetry.
    tls: { groups: [HYBRID, 0x001d, 0x0017, 0x0018], offerGroups: [HYBRID, 0x001d] },
    groups: { x25519mlkem768: mlkem768 },
    ciphers: { chacha20: chacha20poly1305 },
  });
  try {
    const res = await c.fetch(`https://${TARGET}/`);
    const body = await res.text();
    const tls = res.tunnelfetch.tls;
    assert.equal(tls.version, 0x0304, 'TLS 1.3');
    assert.equal(tls.group, HYBRID, 'the server selected X25519MLKEM768');
    assert.ok(res.status >= 200 && res.status < 500, `unexpected status ${res.status}`);
    assert.ok(body.length > 0, 'a wrong concatenation would decrypt to nothing usable');
    // Getting a real 200 here rather than a CertificateError is itself the proof the leaf was
    // validated in userland against the bundled roots (the target may 3xx-redirect to another of
    // its own hosts, which still negotiates the hybrid, so the final tls.hostname is not asserted).
  } finally {
    await c.close().catch(() => {});
  }
});

test(`ChaCha20-Poly1305 completes against ${TARGET} over the injected AEAD`, async () => {
  const { mlkem768, chacha20poly1305 } = await crypto();
  const c = new Client({
    connect: nodeConnect(),
    forceTunnel: true,
    http2: false,
    timeouts,
    maxBodyBytes: 4 << 20,
    // Offer ONLY ChaCha20 for TLS 1.3, so a completed handshake proves the injected AEAD protected
    // the whole session — not merely that it was present in the offer.
    tls: {
      versions: [0x0304], ciphers: [CHACHA],
      groups: [HYBRID, 0x001d], offerGroups: [HYBRID, 0x001d],
    },
    groups: { x25519mlkem768: mlkem768 },
    ciphers: { chacha20: chacha20poly1305 },
  });
  try {
    const res = await c.fetch(`https://${TARGET}/`);
    const body = await res.text();
    assert.equal(res.tunnelfetch.tls.cipherSuite, CHACHA, 'ChaCha20-Poly1305 was negotiated');
    assert.ok(res.status >= 200 && res.status < 500, `unexpected status ${res.status}`);
    assert.ok(body.length > 0);
  } finally {
    await c.close().catch(() => {});
  }
});
