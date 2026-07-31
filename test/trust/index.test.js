// verifyChain and the trust knob: every mode, and every way to hold it wrong.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import { verifyChain } from '../../src/trust/index.js';
import { caFixture, makeCert, toPem, flipSignatureByte } from './_certs.js';

const fx = caFixture();
const HOST = 'server.test';
const chain = [fx.leaf.der, fx.intermediate.der];
const anchorsMode = { mode: 'anchors', anchors: [fx.root.der] };
const pinOf = (bundle) => `sha256/${createHash('sha256').update(bundle.spkiDer).digest('base64')}`;

test('anchors mode verifies a chain against exactly the given anchors', async () => {
  const leaf = await verifyChain({ chain, hostname: HOST, trust: anchorsMode });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
  // PEM anchors work identically, including multi-block PEM text
  const pem = toPem(fx.root.der) + toPem(caFixture({ root: { subject: { CN: 'Other', O: 'o' } } }).root.der);
  await verifyChain({ chain, hostname: HOST, trust: { mode: 'anchors', anchors: [pem] } });
  // and the wrong anchor still fails
  const stranger = caFixture({ root: { subject: { CN: 'Stranger', O: 's' } } });
  await rejectsWithCode(
    async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'anchors', anchors: [stranger.root.der] } }),
    codes.CERT_CHAIN_INCOMPLETE);
});

test('system mode fails closed for a chain the bundled store does not anchor', async () => {
  const { rootStoreProvenance } = await import('../../src/trust/index.js');
  if (rootStoreProvenance.anchorCount === 0) {
    // Placeholder store: refused outright, with the fix spelled out.
    const e = await rejectsWithCode(
      async () => verifyChain({ chain, hostname: HOST }),
      codes.CONFIG_INVALID, /unpopulated/);
    assert.match(e.message, /roots:refresh/);
  } else {
    // Generated store: our factory PKI must not chain to any public anchor.
    await rejectsWithCode(
      async () => verifyChain({ chain, hostname: HOST }),
      codes.CERT_CHAIN_INCOMPLETE);
  }
});

test('unknown mode and malformed trust objects are refused', async () => {
  await rejectsWithCode(async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'nope' } }),
    codes.CONFIG_INVALID, /unknown trust mode "nope"/);
  await rejectsWithCode(async () => verifyChain({ chain, hostname: HOST, trust: null }),
    codes.CONFIG_INVALID);
  await rejectsWithCode(async () => verifyChain({ chain, hostname: HOST, trust: 'system' }),
    codes.CONFIG_INVALID);
});

test('mode none without the explicit confession flag is unreachable', async () => {
  await rejectsWithCode(async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'none' } }),
    codes.CONFIG_INVALID, /insecureAcceptAnyCertificate/);
  // near-misses do not count as consent
  for (const value of [1, 'true', 'yes', {}]) {
    await rejectsWithCode(
      async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'none', insecureAcceptAnyCertificate: value } }),
      codes.CONFIG_INVALID);
  }
});

test('mode none with the flag accepts anything, and still returns the parsed leaf', async () => {
  const trust = { mode: 'none', insecureAcceptAnyCertificate: true };
  const expired = makeCert({ subject: { CN: 'expired' }, notBefore: 0, notAfter: 1 });
  const leaf = await verifyChain({ chain: [expired.der], hostname: HOST, trust });
  assert.equal(leaf.subject.text, 'CN=expired');
  // an unparseable blob is accepted (that is the contract) but cannot be described
  const blob = await verifyChain({ chain: [Uint8Array.of(1, 2, 3)], hostname: HOST, trust });
  assert.equal(blob, null);
});

test('the insecure flag on any verifying mode is a contradiction and refused', async () => {
  await rejectsWithCode(
    async () => verifyChain({ chain, hostname: HOST, trust: { ...anchorsMode, insecureAcceptAnyCertificate: true } }),
    codes.CONFIG_INVALID, /not meaningful with mode 'anchors'/);
});

test('keys from the wrong mode are refused rather than ignored', async () => {
  await rejectsWithCode(
    async () => verifyChain({ chain, hostname: HOST, trust: { ...anchorsMode, pins: [pinOf(fx.root)] } }),
    codes.CONFIG_INVALID, /trust\.pins/);
  await rejectsWithCode(
    async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'custom', verify: async () => {}, anchors: [fx.root.der] } }),
    codes.CONFIG_INVALID, /trust\.anchors/);
});

test('pinned mode: full path validation plus the pin, matched anywhere in the chain', async () => {
  // pin the intermediate SPKI: leaf rotation must survive
  const trust = { mode: 'pinned', pins: [pinOf(fx.intermediate)], anchors: [fx.root.der] };
  await verifyChain({ chain, hostname: HOST, trust });
  // pin the anchor
  await verifyChain({ chain, hostname: HOST, trust: { ...trust, pins: [pinOf(fx.root)] } });
  // a pin that matches nothing reports what it saw
  const e = await rejectsWithCode(
    async () => verifyChain({ chain, hostname: HOST, trust: { ...trust, pins: ['sha256/' + 'A'.repeat(43) + '='] } }),
    codes.CERT_PIN_MISMATCH, /observed/);
  assert.ok(e.detail.observed.length >= 2);
});

test('pinned mode still validates the path: a matching pin cannot bless a broken chain', async () => {
  const trust = { mode: 'pinned', pins: [pinOf(fx.leaf)], anchors: [fx.root.der] };
  await rejectsWithCode(
    async () => verifyChain({ chain: [flipSignatureByte(fx.leaf.der), fx.intermediate.der], hostname: HOST, trust }),
    codes.CERT_SIGNATURE_INVALID);
  await rejectsWithCode(
    async () => verifyChain({ chain, hostname: 'other.test', trust }),
    codes.CERT_NAME_MISMATCH);
});

test('malformed pins are configuration errors, not mismatches', async () => {
  const bad = async (pins) =>
    rejectsWithCode(async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'pinned', pins, anchors: [fx.root.der] } }),
      codes.CONFIG_INVALID);
  await bad([]);
  await bad(['md5/abcd']);
  await bad(['sha256/short']);
  await bad(['sha256/!!!not-base64!!!']);
  await bad([42]);
});

test('mode none + pins: pin-only trust with no path validation, failing closed on garbage', async () => {
  const trust = { mode: 'none', insecureAcceptAnyCertificate: true, pins: [pinOf(fx.leaf)] };
  // no intermediate supplied, chain unvalidatable — but the pin matches the leaf SPKI
  const leaf = await verifyChain({ chain: [fx.leaf.der], hostname: HOST, trust });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
  // wrong pin still rejects
  await rejectsWithCode(
    async () => verifyChain({ chain: [fx.leaf.der], hostname: HOST, trust: { ...trust, pins: [pinOf(fx.root)] } }),
    codes.CERT_PIN_MISMATCH);
  // an unparseable chain cannot be pinned: throws, never accepts
  await rejectsWithCode(
    async () => verifyChain({ chain: [Uint8Array.of(9, 9, 9)], hostname: HOST, trust }),
    codes.CERT_PARSE);
});

test('custom mode: the callback sees the parsed chain and owns the verdict', async () => {
  let saw;
  const leaf = await verifyChain({
    chain, hostname: HOST,
    trust: { mode: 'custom', verify: async (parsed, hostname) => {
      saw = { subjects: parsed.map((c) => c.subject.text), hostname };
    } },
  });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
  assert.deepEqual(saw, {
    subjects: ['CN=server.test, O=tunnelfetch', 'CN=Test Intermediate CA, O=tunnelfetch'],
    hostname: HOST,
  });
  // the callback's own error propagates untouched
  class MyPolicyError extends Error {}
  await assert.rejects(
    () => verifyChain({ chain, hostname: HOST, trust: { mode: 'custom', verify: async () => { throw new MyPolicyError('nope'); } } }),
    MyPolicyError);
  // and a non-function verify is a config error
  await rejectsWithCode(
    async () => verifyChain({ chain, hostname: HOST, trust: { mode: 'custom', verify: true } }),
    codes.CONFIG_INVALID, /verify/);
});

test('a self-signed server certificate can be pinned as its own anchor', async () => {
  // The httpx-style "trust exactly my dev server" flow: the leaf is the anchor.
  const selfSigned = makeCert({ subject: { CN: HOST }, san: { dns: [HOST] } });
  const leaf = await verifyChain({
    chain: [selfSigned.der], hostname: HOST,
    trust: { mode: 'anchors', anchors: [toPem(selfSigned.der)] },
  });
  assert.equal(leaf.subject.text, `CN=${HOST}`);
  // but only for its own identity
  await rejectsWithCode(
    async () => verifyChain({ chain: [selfSigned.der], hostname: 'other.test',
      trust: { mode: 'anchors', anchors: [selfSigned.der] } }),
    codes.CERT_NAME_MISMATCH);
});

test('empty chains are refused in every mode', async () => {
  for (const trust of [anchorsMode, { mode: 'none', insecureAcceptAnyCertificate: true },
    { mode: 'custom', verify: async () => {} }]) {
    await rejectsWithCode(async () => verifyChain({ chain: [], hostname: HOST, trust }),
      codes.CERT_CHAIN_INCOMPLETE);
  }
});
