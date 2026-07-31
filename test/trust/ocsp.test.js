// Stapled OCSP verification: the parser, the signer rules, the freshness window, the verdicts,
// and the policy knob — with the negative space carrying most of the weight, because a staple
// arrives from the very peer being authenticated and every check that can be skipped is a check
// an attacker gets to skip for us.
//
// Fixtures are minted by _certs.js: real signatures over hand-written DER, bent one field at a
// time so each failing test pins exactly one defect.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import { verifyChain } from '../../src/trust/index.js';
import { verifyOcspStaple, parseOcspResponse } from '../../src/trust/ocsp.js';
import { parseCertificate } from '../../src/trust/x509.js';
import {
  caFixture, makeCert, makeOcspResponse, enumerated, genTime, spkiKeyBytes,
  seq, ctx, ctxPrim, octet, oid, int, tlv,
} from './_certs.js';

const NOW = Date.now();
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

const fx = caFixture();
const HOST = 'server.test';
const chain = [fx.leaf.der, fx.intermediate.der];
const anchorsMode = { mode: 'anchors', anchors: [fx.root.der] };

/** A fresh, honest response: `good` for fx.leaf, signed by the intermediate that issued it. */
const goodStaple = (extra = {}) => makeOcspResponse({
  issuer: fx.intermediate,
  subject: fx.leaf,
  thisUpdate: NOW - HOUR,
  nextUpdate: NOW + 7 * DAY,
  ...extra,
}).der;

const check = (ocspResponse, trust = anchorsMode, theChain = chain) =>
  verifyChain({ chain: theChain, hostname: HOST, trust, now: NOW, ocspResponse });

// ================================================================ the honest paths

test('a good staple signed by the issuing CA validates, byName and byKey', async () => {
  const leaf = await check(goodStaple());
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
  await check(goodStaple({ responderId: 'byKey' }));
});

test('a SHA-256 CertID is accepted alongside the universal SHA-1', async () => {
  await check(goodStaple({ hashAlg: 'sha256' }));
});

test('the issuer may be the trust anchor itself when the leaf sits directly under it', async () => {
  const directLeaf = makeCert({ subject: { CN: HOST, O: 't' }, issuer: fx.root });
  const staple = makeOcspResponse({
    issuer: fx.root, subject: directLeaf, thisUpdate: NOW - HOUR, nextUpdate: NOW + DAY,
  }).der;
  const leaf = await verifyChain({
    chain: [directLeaf.der], hostname: HOST, trust: anchorsMode, now: NOW, ocspResponse: staple,
  });
  assert.equal(leaf.subject.text, `CN=${HOST}, O=t`);
});

test('a response covering several certificates matches ours among them', async () => {
  const other = makeCert({ subject: { CN: 'other.test' }, issuer: fx.intermediate });
  await check(goodStaple({
    extraSingles: [{ issuer: fx.intermediate, subject: other, status: 'revoked',
      thisUpdate: NOW - HOUR, nextUpdate: NOW + DAY }],
  }));
});

test('verifyOcspStaple reports the verified window and signer kind', async () => {
  const leaf = parseCertificate(fx.leaf.der);
  const issuer = {
    subjectBytes: fx.intermediate.dnBytes,
    spkiDer: fx.intermediate.spkiDer,
    subjectText: 'the intermediate',
  };
  const verdict = await verifyOcspStaple({ staple: goodStaple(), leaf, issuer, now: NOW });
  assert.equal(verdict.status, 'good');
  assert.equal(verdict.delegated, false);
  assert.equal(verdict.thisUpdate, Math.floor((NOW - HOUR) / 1000) * 1000);
  assert.ok(verdict.nextUpdate !== null);
});

// ================================================================ verdicts are not negotiable

test('a revoked staple is fatal, naming serial, reason and time', async () => {
  const revokedAt = NOW - 3 * DAY;
  const err = await rejectsWithCode(
    () => check(goodStaple({ status: 'revoked', revocationTime: revokedAt, reason: 1 })),
    codes.OCSP_REVOKED);
  assert.match(err.message, /serial 0x[0-9a-f]+/);
  assert.match(err.message, /keyCompromise/);
  assert.match(err.message, new RegExp(new Date(Math.floor(revokedAt / 1000) * 1000).toISOString().slice(0, 10)));
  assert.equal(err.detail.reasonName, 'keyCompromise');
});

test('revoked stays fatal without a reason, and under pinned trust too', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ status: 'revoked', reason: null })), codes.OCSP_REVOKED);
  const { createHash } = await import('node:crypto');
  const pin = `sha256/${createHash('sha256').update(fx.root.spkiDer).digest('base64')}`;
  await rejectsWithCode(
    () => check(goodStaple({ status: 'revoked' }),
      { mode: 'pinned', pins: [pin], anchors: [fx.root.der] }),
    codes.OCSP_REVOKED);
});

test('an expired revocation statement is still a revocation, not a staleness shrug', async () => {
  // The stale window must not soften `revoked`: a CA said this serial is dead, and failing
  // closed on old bad news beats failing open on it.
  await rejectsWithCode(
    () => check(goodStaple({ status: 'revoked', thisUpdate: NOW - 30 * DAY, nextUpdate: NOW - 20 * DAY })),
    codes.OCSP_REVOKED);
});

test('unknown is refused: the responder that should know does not', async () => {
  const err = await rejectsWithCode(
    () => check(goodStaple({ status: 'unknown' })), codes.OCSP_UNKNOWN);
  assert.match(err.message, /serial 0x[0-9a-f]+/);
});

// ================================================================ the signature is the staple

test('a tampered response signature is refused', async () => {
  const err = await rejectsWithCode(
    () => check(goodStaple({ tamperSignature: true })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /cannot be trusted/);
});

test('a response signed by a stranger claiming the CA name is refused', async () => {
  // The classic forgery: responderID says "the CA", the signature says someone else. The
  // signature is checked against the CA key the VALIDATED path supplied, so the claim dies.
  const stranger = makeCert({ subject: fx.intermediate.dnBytes, ca: true });
  await rejectsWithCode(
    () => check(goodStaple({ signer: { ...stranger, dnBytes: fx.intermediate.dnBytes } })),
    codes.OCSP_UNVERIFIED);
});

test('a good verdict about the wrong serial proves nothing about ours', async () => {
  const err = await rejectsWithCode(
    () => check(goodStaple({ serialOverride: fx.leaf.serial + 1000 })), codes.OCSP_MISMATCH);
  assert.match(err.message, /does not cover certificate serial/);
  assert.match(err.message, /covers serial 0x/);
});

test('CertID hashes must match the validated issuer, name and key alike', async () => {
  const wrong = new Uint8Array(20).fill(0xab);
  await rejectsWithCode(() => check(goodStaple({ nameHashOverride: wrong })), codes.OCSP_MISMATCH);
  await rejectsWithCode(() => check(goodStaple({ keyHashOverride: wrong })), codes.OCSP_MISMATCH);
});

test('a response for the right serial under a DIFFERENT CA does not transfer', async () => {
  // Same serial number, different issuer: hashes computed from the other CA cannot match the
  // hashes recomputed from our validated path.
  const otherCa = caFixture();
  const foreign = makeOcspResponse({
    issuer: otherCa.intermediate,
    subject: { serial: fx.leaf.serial },
    signer: otherCa.intermediate,
    thisUpdate: NOW - HOUR,
    nextUpdate: NOW + DAY,
  }).der;
  await rejectsWithCode(() => check(foreign), codes.OCSP_MISMATCH);
});

// ================================================================ delegated responders

const responderOpts = {
  subject: { CN: 'OCSP Responder', O: 'tunnelfetch' },
  issuer: fx.intermediate,
  eku: ['1.3.6.1.5.5.7.3.9'], // id-kp-OCSPSigning
  san: null,
};

test('a delegated responder with the OCSP-signing EKU is accepted, byName and byKey', async () => {
  const responder = makeCert(responderOpts);
  await check(goodStaple({ signer: responder, certs: [responder.der] }));
  await check(goodStaple({ signer: responder, certs: [responder.der], responderId: 'byKey' }));
});

test('a delegated responder without the OCSP-signing EKU is refused', async () => {
  // Without this rule, ANY certificate the CA issued — every customer's TLS cert — could sign
  // "good" for every other, and revocation would defeat itself on first key compromise.
  const noEku = makeCert({ ...responderOpts, eku: ['serverAuth'] });
  const err = await rejectsWithCode(
    () => check(goodStaple({ signer: noEku, certs: [noEku.der] })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /OCSPSigning/);

  const missingEku = makeCert({ ...responderOpts, eku: null });
  await rejectsWithCode(
    () => check(goodStaple({ signer: missingEku, certs: [missingEku.der] })), codes.OCSP_UNVERIFIED);
});

test('anyExtendedKeyUsage does not satisfy the OCSP-signing requirement', async () => {
  const anyEku = makeCert({ ...responderOpts, eku: ['any'] });
  await rejectsWithCode(
    () => check(goodStaple({ signer: anyEku, certs: [anyEku.der] })), codes.OCSP_UNVERIFIED);
});

test('a responder certificate issued by anyone but the leaf\'s CA is refused', async () => {
  // Issued by the ROOT rather than the intermediate that issued the leaf: RFC 6960 s4.2.2.2
  // requires DIRECT issuance, or any CA anywhere could bless responders for this one.
  const wrongIssuer = makeCert({ ...responderOpts, issuer: fx.root });
  const err = await rejectsWithCode(
    () => check(goodStaple({ signer: wrongIssuer, certs: [wrongIssuer.der] })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /direct issuance/);
});

test('a forged responder certificate does not verify under the CA key', async () => {
  // Claims the intermediate as issuer, but the intermediate never signed it.
  const forged = makeCert({ ...responderOpts, issuer: {
    dnBytes: fx.intermediate.dnBytes,
    privateKey: makeCert({ subject: { CN: 'evil' }, ca: true }).privateKey,
    keyType: 'ec-p256',
    ski: null,
  } });
  const err = await rejectsWithCode(
    () => check(goodStaple({ signer: forged, certs: [forged.der] })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /does not verify under the CA key/);
});

test('an expired responder certificate is refused', async () => {
  const expired = makeCert({ ...responderOpts, notBefore: NOW - 30 * DAY, notAfter: NOW - DAY });
  const err = await rejectsWithCode(
    () => check(goodStaple({ signer: expired, certs: [expired.der] })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /not valid at/);
});

test('a responder keyUsage without digitalSignature is refused', async () => {
  const wrongKu = makeCert({ ...responderOpts, keyUsage: ['keyEncipherment'] });
  await rejectsWithCode(
    () => check(goodStaple({ signer: wrongKu, certs: [wrongKu.der] })), codes.OCSP_UNVERIFIED);
});

test('a responder nobody attached leaves nothing to verify against', async () => {
  const responder = makeCert(responderOpts);
  const err = await rejectsWithCode(
    () => check(goodStaple({ signer: responder, certs: [] })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /neither the issuing CA .* nor any certificate attached/);
});

test('id-pkix-ocsp-nocheck is recognized even when critical; other critical strangers kill', async () => {
  const nocheck = makeCert({ ...responderOpts, extraExtensions: [
    { oid: '1.3.6.1.5.5.7.48.1.5', critical: true, value: tlv(0x05) }, // NULL
  ] });
  await check(goodStaple({ signer: nocheck, certs: [nocheck.der] }));

  const strange = makeCert({ ...responderOpts, extraExtensions: [
    { oid: '1.2.3.4.5', critical: true, value: octet(new Uint8Array(0)) },
  ] });
  const err = await rejectsWithCode(
    () => check(goodStaple({ signer: strange, certs: [strange.der] })), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /critical extension/);
});

// ================================================================ freshness, on the injected clock

test('an expired window is fatal — an old "good" is a replayable one', async () => {
  const err = await rejectsWithCode(
    () => check(goodStaple({ thisUpdate: NOW - 10 * DAY, nextUpdate: NOW - 2 * DAY })),
    codes.OCSP_STALE);
  assert.match(err.message, /nextUpdate/);
  assert.match(err.message, /vs now/);
});

test('a response from the future is refused beyond clock-skew allowance', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ thisUpdate: NOW + HOUR, nextUpdate: NOW + 7 * DAY })),
    codes.OCSP_STALE);
  // ...but a few seconds of skew must not kill an honest fresh response.
  await check(goodStaple({ thisUpdate: NOW + 30 * 1000, nextUpdate: NOW + 7 * DAY }));
});

test('without nextUpdate, age is capped rather than unbounded', async () => {
  await check(goodStaple({ thisUpdate: NOW - DAY, nextUpdate: null }));
  const err = await rejectsWithCode(
    () => check(goodStaple({ thisUpdate: NOW - 11 * DAY, nextUpdate: null })), codes.OCSP_STALE);
  assert.match(err.message, /no nextUpdate/);
});

test('freshness runs on the caller\'s clock, not the machine\'s', async () => {
  // The same staple flips verdicts as the injected `now` moves — proof nothing reads Date.now().
  const staple = goodStaple({ thisUpdate: NOW + 30 * DAY, nextUpdate: NOW + 40 * DAY });
  await rejectsWithCode(() => check(staple), codes.OCSP_STALE);
  await verifyChain({
    chain, hostname: HOST, trust: anchorsMode, now: NOW + 35 * DAY, ocspResponse: staple,
  }).then(
    () => assert.fail('the leaf itself expires before that now; expected CERT_EXPIRED'),
    (e) => assert.equal(e.code, codes.CERT_EXPIRED), // the chain check bites first, as it must
  );
});

// ================================================================ parsing is fail-closed

test('a non-successful responseStatus is not a staple, named for what it was', async () => {
  const err = await rejectsWithCode(
    () => check(makeOcspResponse({ responseStatus: 3 }).der), codes.OCSP_UNVERIFIED);
  assert.match(err.message, /tryLater\(3\)/);
});

test('a non-successful status dragging responseBytes along is contradictory', async () => {
  const contradiction = seq(
    enumerated(3),
    ctx(0, seq(oid('1.3.6.1.5.5.7.48.1.1'), octet(new Uint8Array([0x30, 0x00])))),
  );
  const err = await rejectsWithCode(() => check(contradiction), codes.OCSP_PARSE);
  assert.match(err.message, /must not carry responseBytes/);
});

test('an unknown responseType is refused by OID', async () => {
  const err = await rejectsWithCode(
    () => check(goodStaple({ responseType: '1.3.6.1.5.5.7.48.1.4' })), codes.OCSP_PARSE);
  assert.match(err.message, /1\.3\.6\.1\.5\.5\.7\.48\.1\.4/);
});

test('trailing bytes and truncation are malformations, never tolerated', async () => {
  const der = goodStaple();
  const trailing = new Uint8Array(der.byteLength + 1);
  trailing.set(der);
  await rejectsWithCode(() => check(trailing), codes.OCSP_PARSE);
  await rejectsWithCode(() => check(der.subarray(0, der.byteLength - 3)), codes.OCSP_PARSE);
  await rejectsWithCode(() => check(new Uint8Array(0)), codes.OCSP_PARSE);
});

test('an encoded ResponseData version is refused, DEFAULT or otherwise', async () => {
  const asDefault = await rejectsWithCode(
    () => check(goodStaple({ encodeVersion: 0 })), codes.OCSP_PARSE);
  assert.match(asDefault.message, /must be omitted/);
  const unsupported = await rejectsWithCode(
    () => check(goodStaple({ encodeVersion: 1 })), codes.OCSP_PARSE);
  assert.match(unsupported.message, /unsupported ResponseData version/);
});

test('an unsupported CertID hash algorithm is named and refused', async () => {
  const err = await rejectsWithCode(
    () => check(goodStaple({ hashOidOverride: '1.2.840.113549.2.5' })), // md5
    codes.OCSP_PARSE);
  assert.match(err.message, /1\.2\.840\.113549\.2\.5/);
});

test('CertID hashes whose length contradicts the declared algorithm are refused', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ nameHashOverride: new Uint8Array(10).fill(1) })), codes.OCSP_PARSE);
});

test('a nextUpdate before thisUpdate is self-contradictory', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ thisUpdate: NOW, nextUpdate: NOW - DAY })), codes.OCSP_PARSE);
});

test('critical response extensions we cannot read reject the response; a nonce is inert', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ responseExtensions: [
      { oid: '1.2.3.4.5', critical: true, value: octet(new Uint8Array(0)) },
    ] })),
    codes.OCSP_PARSE);
  // The nonce is recognized (and meaningless for a staple: there was no request to bind to).
  await check(goodStaple({ responseExtensions: [
    { oid: '1.3.6.1.5.5.7.48.1.2', critical: true, value: octet(new Uint8Array(16)) },
  ] }));
  // Non-critical strangers are ignorable, per RFC 6960 s4.4.
  await check(goodStaple({ responseExtensions: [
    { oid: '1.2.3.4.5', critical: false, value: octet(new Uint8Array(0)) },
  ] }));
});

test('critical single-response extensions we cannot read reject the response', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ singleExtensions: [
      { oid: '1.2.3.4.5', critical: true, value: octet(new Uint8Array(0)) },
    ] })),
    codes.OCSP_PARSE);
});

test('a garbage certificate attached to the response is a malformation', async () => {
  await rejectsWithCode(
    () => check(goodStaple({ certs: [Uint8Array.of(0x30, 0x03, 1, 2, 3)] })), codes.OCSP_PARSE);
});

test('parseOcspResponse exposes the walked structure, and the trust index re-exports both', async () => {
  const index = await import('../../src/trust/index.js');
  assert.equal(index.verifyOcspStaple, verifyOcspStaple);
  assert.equal(index.parseOcspResponse, parseOcspResponse);
  const parsed = parseOcspResponse(goodStaple({ responderId: 'byKey' }));
  assert.equal(parsed.responseStatusName, 'successful');
  assert.equal(parsed.basic.singles.length, 1);
  assert.equal(parsed.basic.singles[0].status.kind, 'good');
  assert.equal(parsed.basic.responderId.kind, 'key');
  assert.equal(parsed.basic.responderId.keyHash.byteLength, 20);
  const revoked = parseOcspResponse(goodStaple({ status: 'revoked', reason: 4 }));
  assert.deepEqual(
    { kind: revoked.basic.singles[0].status.kind, reason: revoked.basic.singles[0].status.reason },
    { kind: 'revoked', reason: 4 });
});

test('a malformed ResponderID byKey length dies at parse', () => {
  // Hand-build ResponseData with a 19-byte KeyHash: cannot be a SHA-1, can never match.
  const single = seq(
    seq(seq(oid('1.3.14.3.2.26'), tlv(0x05)), octet(new Uint8Array(20)), octet(new Uint8Array(20)), int(1)),
    ctxPrim(0, new Uint8Array(0)),
    genTime(NOW),
  );
  const tbs = seq(ctx(2, octet(new Uint8Array(19))), genTime(NOW), seq(single));
  const basic = seq(tbs, seq(oid('1.2.840.10045.4.3.2')), tlv(0x03, [0, 1, 2]));
  const der = seq(enumerated(0), ctx(0, seq(oid('1.3.6.1.5.5.7.48.1.1'), octet(basic))));
  assert.throws(() => parseOcspResponse(der), (e) => {
    assert.equal(e.code, codes.OCSP_PARSE);
    assert.match(e.message, /20-byte SHA-1 KeyHash/);
    return true;
  });
});

// ================================================================ the policy knob

test("absence is tolerated by default — and that is the documented, argued default", async () => {
  const leaf = await check(null);
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
});

test("'require-staple' turns absence into OCSP_REQUIRED", async () => {
  const err = await rejectsWithCode(
    () => check(null, { ...anchorsMode, revocation: 'require-staple' }), codes.OCSP_REQUIRED);
  assert.match(err.message, /server.test/);
  assert.match(err.message, /require-staple/);
  // and a good staple satisfies it
  await check(goodStaple(), { ...anchorsMode, revocation: 'require-staple' });
});

test('the explicit default spelling is accepted; anything else is config, not policy', async () => {
  await check(goodStaple(), { ...anchorsMode, revocation: 'staple' });
  for (const bad of ['off', 'none', 'hard-fail', true, 1, {}]) {
    await rejectsWithCode(
      () => check(null, { ...anchorsMode, revocation: bad }), codes.CONFIG_INVALID,
      /no value that ignores a revoked certificate/);
  }
});

test('a bad revocation value fails even when no staple arrived', async () => {
  // Config errors must not hide behind a peer that happened not to staple.
  await rejectsWithCode(
    () => check(null, { ...anchorsMode, revocation: 'nonsense' }), codes.CONFIG_INVALID);
});

test("revocation is refused on mode 'none' and mode 'custom'", async () => {
  await rejectsWithCode(
    () => check(null, { mode: 'none', insecureAcceptAnyCertificate: true, revocation: 'staple' }),
    codes.CONFIG_INVALID, /not meaningful with mode 'none'/);
  await rejectsWithCode(
    () => check(null, { mode: 'custom', verify: async () => {}, revocation: 'staple' }),
    codes.CONFIG_INVALID, /not meaningful with mode 'custom'/);
});

test("mode 'none' performs no revocation check — that is what 'none' means", async () => {
  // Documented, not accidental: without a validated issuer there is no trusted key to check a
  // staple against, and mode 'none' asked for no verification.
  await check(goodStaple({ status: 'revoked' }), { mode: 'none', insecureAcceptAnyCertificate: true });
});

test('custom mode receives the staple and owns the decision', async () => {
  const seen = [];
  await check(goodStaple(), {
    mode: 'custom',
    verify: (parsedChain, hostname, details) => {
      seen.push({ hostname, bytes: details.ocspResponse?.byteLength ?? null });
    },
  });
  await check(null, { mode: 'custom', verify: (c, h, details) => {
    seen.push({ bytes: details.ocspResponse });
  } });
  assert.equal(seen.length, 2);
  assert.ok(seen[0].bytes > 0, 'the staple bytes reach the custom callback');
  assert.equal(seen[1].bytes, null);
});

test('system mode accepts the revocation knob (config-level only, no live chain here)', async () => {
  // Our factory chain cannot anchor in the bundled store, so only the config path is provable
  // offline: the knob must not be refused as an unknown key.
  const err = await verifyChain({
    chain, hostname: HOST, trust: { mode: 'system', revocation: 'require-staple' }, now: NOW,
  }).then(() => null, (e) => e);
  assert.ok(err, 'the factory chain must not validate against the bundled store');
  assert.notEqual(err.code, codes.CONFIG_INVALID,
    `revocation on mode system must be accepted as config, got: ${err.message}`);
});
