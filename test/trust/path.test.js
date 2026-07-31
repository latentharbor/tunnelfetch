// Path building + RFC 5280 validation: the full negative matrix, each asserted by err.code.
// Every certificate here is genuinely signed by the factory, so signature checks are real.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import { equal } from '../../src/util/bytes.js';
import { validatePath, anchorFromCertificate } from '../../src/trust/path.js';
import { parseCertificate } from '../../src/trust/x509.js';
import { caFixture, makeCert, flipSignatureByte, ip4, nul } from './_certs.js';

const anchorOf = (bundle) => anchorFromCertificate(parseCertificate(bundle.der));
const HOST = 'server.test';
const DAY = 24 * 3600 * 1000;

const fx = caFixture();
const anchors = [anchorOf(fx.root)];
const validate = (chain, opts = {}) =>
  validatePath({ chain, anchors, hostname: HOST, ...opts });
const wants = (code, chain, opts, re) =>
  rejectsWithCode(async () => validate(chain, opts), code, re);

test('a correct leaf-first chain validates and returns the parsed leaf', async () => {
  const { leaf, path, anchor } = await validate([fx.leaf.der, fx.intermediate.der]);
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
  assert.equal(path.length, 2);
  assert.ok(equal(anchor.spkiDer, fx.root.spkiDer));
});

test('out-of-order chain with an irrelevant extra certificate still validates', async () => {
  const stranger = caFixture({ root: { subject: { CN: 'Stranger Root', O: 'other' } } });
  const { path } = await validate([
    fx.leaf.der,
    stranger.intermediate.der, // irrelevant cert from another PKI
    fx.intermediate.der, // the real issuer, not adjacent to the leaf
  ]);
  assert.equal(path.length, 2); // the stranger is not on the validated path
});

test('a self-signed root included in the chain is ignored in favour of the anchor', async () => {
  const { path, anchor } = await validate([fx.leaf.der, fx.intermediate.der, fx.root.der]);
  assert.equal(path.length, 2);
  assert.ok(equal(anchor.spkiDer, fx.root.spkiDer));
});

test('expired leaf and expired intermediate, each named', async () => {
  const now = Date.now();
  const exp = caFixture({ leaf: { notBefore: now - 10 * DAY, notAfter: now - DAY } });
  let e = await rejectsWithCode(
    async () => validatePath({ chain: [exp.leaf.der, exp.intermediate.der], anchors: [anchorOf(exp.root)], hostname: HOST }),
    codes.CERT_EXPIRED, /CN=server\.test/);
  assert.match(e.message, /expired/);

  const expInt = caFixture({ intermediate: { notBefore: now - 10 * DAY, notAfter: now - DAY } });
  e = await rejectsWithCode(
    async () => validatePath({ chain: [expInt.leaf.der, expInt.intermediate.der], anchors: [anchorOf(expInt.root)], hostname: HOST }),
    codes.CERT_EXPIRED, /CN=Test Intermediate CA/);
});

test('not-yet-valid leaf is rejected with the activation instant', async () => {
  const now = Date.now();
  const soon = caFixture({ leaf: { notBefore: now + DAY, notAfter: now + 30 * DAY } });
  const e = await rejectsWithCode(
    async () => validatePath({ chain: [soon.leaf.der, soon.intermediate.der], anchors: [anchorOf(soon.root)], hostname: HOST }),
    codes.CERT_NOT_YET_VALID, /not valid until/);
  assert.ok(e.detail.notBefore > now);
});

test('the `now` knob is honoured', async () => {
  const past = Date.now() - 60 * DAY;
  const window = { notBefore: past - DAY, notAfter: past + DAY };
  const old = caFixture({ leaf: window, intermediate: window, root: window });
  const chain = [old.leaf.der, old.intermediate.der];
  const a = [anchorOf(old.root)];
  await validatePath({ chain, anchors: a, hostname: HOST, now: past }); // valid back then
  await rejectsWithCode(async () => validatePath({ chain, anchors: a, hostname: HOST }),
    codes.CERT_EXPIRED);
});

test('hostname mismatch surfaces through path validation', async () => {
  await wants(codes.CERT_NAME_MISMATCH, [fx.leaf.der, fx.intermediate.der], { hostname: 'other.test' });
});

test('one flipped signature byte on the leaf is CERT_SIGNATURE_INVALID', async () => {
  const e = await wants(codes.CERT_SIGNATURE_INVALID,
    [flipSignatureByte(fx.leaf.der), fx.intermediate.der], {}, /did not verify/);
  assert.match(e.message, /CN=server\.test/);
});

test('one flipped signature byte on the intermediate is also caught', async () => {
  await wants(codes.CERT_SIGNATURE_INVALID,
    [fx.leaf.der, flipSignatureByte(fx.intermediate.der)], {}, /CN=Test Intermediate CA/);
});

test('chain to an unknown self-signed root: CERT_UNTRUSTED_ROOT', async () => {
  const rogue = caFixture({ root: { subject: { CN: 'Rogue Root', O: 'rogue' } } });
  const e = await rejectsWithCode(
    async () => validate([rogue.leaf.der, rogue.intermediate.der, rogue.root.der]),
    codes.CERT_UNTRUSTED_ROOT, /Rogue Root/);
  assert.match(e.message, /not a trust anchor/);
});

test('self-signed leaf presented alone: CERT_UNTRUSTED_ROOT', async () => {
  const lone = makeCert({ subject: { CN: HOST } });
  await wants(codes.CERT_UNTRUSTED_ROOT, [lone.der], {}, /self-signed/);
});

test('missing intermediate: CERT_CHAIN_INCOMPLETE names the absent issuer', async () => {
  const e = await wants(codes.CERT_CHAIN_INCOMPLETE, [fx.leaf.der], {}, /no certificate for issuer/);
  assert.match(e.message, /CN=Test Intermediate CA/);
});

test('empty chain: CERT_CHAIN_INCOMPLETE', async () => {
  await wants(codes.CERT_CHAIN_INCOMPLETE, [], {}, /no certificates/);
});

test('intermediate without the CA bit cannot issue', async () => {
  // ca:false drops basicConstraints entirely (the DER-honest way to not be a CA).
  const noCa = caFixture({ intermediate: { ca: false, keyUsage: ['digitalSignature', 'keyCertSign'], san: null } });
  const e = await rejectsWithCode(
    async () => validatePath({ chain: [noCa.leaf.der, noCa.intermediate.der], anchors: [anchorOf(noCa.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /no basicConstraints/);
  assert.match(e.message, /CN=Test Intermediate CA/);
});

test('intermediate whose keyUsage lacks keyCertSign cannot issue', async () => {
  const weakKu = caFixture({ intermediate: { keyUsage: ['digitalSignature', 'cRLSign'] } });
  await rejectsWithCode(
    async () => validatePath({ chain: [weakKu.leaf.der, weakKu.intermediate.der], anchors: [anchorOf(weakKu.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /keyCertSign/);
});

test('pathLenConstraint: a zero-depth CA may issue leaves but not further CAs', async () => {
  const root = makeCert({ subject: { CN: 'PL Root' }, ca: true });
  const a = makeCert({ subject: { CN: 'PL A' }, issuer: root, ca: true, pathLen: 0 });
  const b = makeCert({ subject: { CN: 'PL B' }, issuer: a, ca: true });
  const leafViaB = makeCert({ subject: { CN: HOST }, issuer: b, san: { dns: [HOST] } });
  const e = await rejectsWithCode(
    async () => validatePath({ chain: [leafViaB.der, b.der, a.der], anchors: [anchorOf(root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /pathLenConstraint 0 imposed by "CN=PL A"/);
  assert.match(e.message, /CN=PL B/);
  // but a leaf directly under the constrained CA is fine
  const leafViaA = makeCert({ subject: { CN: HOST }, issuer: a, san: { dns: [HOST] } });
  await validatePath({ chain: [leafViaA.der, a.der], anchors: [anchorOf(root)], hostname: HOST });
});

test('permitted-subtree name constraint: leaf outside the subtree is rejected', async () => {
  const nc = caFixture({
    intermediate: { nameConstraints: { permitted: [{ dns: 'example.test' }], critical: true } },
    leaf: { san: { dns: ['server.test'] } },
  });
  const e = await rejectsWithCode(
    async () => validatePath({ chain: [nc.leaf.der, nc.intermediate.der], anchors: [anchorOf(nc.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /outside the permitted subtrees/);
  assert.match(e.message, /server\.test/);
  assert.match(e.message, /CN=Test Intermediate CA/);
  // and a leaf inside the subtree passes
  const good = caFixture({
    intermediate: { nameConstraints: { permitted: [{ dns: 'example.test' }], critical: true } },
    leaf: { san: { dns: ['a.example.test'] } },
  });
  await validatePath({ chain: [good.leaf.der, good.intermediate.der], anchors: [anchorOf(good.root)], hostname: 'a.example.test' });
});

test('excluded-subtree name constraints for DNS and IP', async () => {
  const ncDns = caFixture({
    intermediate: { nameConstraints: { excluded: [{ dns: 'forbidden.test' }], critical: true } },
    leaf: { san: { dns: ['x.forbidden.test'] } },
  });
  await rejectsWithCode(
    async () => validatePath({ chain: [ncDns.leaf.der, ncDns.intermediate.der], anchors: [anchorOf(ncDns.root)], hostname: 'x.forbidden.test' }),
    codes.CERT_CONSTRAINT, /excluded/);

  const subtree = new Uint8Array(8);
  subtree.set(ip4('192.0.2.0'), 0);
  subtree.set(ip4('255.255.255.0'), 4);
  const ncIp = caFixture({
    intermediate: { nameConstraints: { excluded: [{ ip: subtree }], critical: true } },
    leaf: { san: { dns: [HOST], ip: [ip4('192.0.2.99')] } },
  });
  await rejectsWithCode(
    async () => validatePath({ chain: [ncIp.leaf.der, ncIp.intermediate.der], anchors: [anchorOf(ncIp.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /iPAddress/);
});

test('name constraints imposed by the trust anchor itself are enforced', async () => {
  const root = makeCert({
    subject: { CN: 'Constrained Root' }, ca: true,
    nameConstraints: { permitted: [{ dns: 'allowed.test' }], critical: true },
  });
  const leaf = makeCert({ subject: { CN: HOST }, issuer: root, san: { dns: [HOST] } });
  await rejectsWithCode(
    async () => validatePath({ chain: [leaf.der], anchors: [anchorOf(root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /Constrained Root/);
});

test('unsupported constraint type: critical rejects, non-critical is ignored', async () => {
  const mk = (critical) => caFixture({
    intermediate: { nameConstraints: { permitted: [{ email: 'x@mail.test' }], critical } },
  });
  const crit = mk(true);
  await rejectsWithCode(
    async () => validatePath({ chain: [crit.leaf.der, crit.intermediate.der], anchors: [anchorOf(crit.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /unsupported type in a critical/);
  const lax = mk(false);
  await validatePath({ chain: [lax.leaf.der, lax.intermediate.der], anchors: [anchorOf(lax.root)], hostname: HOST });
});

test('unknown critical extension anywhere on the path is fatal', async () => {
  const weird = caFixture({
    intermediate: { extraExtensions: [{ oid: '1.3.6.1.4.1.99999.7', critical: true, value: nul() }] },
  });
  const e = await rejectsWithCode(
    async () => validatePath({ chain: [weird.leaf.der, weird.intermediate.der], anchors: [anchorOf(weird.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /unrecognised critical extension/);
  assert.match(e.message, /1\.3\.6\.1\.4\.1\.99999\.7/);
  // on the leaf too
  const weirdLeaf = caFixture({
    leaf: { extraExtensions: [{ oid: '1.3.6.1.4.1.99999.8', critical: true, value: nul() }] },
  });
  await rejectsWithCode(
    async () => validatePath({ chain: [weirdLeaf.leaf.der, weirdLeaf.intermediate.der], anchors: [anchorOf(weirdLeaf.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /1\.3\.6\.1\.4\.1\.99999\.8/);
});

test('SHA-1 and MD5 signatures die in path validation with CERT_SIGNATURE_WEAK', async () => {
  const sha1 = caFixture({ leaf: { sigHash: 'sha1' } });
  await rejectsWithCode(
    async () => validatePath({ chain: [sha1.leaf.der, sha1.intermediate.der], anchors: [anchorOf(sha1.root)], hostname: HOST }),
    codes.CERT_SIGNATURE_WEAK, /SHA-1|sha1/i);
  const md5 = caFixture({ keyType: 'rsa', leaf: { sigHash: 'md5' } });
  await rejectsWithCode(
    async () => validatePath({ chain: [md5.leaf.der, md5.intermediate.der], anchors: [anchorOf(md5.root)], hostname: HOST }),
    codes.CERT_SIGNATURE_WEAK, /md5WithRSAEncryption/);
});

test('a SHA-1 self-signed root in the chain does not break a modern path', async () => {
  // The root's own signature is never consumed, so its algorithm must not matter.
  const root = makeCert({ subject: { CN: 'Old Root' }, keyType: 'rsa', ca: true, sigHash: 'sha1' });
  const inter = makeCert({ subject: { CN: 'Modern Int' }, issuer: root, ca: true, keyType: 'rsa' });
  const leaf = makeCert({ subject: { CN: HOST }, issuer: inter, keyType: 'rsa', san: { dns: [HOST] } });
  const { path } = await validatePath({
    chain: [leaf.der, inter.der, root.der], anchors: [anchorOf(root)], hostname: HOST,
  });
  assert.equal(path.length, 2);
});

test('leaf EKU must include serverAuth or anyExtendedKeyUsage', async () => {
  const clientOnly = caFixture({ leaf: { eku: ['clientAuth'] } });
  const e = await rejectsWithCode(
    async () => validatePath({ chain: [clientOnly.leaf.der, clientOnly.intermediate.der], anchors: [anchorOf(clientOnly.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /serverAuth/);
  assert.match(e.message, /1\.3\.6\.1\.5\.5\.7\.3\.2/);
  const anyEku = caFixture({ leaf: { eku: ['any'] } });
  await validatePath({ chain: [anyEku.leaf.der, anyEku.intermediate.der], anchors: [anchorOf(anyEku.root)], hostname: HOST });
  const noEku = caFixture({ leaf: { eku: null } });
  await validatePath({ chain: [noEku.leaf.der, noEku.intermediate.der], anchors: [anchorOf(noEku.root)], hostname: HOST });
});

test('leaf keyUsage without digitalSignature is rejected', async () => {
  const kx = caFixture({ leaf: { keyUsage: ['keyEncipherment'] } });
  await rejectsWithCode(
    async () => validatePath({ chain: [kx.leaf.der, kx.intermediate.der], anchors: [anchorOf(kx.root)], hostname: HOST }),
    codes.CERT_CONSTRAINT, /digitalSignature/);
});

test('a leaf that is also a CA is legal as an end entity', async () => {
  const caLeaf = caFixture({
    leaf: { ca: true, keyUsage: ['digitalSignature', 'keyCertSign'], eku: ['serverAuth'], san: { dns: [HOST] } },
  });
  const { leaf } = await validatePath({
    chain: [caLeaf.leaf.der, caLeaf.intermediate.der], anchors: [anchorOf(caLeaf.root)], hostname: HOST,
  });
  assert.equal(leaf.basicConstraints.ca, true);
});

test('maxPathLength caps pathological chains', async () => {
  let issuer = makeCert({ subject: { CN: 'Deep Root' }, ca: true });
  const root = issuer;
  const chain = [];
  for (let i = 0; i < 12; i++) {
    issuer = makeCert({ subject: { CN: `Deep CA ${i}` }, issuer, ca: true });
    chain.unshift(issuer.der);
  }
  const leaf = makeCert({ subject: { CN: HOST }, issuer, san: { dns: [HOST] } });
  chain.unshift(leaf.der);
  await rejectsWithCode(
    async () => validatePath({ chain, anchors: [anchorOf(root)], hostname: HOST, maxPathLength: 5 }),
    codes.CERT_CONSTRAINT, /exceeded 5 certificates/);
});

test('two anchors sharing a DN: the signature picks the right one', async () => {
  // Root rollover: same name, different keys. The chain must land on the key that signed it.
  const name = { CN: 'Rollover Root', O: 'shared' };
  const oldRoot = makeCert({ subject: name, ca: true, ski: false });
  const newRoot = makeCert({ subject: name, ca: true, ski: false });
  const leaf = makeCert({ subject: { CN: HOST }, issuer: newRoot, san: { dns: [HOST] }, aki: false });
  const { anchor } = await validatePath({
    chain: [leaf.der], anchors: [anchorOf(oldRoot), anchorOf(newRoot)], hostname: HOST,
  });
  assert.ok(equal(anchor.spkiDer, newRoot.spkiDer));
});

test('anchors may be given as raw DER', async () => {
  await validatePath({ chain: [fx.leaf.der, fx.intermediate.der], anchors: [fx.root.der], hostname: HOST });
});

test('mixed-algorithm chain: RSA root signing an EC leaf', async () => {
  const root = makeCert({ subject: { CN: 'RSA Root' }, keyType: 'rsa', ca: true });
  const leaf = makeCert({ subject: { CN: HOST }, issuer: root, keyType: 'ec-p256', san: { dns: [HOST] } });
  const { leaf: parsed } = await validatePath({ chain: [leaf.der], anchors: [anchorOf(root)], hostname: HOST });
  assert.equal(parsed.spki.curveOid, '1.2.840.10045.3.1.7');
});
