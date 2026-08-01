// EKU chaining across the certification path.
//
// The validator already refuses a LEAF whose extendedKeyUsage excludes serverAuth (see
// path.test.js "leaf EKU must include serverAuth or anyExtendedKeyUsage"). The CA/Browser Forum
// Baseline Requirements and every mainstream browser (mozilla::pkix, Chrome, Safari) extend that
// rule up the chain: an INTERMEDIATE that carries an extendedKeyUsage extension must include
// serverAuth (or anyExtendedKeyUsage) too, or the chain is not usable for TLS server
// authentication. This is the mechanism that makes a "technically constrained" sub-CA safe: a CA
// can delegate a sub-CA restricted to id-kp-emailProtection (or id-kp-clientAuth), relying on EKU
// chaining so that a compromise of that sub-CA cannot mint TLS server certificates.
//
// These tests assert the CORRECT (browser-equivalent) behaviour: a serverAuth leaf under an
// intermediate whose EKU excludes serverAuth must be REJECTED. They FAIL against the current
// validator, which reads extendedKeyUsage only on the leaf (src/trust/path.js: the `isLeaf`
// branch of validatePath) and never on the intermediates above it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import { validatePath, anchorFromCertificate } from '../../src/trust/path.js';
import { parseCertificate } from '../../src/trust/x509.js';
import { caFixture } from './_certs.js';

const anchorOf = (bundle) => anchorFromCertificate(parseCertificate(bundle.der));
const HOST = 'server.test';

// id-kp-emailProtection — an S/MIME purpose that must not license issuing TLS server certs.
const EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';

/** Three-tier fixture whose intermediate carries `intermediateEku` (null = no EKU extension). */
function fixtureWithIntermediateEku(intermediateEku) {
  const fx = caFixture({ intermediate: { eku: intermediateEku } });
  return { chain: [fx.leaf.der, fx.intermediate.der], anchors: [anchorOf(fx.root)] };
}

// ---- must reject: the intermediate is technically constrained AWAY from serverAuth ----------

test('a clientAuth-only intermediate cannot issue a serverAuth leaf', async () => {
  const { chain, anchors } = fixtureWithIntermediateEku(['clientAuth']);
  await rejectsWithCode(
    async () => validatePath({ chain, anchors, hostname: HOST }),
    codes.CERT_CONSTRAINT, /serverAuth/);
});

test('an emailProtection-only intermediate cannot issue a serverAuth leaf', async () => {
  const { chain, anchors } = fixtureWithIntermediateEku([EMAIL_PROTECTION]);
  await rejectsWithCode(
    async () => validatePath({ chain, anchors, hostname: HOST }),
    codes.CERT_CONSTRAINT, /serverAuth/);
});

// ---- must accept: the intermediate's EKU permits serverAuth, or is absent (unconstrained) ----

test('an intermediate whose EKU includes serverAuth is accepted', async () => {
  const { chain, anchors } = fixtureWithIntermediateEku(['serverAuth', 'clientAuth']);
  const { leaf } = await validatePath({ chain, anchors, hostname: HOST });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
});

test('an intermediate with anyExtendedKeyUsage is accepted', async () => {
  const { chain, anchors } = fixtureWithIntermediateEku(['any']);
  const { leaf } = await validatePath({ chain, anchors, hostname: HOST });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
});

test('an intermediate with no EKU extension is unconstrained and accepted', async () => {
  const { chain, anchors } = fixtureWithIntermediateEku(null);
  const { leaf } = await validatePath({ chain, anchors, hostname: HOST });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
});
