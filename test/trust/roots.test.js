// Root store generator: re-derives a store from factory-minted PEM roots and proves the
// generated module is faithful — a generator bug must not be able to pass unnoticed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { equal } from '../../src/util/bytes.js';
import { parseCertificate } from '../../src/trust/x509.js';
import { validatePath } from '../../src/trust/path.js';
import { buildAnchors, buildModuleSource } from '../../scripts/refresh-roots.mjs';
import { caFixture, makeCert, toPem } from './_certs.js';

const fx = caFixture();
const constrained = makeCert({
  subject: { CN: 'Constrained Fixture Root', O: 'tunnelfetch' },
  ca: true,
  nameConstraints: { permitted: [{ dns: 'inside.test' }], critical: true },
});
const fixturePem = toPem(fx.root.der) + toPem(constrained.der);
const meta = { source: 'file:fixture.pem', retrievedAt: '2026-07-31' };

async function importGenerated(pemText) {
  const dir = mkdtempSync(join(tmpdir(), 'tunnelfetch-roots-'));
  const { code, count } = buildModuleSource(pemText, meta);
  // the generated module imports ../util/bytes.js, so mirror the src layout
  const file = join(dir, 'trust-roots.mjs');
  writeFileSync(file, code.replace("'../util/bytes.js'",
    JSON.stringify(pathToFileURL(join(process.cwd(), 'src/util/bytes.js')).href)));
  return { mod: await import(pathToFileURL(file).href), count };
}

test('generated store matches a direct parse of the fixture roots', async () => {
  const { mod, count } = await importGenerated(fixturePem);
  assert.equal(count, 2);
  assert.equal(mod.provenance.anchorCount, 2);
  assert.equal(mod.provenance.source, meta.source);
  assert.equal(mod.provenance.retrievedAt, meta.retrievedAt);
  assert.match(mod.provenance.upstreamSha256, /^[0-9a-f]{64}$/);

  for (const der of [fx.root.der, constrained.der]) {
    const cert = parseCertificate(der);
    const found = await mod.systemAnchors.forIssuer(cert.subject.bytes);
    assert.equal(found.length, 1, `anchor for ${cert.subject.text}`);
    const a = found[0];
    assert.equal(a.subjectText, cert.subject.text);
    assert.ok(equal(a.subjectBytes, cert.subject.bytes));
    assert.ok(equal(a.spkiDer, cert.spki.spkiDer));
    assert.ok(equal(a.subjectKeyIdentifier, cert.subjectKeyIdentifier));
    assert.equal(a.notBefore, cert.notBefore);
    assert.equal(a.notAfter, cert.notAfter);
  }
  // the name-constrained root keeps its raw constraint bytes; the plain root has none
  const plain = (await mod.systemAnchors.forIssuer(parseCertificate(fx.root.der).subject.bytes))[0];
  assert.equal(plain.nameConstraintsBytes, null);
  const nc = (await mod.systemAnchors.forIssuer(parseCertificate(constrained.der).subject.bytes))[0];
  assert.ok(nc.nameConstraintsBytes instanceof Uint8Array);

  // an unknown issuer resolves to no anchors, not an error
  assert.deepEqual(await mod.systemAnchors.forIssuer(parseCertificate(fx.leaf.der).subject.bytes), []);
});

test('the generated store works as the anchor source for real path validation', async () => {
  const { mod } = await importGenerated(fixturePem);
  const { leaf } = await validatePath({
    chain: [fx.leaf.der, fx.intermediate.der],
    anchors: mod.systemAnchors,
    hostname: 'server.test',
  });
  assert.equal(leaf.subject.text, 'CN=server.test, O=tunnelfetch');
  // and the stored name constraints are live: a leaf outside the subtree is rejected
  const badLeaf = makeCert({ subject: { CN: 'outside.test' }, issuer: constrained, san: { dns: ['outside.test'] } });
  await assert.rejects(
    () => validatePath({ chain: [badLeaf.der], anchors: mod.systemAnchors, hostname: 'outside.test' }),
    (e) => e.code === 'CERT_CONSTRAINT');
});

test('generation is deterministic and deduplicates identical roots', () => {
  const a = buildModuleSource(fixturePem, meta);
  const b = buildModuleSource(fixturePem, meta);
  assert.equal(a.code, b.code);
  assert.equal(buildAnchors(fixturePem + fixturePem).length, 2); // same roots twice -> 2 anchors
});

test('generator refuses a non-self-signed certificate in the feed', () => {
  assert.throws(() => buildAnchors(toPem(fx.intermediate.der)), /not self-issued/);
});

test('the checked-in store is coherent: fully populated with provenance, or loudly empty', async () => {
  const mod = await import('../../src/trust/roots.js');
  if (mod.provenance.anchorCount === 0) {
    // Placeholder state: all provenance null, so "never generated" cannot pass as "no trust".
    assert.equal(mod.provenance.source, null);
    assert.equal(mod.provenance.retrievedAt, null);
    assert.equal(mod.provenance.upstreamSha256, null);
  } else {
    // Generated state: provenance must say exactly where the anchors came from. The source is a
    // feed identifier, never a URL — src/ carries no endpoints, per the repo hygiene suite.
    assert.match(mod.provenance.source, /^(ccadb:|file:)/);
    assert.match(mod.provenance.retrievedAt, /^\d{4}-\d{2}-\d{2}$/);
    assert.match(mod.provenance.upstreamSha256, /^[0-9a-f]{64}$/);
  }
  // Either way, our test fixture root is not in it.
  assert.deepEqual(await mod.systemAnchors.forIssuer(parseCertificate(fx.root.der).subject.bytes), []);
});
