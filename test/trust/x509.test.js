// Certificate parser: field extraction cross-checked against node:crypto's X509Certificate
// (allowed here in test/, never in src/), plus the parser-level rejections.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import { equal } from '../../src/util/bytes.js';
import {
  parseCertificate, resolveSignatureScheme, decodePem, OID,
} from '../../src/trust/x509.js';
import {
  caFixture, makeCert, toPem, ip4, seq, oid, nul, int, ctx, pssParams,
} from './_certs.js';

const fx = caFixture({
  leaf: { san: { dns: ['server.test', '*.wild.test'], ip: [ip4('192.0.2.7')] } },
  intermediate: { pathLen: 0 },
});

test('parses the standard fixture and agrees with node:crypto', () => {
  for (const bundle of [fx.root, fx.intermediate, fx.leaf]) {
    const ours = parseCertificate(bundle.der);
    const theirs = new X509Certificate(Buffer.from(bundle.der));
    assert.equal(ours.version, 3);
    assert.ok(equal(ours.der, new Uint8Array(theirs.raw)));
    // node renders the DN newline-separated; ours comma-separated
    assert.equal(ours.subject.text, theirs.subject.split('\n').join(', '));
    assert.equal(ours.issuer.text, theirs.issuer.split('\n').join(', '));
    assert.equal(new Date(ours.notBefore).toISOString(), theirs.validFromDate.toISOString());
    assert.equal(new Date(ours.notAfter).toISOString(), theirs.validToDate.toISOString());
    assert.equal(ours.basicConstraints.ca, theirs.ca);
    assert.equal(ours.serialNumber.replace(/^0+/, '').toLowerCase(),
      theirs.serialNumber.replace(/^0+/, '').toLowerCase());
  }
});

test('tbsBytes is an exact slice of the original DER', () => {
  const cert = parseCertificate(fx.leaf.der);
  assert.equal(cert.tbsBytes.buffer, cert.der.buffer);
  // the TBS starts right after the outer SEQUENCE header
  const headerLen = cert.der.byteLength - cert.tbsBytes.byteOffset + cert.tbsBytes.byteOffset;
  assert.ok(cert.tbsBytes.byteOffset > 0 && cert.tbsBytes.byteOffset <= 4);
  assert.ok(headerLen > 0);
});

test('pathLenConstraint comes from our own DER walk', () => {
  const inter = parseCertificate(fx.intermediate.der);
  assert.deepEqual(inter.basicConstraints, { present: true, ca: true, pathLenConstraint: 0 });
  const root = parseCertificate(fx.root.der);
  assert.deepEqual(root.basicConstraints, { present: true, ca: true, pathLenConstraint: null });
  const leaf = parseCertificate(fx.leaf.der);
  assert.deepEqual(leaf.basicConstraints, { present: false, ca: false, pathLenConstraint: null });
});

test('keyUsage bits are real bits, not EKU OIDs', () => {
  const root = parseCertificate(fx.root.der);
  assert.equal(root.keyUsage.keyCertSign, true);
  assert.equal(root.keyUsage.cRLSign, true);
  assert.equal(root.keyUsage.digitalSignature, false);
  const leaf = parseCertificate(fx.leaf.der);
  assert.equal(leaf.keyUsage.digitalSignature, true);
  assert.equal(leaf.keyUsage.keyCertSign, false);
});

test('extendedKeyUsage, SAN, SKI/AKI round-trip', () => {
  const leaf = parseCertificate(fx.leaf.der);
  assert.deepEqual([...leaf.extendedKeyUsage], [OID.serverAuth]);
  assert.deepEqual([...leaf.subjectAltNames.dns], ['server.test', '*.wild.test']);
  assert.equal(leaf.subjectAltNames.ip.length, 1);
  assert.ok(equal(leaf.subjectAltNames.ip[0], ip4('192.0.2.7')));
  assert.ok(equal(leaf.subjectKeyIdentifier, fx.leaf.ski));
  assert.ok(equal(leaf.authorityKeyIdentifier, fx.intermediate.ski));
  const root = parseCertificate(fx.root.der);
  assert.equal(root.extendedKeyUsage, null);
  assert.equal(root.subjectAltNames.present, false);
  assert.equal(root.isSelfIssued, true);
  assert.equal(leaf.isSelfIssued, false);
});

test('outer/inner signatureAlgorithm mismatch is rejected as an attack signature', async () => {
  // Reassemble the leaf with a different OUTER algorithm than the TBS claims.
  const cert = parseCertificate(fx.leaf.der);
  const sigBytes = cert.signature;
  const outer = seq(oid('1.2.840.10045.4.3.3')); // ecdsa-with-SHA384, TBS says SHA256
  const forged = seq(cert.tbsBytes, outer, Uint8Array.of(0x03, sigBytes.length + 1, 0, ...sigBytes));
  const e = await rejectsWithCode(async () => parseCertificate(forged), codes.CERT_PARSE,
    /signatureAlgorithm mismatch/);
  assert.match(e.message, /1\.2\.840\.10045\.4\.3\.3/);
  assert.match(e.message, /1\.2\.840\.10045\.4\.3\.2/);
});

test('same OID with different parameters is still a mismatch', async () => {
  const cert = parseCertificate(fx.leaf.der);
  const outer = seq(oid('1.2.840.10045.4.3.2'), nul()); // spurious NULL params added
  const forged = seq(cert.tbsBytes, outer,
    Uint8Array.of(0x03, cert.signature.length + 1, 0, ...cert.signature));
  await rejectsWithCode(async () => parseCertificate(forged), codes.CERT_PARSE,
    /same OID, different parameters/);
});

test('unknown critical extensions are recorded; non-critical ones are not', () => {
  const withCritical = makeCert({
    subject: { CN: 'crit.test' },
    extraExtensions: [
      { oid: '1.3.6.1.4.1.99999.1', critical: true, value: nul() },
      { oid: '1.3.6.1.4.1.99999.2', critical: false, value: nul() },
    ],
  });
  const cert = parseCertificate(withCritical.der);
  assert.deepEqual([...cert.unknownCriticalExtensions], ['1.3.6.1.4.1.99999.1']);
  // known critical extensions never land in the unknown list
  const leaf = parseCertificate(fx.leaf.der);
  assert.deepEqual([...leaf.unknownCriticalExtensions], []);
});

test('duplicate extensions are rejected', async () => {
  const dup = makeCert({
    subject: { CN: 'dup.test' },
    extraExtensions: [
      { oid: '1.3.6.1.4.1.99999.1', critical: false, value: nul() },
      { oid: '1.3.6.1.4.1.99999.1', critical: false, value: int(1) },
    ],
  });
  await rejectsWithCode(async () => parseCertificate(dup.der), codes.CERT_PARSE, /duplicate extension/);
});

test('pathLenConstraint without cA is self-contradictory and rejected', async () => {
  const bad = makeCert({ subject: { CN: 'x.test' }, ca: false, pathLen: 3 });
  await rejectsWithCode(async () => parseCertificate(bad.der), codes.CERT_PARSE,
    /pathLenConstraint present without cA/);
});

test('NUL bytes in SAN dNSName are rejected at parse time', async () => {
  const nulCert = makeCert({ subject: { CN: 'nul.test' }, san: { dns: ['good.test\0.evil.test'] } });
  await rejectsWithCode(async () => parseCertificate(nulCert.der), codes.CERT_PARSE, /NUL byte/);
});

test('v1 certificates parse with no extensions', () => {
  const v1 = makeCert({ subject: { CN: 'v1.test' }, version: 1 });
  const cert = parseCertificate(v1.der);
  assert.equal(cert.version, 1);
  assert.equal(cert.extensions.size, 0);
  assert.equal(cert.basicConstraints.present, false);
  assert.equal(cert.subjectAltNames.present, false);
});

test('truncated and trailing-garbage certificates are rejected', async () => {
  await rejectsWithCode(async () => parseCertificate(fx.leaf.der.subarray(0, 60)),
    codes.CERT_PARSE, /runs past end/);
  const padded = new Uint8Array(fx.leaf.der.byteLength + 1);
  padded.set(fx.leaf.der);
  await rejectsWithCode(async () => parseCertificate(padded), codes.CERT_PARSE, /trailing bytes/);
  await rejectsWithCode(async () => parseCertificate('not bytes'), codes.CERT_PARSE, /Uint8Array/);
});

// ------------------------------------------------------------------ signature scheme resolution

test('SHA-1 and MD5 signature algorithms are rejected by OID with the right code', async () => {
  const sha1Ec = caFixture({ leaf: { sigHash: 'sha1' } });
  let e = await rejectsWithCode(
    async () => resolveSignatureScheme(parseCertificate(sha1Ec.leaf.der)),
    codes.CERT_SIGNATURE_WEAK, /ecdsa-with-SHA1/);
  assert.match(e.message, /1\.2\.840\.10045\.4\.1/);

  const rsa = caFixture({ keyType: 'rsa', leaf: { sigHash: 'sha1' } });
  e = await rejectsWithCode(
    async () => resolveSignatureScheme(parseCertificate(rsa.leaf.der)),
    codes.CERT_SIGNATURE_WEAK, /sha1WithRSAEncryption/);
  assert.match(e.message, /1\.2\.840\.113549\.1\.1\.5/);

  const md5 = caFixture({ keyType: 'rsa', leaf: { sigHash: 'md5' } });
  e = await rejectsWithCode(
    async () => resolveSignatureScheme(parseCertificate(md5.leaf.der)),
    codes.CERT_SIGNATURE_WEAK, /md5WithRSAEncryption/);
  assert.match(e.message, /1\.2\.840\.113549\.1\.1\.4/);
});

test('modern schemes resolve; unknown algorithms are unsupported, not invalid', async () => {
  assert.equal(resolveSignatureScheme(parseCertificate(fx.leaf.der)).kind, 'ecdsa');
  const rsa = caFixture({ keyType: 'rsa' });
  assert.equal(resolveSignatureScheme(parseCertificate(rsa.leaf.der)).kind, 'rsa-pkcs1');
  const ed = caFixture({ keyType: 'ed25519' });
  assert.equal(resolveSignatureScheme(parseCertificate(ed.leaf.der)).kind, 'ed25519');
  const pss = caFixture({ keyType: 'rsa', leaf: { pss: true } });
  const plan = resolveSignatureScheme(parseCertificate(pss.leaf.der));
  assert.equal(plan.kind, 'rsa-pss');
  assert.equal(plan.hash, 'SHA-256');

  const fake = { subject: { text: 'fake' }, signatureAlgorithm: { oid: '1.2.3.4.5', paramsTlv: null } };
  const e = await rejectsWithCode(async () => resolveSignatureScheme(fake),
    codes.CERT_SIGNATURE_UNSUPPORTED, /1\.2\.3\.4\.5/);
  assert.equal(e.code, codes.CERT_SIGNATURE_UNSUPPORTED);
});

test('RSA-PSS parameters are checked for internal consistency, not assumed', async () => {
  const pssCert = (params) => ({
    subject: { text: 'pss-test' },
    signatureAlgorithm: { oid: OID.rsassaPss, paramsTlv: {}, paramsBytes: params },
  });
  // absent parameters mean SHA-1 defaults -> weak
  await rejectsWithCode(
    async () => resolveSignatureScheme({ subject: { text: 'd' }, signatureAlgorithm: { oid: OID.rsassaPss, paramsTlv: null } }),
    codes.CERT_SIGNATURE_WEAK, /SHA-1/);
  // MGF1 hash disagreeing with the message hash
  await rejectsWithCode(async () => resolveSignatureScheme(pssCert(pssParams('sha256', 32, 'sha384'))),
    codes.CERT_SIGNATURE_UNSUPPORTED, /MGF1 hash/);
  // salt length != hash length
  await rejectsWithCode(async () => resolveSignatureScheme(pssCert(pssParams('sha256', 20))),
    codes.CERT_SIGNATURE_UNSUPPORTED, /salt length 20/);
  // consistent SHA-384 parameters resolve
  const plan = resolveSignatureScheme(pssCert(pssParams('sha384')));
  assert.equal(plan.hash, 'SHA-384');
});

// ------------------------------------------------------------------ PEM

test('decodePem extracts every block and round-trips DER', async () => {
  const pem = toPem(fx.root.der) + '\n' + toPem(fx.intermediate.der);
  const ders = decodePem(pem);
  assert.equal(ders.length, 2);
  assert.ok(equal(ders[0], fx.root.der));
  assert.ok(equal(ders[1], fx.intermediate.der));
  await rejectsWithCode(async () => decodePem('no certs here'), codes.CERT_PARSE, /no CERTIFICATE blocks/);
});
