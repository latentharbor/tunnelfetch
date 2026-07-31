// Identity matching: SAN-only, strict wildcards, raw-byte IP comparison, no IDNA guessing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import { matchesIdentity, parseIp, dnsWithinSubtree, ipWithinSubtree } from '../../src/trust/name.js';
import { parseCertificate } from '../../src/trust/x509.js';
import { makeCert, ip4 } from './_certs.js';

const certWith = (san) => parseCertificate(makeCert({ subject: { CN: 'unit.test' }, san }).der);
const ok = (cert, host) => assert.equal(matchesIdentity(cert, host), undefined);
const mismatch = (cert, host, re) =>
  rejectsWithCode(async () => matchesIdentity(cert, host), codes.CERT_NAME_MISMATCH, re);

test('exact dNSName match, ASCII case-insensitive, trailing dot tolerated', async () => {
  const cert = certWith({ dns: ['server.test'] });
  ok(cert, 'server.test');
  ok(cert, 'SERVER.Test');
  ok(cert, 'server.test.');
  await mismatch(cert, 'other.test', /dNSName entries: server\.test/);
  await mismatch(cert, 'sub.server.test');
  await mismatch(cert, 'erver.test');
  await mismatch(cert, 'server.test.evil.test');
});

test('a certificate with no SAN matches nothing, and says why', async () => {
  // CN says server.test; without a SAN that must count for nothing.
  const cert = parseCertificate(makeCert({ subject: { CN: 'server.test' }, san: null }).der);
  const e = await mismatch(cert, 'server.test', /no subjectAltName/);
  assert.match(e.message, /Common Name is never consulted/);
});

test('wildcard covers exactly one whole leftmost label', async () => {
  const cert = certWith({ dns: ['*.example.test'] });
  ok(cert, 'a.example.test');
  ok(cert, 'WWW.EXAMPLE.TEST');
  await mismatch(cert, 'example.test'); // bare domain: wildcard is not optional
  await mismatch(cert, 'a.b.example.test'); // two labels: the over-match that hurts
  await mismatch(cert, '.example.test'); // empty leftmost label
});

test('degenerate wildcards never match', async () => {
  // '*.test' would cover an entire TLD; 'w*' and mid-name '*' are partial-label forms.
  await mismatch(certWith({ dns: ['*.test'] }), 'a.test');
  await mismatch(certWith({ dns: ['w*.example.test'] }), 'wx.example.test');
  await mismatch(certWith({ dns: ['a.*.example.test'] }), 'a.b.example.test');
  await mismatch(certWith({ dns: ['*'] }), 'test');
  await mismatch(certWith({ dns: ['f*o.example.test'] }), 'foo.example.test');
});

test('non-ASCII query hostnames are refused with an IDNA pointer, not guessed at', async () => {
  const cert = certWith({ dns: ['xn--caf-dma.test'] });
  ok(cert, 'xn--caf-dma.test'); // A-label form works
  const e = await rejectsWithCode(async () => matchesIdentity(cert, 'café.test'),
    codes.CONFIG_INVALID, /IDNA is not implemented/);
  assert.match(e.message, /A-label/);
});

test('NUL and empty hostnames are configuration errors', async () => {
  const cert = certWith({ dns: ['server.test'] });
  await rejectsWithCode(async () => matchesIdentity(cert, 'server.test\0.evil.test'),
    codes.CONFIG_INVALID, /NUL/);
  await rejectsWithCode(async () => matchesIdentity(cert, ''), codes.CONFIG_INVALID, /non-empty/);
  await rejectsWithCode(async () => matchesIdentity(cert, '.'), codes.CONFIG_INVALID, /no labels/);
});

test('IP identities match only iPAddress entries, by raw bytes', async () => {
  const cert = certWith({ dns: ['192.0.2.1'], ip: [ip4('192.0.2.7')] });
  ok(cert, '192.0.2.7');
  // The dNSName spelling "192.0.2.1" must NOT satisfy an IP query.
  await mismatch(cert, '192.0.2.1', /iPAddress entries: 192\.0\.2\.7/);
  await mismatch(cert, '192.0.2.8');
  // And an IP entry never satisfies a DNS query.
  const ipOnly = certWith({ ip: [ip4('192.0.2.7')] });
  await mismatch(ipOnly, 'server.test', /dNSName entries: none/);
});

test('IPv6 identities: compressed, uppercase, and bracketed spellings all match', async () => {
  const v6 = parseIp('2001:db8::1');
  const cert = certWith({ ip: [v6] });
  ok(cert, '2001:db8::1');
  ok(cert, '2001:0DB8:0:0:0:0:0:1');
  ok(cert, '[2001:db8::1]');
  await mismatch(cert, '2001:db8::2');
});

// ------------------------------------------------------------------ IP literal parser

test('parseIp: strict IPv4', () => {
  assert.deepEqual(Array.from(parseIp('192.0.2.1')), [192, 0, 2, 1]);
  assert.deepEqual(Array.from(parseIp('0.0.0.0')), [0, 0, 0, 0]);
  assert.equal(parseIp('256.0.0.1'), null);
  assert.equal(parseIp('01.2.3.4'), null); // leading zero: octal ambiguity
  assert.equal(parseIp('1.2.3'), null);
  assert.equal(parseIp('1.2.3.4.5'), null);
  assert.equal(parseIp('1.2.3.x'), null);
  assert.equal(parseIp('server.test'), null);
});

test('parseIp: IPv6 compression, embedded IPv4, and malformed spellings', () => {
  const hex = (u8) => Buffer.from(u8).toString('hex');
  assert.equal(hex(parseIp('::1')), '00000000000000000000000000000001');
  assert.equal(hex(parseIp('::')), '00000000000000000000000000000000');
  assert.equal(hex(parseIp('2001:db8::8:800:200c:417a')), '20010db80000000000080800200c417a');
  assert.equal(hex(parseIp('1:2:3:4:5:6:7:8')), '00010002000300040005000600070008');
  assert.equal(hex(parseIp('::ffff:192.0.2.1')), '00000000000000000000ffffc0000201');
  assert.equal(hex(parseIp('fe80::')), 'fe800000000000000000000000000000');
  assert.equal(parseIp('1:2:3:4:5:6:7::8'), null); // '::' must absorb at least one group
  assert.equal(parseIp('1::2::3'), null); // two compressions
  assert.equal(parseIp(':::'), null);
  assert.equal(parseIp('1:2:3:4:5:6:7'), null); // seven groups, no compression
  assert.equal(parseIp('1:2:3:4:5:6:7:8:9'), null);
  assert.equal(parseIp('12345::'), null); // five hex digits
  assert.equal(parseIp('fe80::1%eth0'), null); // zone index
  assert.equal(parseIp('1.2.3.4::1'), null); // embedded v4 must be the tail
  assert.equal(parseIp('::1.2.3.999'), null);
});

// ------------------------------------------------------------------ constraint predicates

test('dnsWithinSubtree: label-boundary suffix semantics', () => {
  assert.equal(dnsWithinSubtree('example.com', 'example.com'), true);
  assert.equal(dnsWithinSubtree('a.example.com', 'example.com'), true);
  assert.equal(dnsWithinSubtree('a.b.example.com', 'EXAMPLE.COM'), true);
  assert.equal(dnsWithinSubtree('badexample.com', 'example.com'), false); // not a label boundary
  assert.equal(dnsWithinSubtree('example.com.evil.test', 'example.com'), false);
  assert.equal(dnsWithinSubtree('anything.test', ''), true); // empty constraint covers all DNS
  assert.equal(dnsWithinSubtree('a.example.com', '.example.com'), true); // leading-dot form
  assert.equal(dnsWithinSubtree('example.com', '.example.com'), false); // ...subdomains only
});

test('ipWithinSubtree: masked comparison, family must agree', () => {
  const mask24 = ip4('255.255.255.0');
  assert.equal(ipWithinSubtree(ip4('192.0.2.99'), ip4('192.0.2.0'), mask24), true);
  assert.equal(ipWithinSubtree(ip4('192.0.3.1'), ip4('192.0.2.0'), mask24), false);
  assert.equal(ipWithinSubtree(parseIp('::ffff:c000:0201'), ip4('192.0.2.0'), mask24), false);
  const all = ip4('255.255.255.255');
  assert.equal(ipWithinSubtree(ip4('192.0.2.1'), ip4('192.0.2.1'), all), true);
  assert.equal(ipWithinSubtree(ip4('192.0.2.2'), ip4('192.0.2.1'), all), false);
});
