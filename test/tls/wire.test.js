// Wire primitives and extension codecs. Everything here is pure bytes in, bytes out, so it is
// asserted against fixed vectors rather than round-trips alone — a round-trip test passes happily
// when both sides share the same misreading of the spec.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Builder, Cursor, vector, handshakeMessage } from '../../src/tls/wire.js';
import {
  encodeServerName,
  encodeSupportedVersions,
  encodeSupportedGroups,
  encodeSignatureAlgorithms,
  encodeKeyShare,
  encodeKeyShareHrr,
  encodeAlpn,
  encodePskKeyExchangeModes,
  encodeExtendedMasterSecret,
  encodeRenegotiationInfo,
  encodeEcPointFormats,
  encodeExtensionBlock,
  decodeExtensionBlock,
  rejectUnofferedExtensions,
  decodeSelectedVersion,
  decodeKeyShareEntry,
  decodeKeyShareHrr,
  decodeAlpn,
  requireSupportedGroup,
  isIpLiteral,
} from '../../src/tls/extensions.js';
import { EXTENSION, GROUP, TLS13, TLS12, SIG_SCHEME } from '../../src/tls/constants.js';
import { toHex, fromHex, utf8 } from '../../src/util/bytes.js';
import { rejectsWithCode } from '../_harness.js';

const throwsCode = (fn, code) => {
  let err;
  try {
    fn();
  } catch (e) {
    err = e;
  }
  assert.ok(err, `expected a throw with code ${code}`);
  assert.equal(err.code, code, `expected ${code}, got ${err.code}: ${err?.message}`);
  return err;
};

// ------------------------------------------------------------------ Cursor

test('Cursor reads big-endian integers and advances', () => {
  const c = new Cursor(fromHex('01' + '0203' + '040506' + '0708090a'));
  assert.equal(c.u8(), 0x01);
  assert.equal(c.u16(), 0x0203);
  assert.equal(c.u24(), 0x040506);
  assert.equal(c.u32(), 0x0708090a);
  assert.equal(c.done, true);
});

test('Cursor refuses to read past its bound and says what it was reading', () => {
  const c = new Cursor(fromHex('0102'), 'ServerHello');
  c.u8();
  const err = throwsCode(() => c.u16('cipher_suite'), 'TLS_HANDSHAKE');
  assert.match(err.message, /ServerHello/);
  assert.match(err.message, /cipher_suite/);
  assert.match(err.message, /needed 2 bytes/);
  assert.match(err.message, /only 1 remain/);
});

test('Cursor.vector honours 1, 2 and 3 byte length prefixes', () => {
  assert.equal(toHex(new Cursor(fromHex('02aabb')).vector(1)), 'aabb');
  assert.equal(toHex(new Cursor(fromHex('0002aabb')).vector(2)), 'aabb');
  assert.equal(toHex(new Cursor(fromHex('000002aabb')).vector(3)), 'aabb');
});

test('a vector length longer than the enclosing buffer is rejected, not clamped', () => {
  throwsCode(() => new Cursor(fromHex('00ffaabb'), 'ext').vector(2, 'body'), 'TLS_HANDSHAKE');
});

test('Cursor.sub bounds nested structures to the parent vector', () => {
  // outer 2-byte vector of 4 bytes, containing a 1-byte vector of 2 bytes, then 1 spare byte
  const c = new Cursor(fromHex('0004' + '02aabb' + 'cc'), 'outer');
  const inner = c.sub(2, 'list');
  assert.equal(toHex(inner.vector(1, 'item')), 'aabb');
  assert.equal(inner.remaining, 1);
  throwsCode(() => inner.end('list'), 'TLS_HANDSHAKE');
});

test('Cursor.end reports trailing bytes rather than ignoring them', () => {
  const c = new Cursor(fromHex('0102'), 'thing');
  c.u8();
  const err = throwsCode(() => c.end('body'), 'TLS_HANDSHAKE');
  assert.match(err.message, /1 trailing bytes/);
});

test('take(0) and empty vectors are legal', () => {
  const c = new Cursor(fromHex('00'), 'x');
  assert.equal(c.vector(1).byteLength, 0);
  assert.equal(c.done, true);
});

// ------------------------------------------------------------------ Builder

test('Builder writes a length prefix that always matches the body', () => {
  const b = new Builder().u8(0x16).vector(2, fromHex('aabbcc'));
  assert.equal(toHex(b.build()), '16' + '0003' + 'aabbcc');
});

test('Builder rejects a body that cannot fit its length prefix', () => {
  const big = new Uint8Array(256);
  const err = throwsCode(() => new Builder().vector(1, big), 'TLS_HANDSHAKE');
  assert.match(err.message, /256 bytes does not fit in a 1-byte length prefix/);
});

test('handshakeMessage frames type and 24-bit length', () => {
  assert.equal(toHex(handshakeMessage(0x01, fromHex('ff'))), '01' + '000001' + 'ff');
  assert.equal(toHex(handshakeMessage(0x14, new Uint8Array(0))), '14' + '000000');
});

test('vector() standalone matches Builder.vector', () => {
  assert.equal(toHex(vector(2, fromHex('01'))), '000101');
});

// ------------------------------------------------------------------ extension encoders (fixed vectors)

test('server_name encodes the RFC 6066 nested structure exactly', () => {
  // ext type 0000, ext len 0010, list len 000e, name type 00, name len 000b, "example.com"
  const got = toHex(encodeServerName('example.com'));
  assert.equal(got, '0000' + '0010' + '000e' + '00' + '000b' + toHex(utf8('example.com')));
});

test('server_name is omitted for IP literals, as RFC 6066 requires', () => {
  assert.equal(encodeServerName('192.0.2.1'), null);
  assert.equal(encodeServerName('2001:db8::1'), null);
  assert.notEqual(encodeServerName('host.example'), null);
});

test('supported_versions offers 1.3 then 1.2 in a 1-byte-prefixed list', () => {
  assert.equal(toHex(encodeSupportedVersions([TLS13, TLS12])), '002b' + '0005' + '04' + '0304' + '0303');
});

test('supported_groups puts x25519 first', () => {
  const hex = toHex(encodeSupportedGroups());
  assert.equal(hex.slice(0, 4), '000a');
  // after ext type(2) + ext len(2) + list len(2) the first group is x25519 = 001d
  assert.equal(hex.slice(12, 16), '001d');
});

test('signature_algorithms never offers a SHA-1 scheme', () => {
  const hex = toHex(encodeSignatureAlgorithms());
  assert.ok(!hex.includes('0201'), 'rsa_pkcs1_sha1 must not be offered');
  assert.ok(!hex.includes('0203'), 'ecdsa_sha1 must not be offered');
  assert.ok(hex.includes('0804'), 'rsa_pss_rsae_sha256 must be offered');
});

test('key_share encodes group and key with a 2-byte key length', () => {
  const key = new Uint8Array(32).fill(0xab);
  const got = toHex(encodeKeyShare([{ group: GROUP.x25519, keyExchange: key }]));
  assert.equal(got, '0033' + '0026' + '0024' + '001d' + '0020' + 'ab'.repeat(32));
});

test('the HelloRetryRequest key_share is a bare group id', () => {
  assert.equal(toHex(encodeKeyShareHrr(GROUP.secp256r1)), '0033' + '0002' + '0017');
});

test('alpn offers exactly what it is given', () => {
  assert.equal(toHex(encodeAlpn(['http/1.1'])), '0010' + '000b' + '0009' + '08' + toHex(utf8('http/1.1')));
});

test('the compatibility extensions have their fixed encodings', () => {
  assert.equal(toHex(encodePskKeyExchangeModes()), '002d' + '0002' + '01' + '01');
  assert.equal(toHex(encodeExtendedMasterSecret()), '0017' + '0000');
  assert.equal(toHex(encodeRenegotiationInfo()), 'ff01' + '0001' + '00');
  assert.equal(toHex(encodeEcPointFormats()), '000b' + '0002' + '01' + '00');
});

test('encodeExtensionBlock skips nulls so an omitted SNI leaves no gap', () => {
  const block = encodeExtensionBlock([null, encodeExtendedMasterSecret(), null]);
  assert.equal(toHex(block), '0004' + '0017' + '0000');
});

// ------------------------------------------------------------------ extension decoding

test('decodeExtensionBlock returns every extension keyed by type', () => {
  const block = encodeExtensionBlock([encodeExtendedMasterSecret(), encodeRenegotiationInfo()]);
  // strip the outer 2-byte length that the block itself carries
  const map = decodeExtensionBlock(block.subarray(2), 'ServerHello');
  assert.deepEqual([...map.keys()], [EXTENSION.extended_master_secret, EXTENSION.renegotiation_info]);
  assert.equal(map.get(EXTENSION.extended_master_secret).byteLength, 0);
});

test('a duplicated extension is rejected rather than last-one-wins', () => {
  const dup = fromHex('0017' + '0000' + '0017' + '0000');
  const err = throwsCode(() => decodeExtensionBlock(dup, 'ServerHello'), 'TLS_HANDSHAKE');
  assert.match(err.message, /0x0017 twice/);
});

test('a truncated extension body is rejected', () => {
  throwsCode(() => decodeExtensionBlock(fromHex('0017' + '0004' + '0102'), 'ServerHello'), 'TLS_HANDSHAKE');
});

test('an extension the client never offered is a protocol violation', () => {
  const received = new Map([[EXTENSION.early_data, new Uint8Array(0)]]);
  const offered = new Set([EXTENSION.server_name, EXTENSION.key_share]);
  const err = throwsCode(
    () => rejectUnofferedExtensions(received, offered, 'EncryptedExtensions'),
    'TLS_EXTENSION_UNSUPPORTED',
  );
  assert.match(err.message, /0x002a/);
  assert.match(err.message, /not offered/);
});

test('decodeSelectedVersion reads one version and rejects a list', () => {
  assert.equal(decodeSelectedVersion(fromHex('0304')), TLS13);
  throwsCode(() => decodeSelectedVersion(fromHex('03040303')), 'TLS_HANDSHAKE');
});

test('decodeKeyShareEntry round-trips an encoded share', () => {
  const key = new Uint8Array(32).fill(7);
  const encoded = encodeKeyShare([{ group: GROUP.x25519, keyExchange: key }]);
  // skip ext type(2), ext len(2), client-side list len(2) to get at the single entry
  const entry = decodeKeyShareEntry(encoded.subarray(6), 'ServerHello');
  assert.equal(entry.group, GROUP.x25519);
  assert.equal(toHex(entry.keyExchange), toHex(key));
});

test('decodeKeyShareHrr reads a bare group', () => {
  assert.equal(decodeKeyShareHrr(fromHex('0017')), GROUP.secp256r1);
  throwsCode(() => decodeKeyShareHrr(fromHex('001700')), 'TLS_HANDSHAKE');
});

test('decodeAlpn accepts exactly one protocol and rejects two', () => {
  // list length is 9: the 1-byte name length plus the 8-byte name
  assert.equal(decodeAlpn(fromHex('0009' + '08' + toHex(utf8('http/1.1')))), 'http/1.1');
  const two = fromHex('0006' + '02' + toHex(utf8('h2')) + '02' + toHex(utf8('h3')));
  throwsCode(() => decodeAlpn(two), 'TLS_HANDSHAKE');
});

// ------------------------------------------------------------------ negotiation guards

test('an unimplemented group produces an actionable error naming the value', () => {
  const err = throwsCode(() => requireSupportedGroup(GROUP.x448, 'ServerHello'), 'TLS_GROUP_UNSUPPORTED');
  assert.match(err.message, /0x001e/);
  assert.match(err.message, /x448/);
  assert.match(err.message, /not implemented/);
  assert.match(err.message, /offered/);
  assert.equal(err.detail.group, GROUP.x448);
});

test('a wholly unknown group still yields a hex code rather than undefined', () => {
  const err = throwsCode(() => requireSupportedGroup(0x9999, 'ServerHello'), 'TLS_GROUP_UNSUPPORTED');
  assert.match(err.message, /0x9999/);
  assert.match(err.message, /unknown/);
});

test('supported groups all resolve to WebCrypto parameters', () => {
  for (const g of [GROUP.x25519, GROUP.secp256r1, GROUP.secp384r1, GROUP.secp521r1]) {
    const p = requireSupportedGroup(g, 'test');
    assert.ok(p.algorithm.name);
    assert.ok(p.publicLen > 0);
  }
});

test('isIpLiteral distinguishes hostnames from addresses', () => {
  assert.equal(isIpLiteral('192.0.2.1'), true);
  assert.equal(isIpLiteral('2001:db8::1'), true);
  assert.equal(isIpLiteral('::1'), true);
  assert.equal(isIpLiteral('example.com'), false);
  assert.equal(isIpLiteral('1234.example'), false);
  assert.equal(isIpLiteral('999.999.999.999'), true); // syntactically an IPv4 literal; not our job to validate
});

test('signature scheme table has no gaps for what we offer', async () => {
  const { SUPPORTED_SIG_SCHEMES, SIG_SCHEME_PARAMS } = await import('../../src/tls/constants.js');
  for (const s of SUPPORTED_SIG_SCHEMES) {
    assert.ok(SIG_SCHEME_PARAMS[s], `offered scheme ${s.toString(16)} has no verify parameters`);
  }
  assert.ok(!SUPPORTED_SIG_SCHEMES.includes(SIG_SCHEME.rsa_pkcs1_sha1));
});

test('rejectsWithCode helper works on async extension paths', async () => {
  await rejectsWithCode(async () => {
    decodeExtensionBlock(fromHex('0017'), 'ServerHello');
  }, 'TLS_HANDSHAKE');
});
