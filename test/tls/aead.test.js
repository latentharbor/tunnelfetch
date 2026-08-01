// AEAD record protection. The strongest tests here are byte-for-byte replays of RFC 8448
// section 3: AES-GCM is deterministic given (key, nonce, aad, plaintext), so our encrypt()
// must reproduce the exact ciphertext records of the published trace, and decrypt() must
// open them. That pins key derivation, nonce construction, inner-plaintext framing, and AAD
// in one stroke — a mistake in any of them cannot produce the same bytes.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAead, buildNonce } from '../../src/tls/aead.js';
import { CIPHER, MAX_PLAINTEXT, TLS12, TLS13 } from '../../src/tls/constants.js';
import { concat, fromHex, latin1, toHex, u8, u16, utf8 } from '../../src/util/bytes.js';
import { codes } from '../../src/errors.js';
import { rejectsWithCode } from '../_harness.js';
import { RFC8448_1RTT as V } from './_vectors.js';

const AES128 = CIPHER.TLS_AES_128_GCM_SHA256;
const GCM12 = CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);
const header = (rec) => rec.subarray(0, 5);
const body = (rec) => rec.subarray(5);

// ---------------------------------------------------------------- nonce construction

test('nonce at seq 0 is the static IV itself (RFC 8446 s5.3)', () => {
  const iv = fromHex('5d313eb2671276ee13000b30');
  eq(buildNonce(iv, 0), iv);
  eq(buildNonce(iv, 0n), iv);
});

test('nonce XORs the big-endian sequence number into the low 8 bytes', () => {
  const iv = fromHex('000000000000000000000000');
  eq(buildNonce(iv, 1), fromHex('000000000000000000000001'));
  eq(buildNonce(iv, 0x0102030405n), fromHex('000000000000000102030405'));
  // past 32 bits — the overflow zone where a Number-typed counter would go wrong
  eq(buildNonce(iv, (1n << 32n) + 5n), fromHex('000000000000000100000005'));
  eq(buildNonce(iv, (1n << 56n) | 0xffn), fromHex('0000000001000000000000ff'));
});

test('nonce XOR is an involution against a nonzero IV', () => {
  const iv = fromHex('0f1e2d3c4b5a69788796a5b4');
  const n = buildNonce(iv, 0x1122334455667788n);
  eq(buildNonce(n, 0x1122334455667788n), iv);
});

test('sequence numbers refuse to reach 2^64-1', async () => {
  const iv = new Uint8Array(12);
  buildNonce(iv, (1n << 64n) - 2n); // last usable value is fine
  await rejectsWithCode(async () => buildNonce(iv, (1n << 64n) - 1n), codes.TLS_RECORD, /rekey/);
  await rejectsWithCode(async () => buildNonce(iv, 1n << 64n), codes.TLS_RECORD);
  await rejectsWithCode(async () => buildNonce(iv, -1n), codes.CONFIG_INVALID);
});

test('encrypt and decrypt refuse the wrapped sequence number too', async () => {
  const a = await createAead({ cipher: AES128, key: new Uint8Array(16), iv: new Uint8Array(12) });
  const max = (1n << 64n) - 1n;
  await rejectsWithCode(() => a.encrypt(max, 23, utf8('x')), codes.TLS_RECORD, /rekey/);
  await rejectsWithCode(() => a.decrypt(max, new Uint8Array(17), new Uint8Array(5)),
    codes.TLS_RECORD, /rekey/);
});

// ---------------------------------------------------------------- RFC 8448 decrypt replays

const CASES = [
  ['server handshake flight (EE+Cert+CV+Fin), seq 0',
    () => [V.serverHsKey, V.serverHsIv, 0n, V.serverFlightRecord, 22, V.serverFlightPlaintext]],
  ['client Finished, seq 0',
    () => [V.clientHsKey, V.clientHsIv, 0n, V.clientFinishedRecord, 22, V.clientFinished]],
  ['NewSessionTicket under server app keys, seq 0',
    () => [V.serverApKey, V.serverApIv, 0n, V.newSessionTicketRecord, 22, V.newSessionTicket]],
  ['server application data, seq 1',
    () => [V.serverApKey, V.serverApIv, 1n, V.serverAppDataRecord, 23, V.appDataPlaintext]],
  ['server close_notify, seq 2',
    () => [V.serverApKey, V.serverApIv, 2n, V.serverCloseNotifyRecord, 21, fromHex('0100')]],
  ['client application data, seq 0',
    () => [V.clientApKey, V.clientApIv, 0n, V.clientAppDataRecord, 23, V.appDataPlaintext]],
  ['client close_notify, seq 1',
    () => [V.clientApKey, V.clientApIv, 1n, V.clientCloseNotifyRecord, 21, fromHex('0100')]],
];

for (const [name, make] of CASES) {
  test(`RFC 8448 decrypt: ${name}`, async () => {
    const [key, iv, seq, record, wantType, wantPlain] = make();
    const aead = await createAead({ cipher: AES128, key, iv });
    const { type, plaintext } = await aead.decrypt(seq, body(record), header(record));
    assert.equal(type, wantType);
    eq(plaintext, wantPlain);
  });
  test(`RFC 8448 encrypt reproduces the trace bytes: ${name}`, async () => {
    const [key, iv, seq, record, type, plain] = make();
    const aead = await createAead({ cipher: AES128, key, iv });
    const out = await aead.encrypt(seq, type, plain);
    eq(concat([u8(23), u16(0x0303), u16(out.byteLength), out]), record);
  });
}

test('decrypting with the wrong sequence number fails closed', async () => {
  const aead = await createAead({ cipher: AES128, key: V.serverApKey, iv: V.serverApIv });
  await rejectsWithCode(
    () => aead.decrypt(0n, body(V.serverAppDataRecord), header(V.serverAppDataRecord)),
    codes.TLS_RECORD);
});

test('a flipped ciphertext byte (tag or body) fails closed', async () => {
  const aead = await createAead({ cipher: AES128, key: V.clientApKey, iv: V.clientApIv });
  for (const at of [0, 20, V.clientAppDataRecord.byteLength - 6]) {
    const rec = V.clientAppDataRecord.slice();
    rec[5 + at] ^= 0x01;
    await rejectsWithCode(() => aead.decrypt(0n, body(rec), header(rec)), codes.TLS_RECORD,
      /authentication failed/);
  }
});

test('a flipped header byte breaks the AAD binding', async () => {
  const aead = await createAead({ cipher: AES128, key: V.clientApKey, iv: V.clientApIv });
  const rec = V.clientAppDataRecord.slice();
  rec[1] = 0x02; // legacy_version 0x0203: not what the sender authenticated
  await rejectsWithCode(() => aead.decrypt(0n, body(rec), header(rec)), codes.TLS_RECORD);
});

// ---------------------------------------------------------------- inner plaintext handling

const freshAead = () => createAead({
  cipher: AES128, key: fromHex('000102030405060708090a0b0c0d0e0f'),
  iv: fromHex('a0a1a2a3a4a5a6a7a8a9aaab'),
});

test('padding: encrypt appends zeros, decrypt strips them and finds the type', async () => {
  const aead = await freshAead();
  const msg = utf8('padded payload');
  const out = await aead.encrypt(5n, 23, msg, { padding: 40 });
  assert.equal(out.byteLength, msg.byteLength + 1 + 40 + 16, 'ciphertext reflects the padding');
  const hdr = concat([u8(23), u16(0x0303), u16(out.byteLength)]);
  const { type, plaintext } = await aead.decrypt(5n, out, hdr);
  assert.equal(type, 23);
  eq(plaintext, msg);
});

test('a hand-built padded inner plaintext round-trips', async () => {
  // Not via our own encrypt: encrypt the inner struct directly with WebCrypto so decrypt is
  // tested against an independently framed record.
  const key = fromHex('101112131415161718191a1b1c1d1e1f');
  const iv = fromHex('202122232425262728292a2b');
  const gcm = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const content = utf8('alert');
  const inner = concat([content, u8(21), new Uint8Array(9)]); // type alert + 9 pad zeros
  const hdr = concat([u8(23), u16(0x0303), u16(inner.byteLength + 16)]);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: buildNonce(iv, 3), additionalData: hdr }, gcm, inner));
  const aead = await createAead({ cipher: AES128, key, iv });
  const { type, plaintext } = await aead.decrypt(3n, ct, hdr);
  assert.equal(type, 21);
  eq(plaintext, content);
});

test('an all-zero inner plaintext (no content type) is rejected', async () => {
  const aead = await freshAead();
  // encrypt() lets us build one: type byte 0x00 plus zero padding is indistinguishable from
  // padding-only, which is exactly the malformed record RFC 8446 s5.4 says to reject.
  const out = await aead.encrypt(0n, 0, new Uint8Array(0), { padding: 11 });
  const hdr = concat([u8(23), u16(0x0303), u16(out.byteLength)]);
  await rejectsWithCode(() => aead.decrypt(0n, out, hdr), codes.TLS_RECORD, /no content type/);
});

test('zero-length content with a real type survives the padding strip', async () => {
  const aead = await freshAead();
  const out = await aead.encrypt(0n, 23, new Uint8Array(0));
  const hdr = concat([u8(23), u16(0x0303), u16(out.byteLength)]);
  const { type, plaintext } = await aead.decrypt(0n, out, hdr);
  assert.equal(type, 23);
  assert.equal(plaintext.byteLength, 0);
});

test('padding is clamped so the inner plaintext cannot exceed 2^14+1', async () => {
  const aead = await freshAead();
  const msg = new Uint8Array(MAX_PLAINTEXT - 4);
  const out = await aead.encrypt(0n, 23, msg, { padding: 1 << 20 });
  assert.equal(out.byteLength, MAX_PLAINTEXT + 1 + 16, 'pad clamped to the 4 free bytes');
});

test('oversized plaintext and short ciphertext are rejected up front', async () => {
  const aead = await freshAead();
  await rejectsWithCode(() => aead.encrypt(0n, 23, new Uint8Array(MAX_PLAINTEXT + 1)),
    codes.CONFIG_INVALID, /fragment/);
  await rejectsWithCode(() => aead.decrypt(0n, new Uint8Array(16), new Uint8Array(5)),
    codes.TLS_RECORD, /shorter than/);
});

test('createAead validates cipher, key length, and IV length', async () => {
  const k16 = new Uint8Array(16);
  const iv12 = new Uint8Array(12);
  // 0x00ff, which is TLS_EMPTY_RENEGOTIATION_INFO_SCSV and never a real suite. This used to be
  // 0x1303, but ChaCha20 has AEAD parameters now — it is refused later, for the specific reason
  // that no implementation was injected, which is a different and more useful error.
  await rejectsWithCode(() => createAead({ cipher: 0x00ff, key: k16, iv: iv12 }),
    codes.TLS_CIPHER_UNSUPPORTED, /0x00ff/);
  await rejectsWithCode(() => createAead({ cipher: AES128, key: new Uint8Array(32), iv: iv12 }),
    codes.CONFIG_INVALID);
  await rejectsWithCode(() => createAead({ cipher: AES128, key: k16, iv: new Uint8Array(4) }),
    codes.CONFIG_INVALID);
  await rejectsWithCode(
    () => createAead({ version: 0x0301, cipher: AES128, key: k16, iv: iv12 }),
    codes.CONFIG_INVALID);
});

test('AES-256-GCM-SHA384 parameters round-trip', async () => {
  const aead = await createAead({
    cipher: CIPHER.TLS_AES_256_GCM_SHA384, key: new Uint8Array(32).fill(1),
    iv: new Uint8Array(12).fill(2),
  });
  const out = await aead.encrypt(7n, 22, utf8('finished'));
  const hdr = concat([u8(23), u16(0x0303), u16(out.byteLength)]);
  const { type, plaintext } = await aead.decrypt(7n, out, hdr);
  assert.equal(type, 22);
  eq(plaintext, utf8('finished'));
});

// ---------------------------------------------------------------- TLS 1.2 (RFC 5288)

const make12 = () => createAead({
  version: TLS12, cipher: GCM12,
  key: fromHex('404142434445464748494a4b4c4d4e4f'), iv: fromHex('50515253'),
});

test('TLS 1.2: explicit 8-byte nonce on the wire, sequence number as AAD', async () => {
  const aead = await make12();
  const msg = utf8('GET / HTTP/1.1');
  const out = await aead.encrypt(9n, 23, msg);
  eq(out.subarray(0, 8), fromHex('0000000000000009'), 'explicit nonce is the sequence number');
  assert.equal(out.byteLength, 8 + msg.byteLength + 16);
  const hdr = concat([u8(23), u16(TLS12), u16(out.byteLength)]);
  const { type, plaintext } = await aead.decrypt(9n, out, hdr);
  assert.equal(type, 23);
  eq(plaintext, msg);
});

test('TLS 1.2: receiver AAD uses its own counter, so a replayed record fails', async () => {
  const aead = await make12();
  const out = await aead.encrypt(0n, 23, utf8('once'));
  const hdr = concat([u8(23), u16(TLS12), u16(out.byteLength)]);
  await aead.decrypt(0n, out, hdr);
  await rejectsWithCode(() => aead.decrypt(1n, out, hdr), codes.TLS_RECORD,
    /authentication failed/);
});

test('TLS 1.2: the outer record type is bound by the AAD', async () => {
  const aead = await make12();
  const out = await aead.encrypt(0n, 22, utf8('finished'));
  const asAppData = concat([u8(23), u16(TLS12), u16(out.byteLength)]);
  await rejectsWithCode(() => aead.decrypt(0n, out, asAppData), codes.TLS_RECORD);
  const asHandshake = concat([u8(22), u16(TLS12), u16(out.byteLength)]);
  const { type } = await aead.decrypt(0n, out, asHandshake);
  assert.equal(type, 22);
});

test('TLS 1.2: a tampered explicit nonce fails authentication', async () => {
  const aead = await make12();
  const out = (await aead.encrypt(4n, 23, utf8('data'))).slice();
  out[7] ^= 0xff;
  const hdr = concat([u8(23), u16(TLS12), u16(out.byteLength)]);
  await rejectsWithCode(() => aead.decrypt(4n, out, hdr), codes.TLS_RECORD);
});

test('TLS 1.2: fixed IV must be 4 bytes and padding is refused', async () => {
  await rejectsWithCode(() => createAead({
    version: TLS12, cipher: GCM12, key: new Uint8Array(16), iv: new Uint8Array(12),
  }), codes.CONFIG_INVALID);
  const aead = await make12();
  await rejectsWithCode(() => aead.encrypt(0n, 23, utf8('x'), { padding: 4 }),
    codes.CONFIG_INVALID, /TLS 1.3/);
});

test('TLS 1.3 static IV is copied, not aliased', async () => {
  const iv = fromHex('a0a1a2a3a4a5a6a7a8a9aaab');
  const key = new Uint8Array(16);
  const aead = await createAead({ cipher: AES128, key, iv });
  const before = await aead.encrypt(0n, 23, utf8('pinned'));
  iv.fill(0); // caller scrubs its buffer; the AEAD must be unaffected
  eq(await aead.encrypt(0n, 23, utf8('pinned')), before);
});

// ChaCha20-Poly1305 is reachable only through an injected implementation. This runtime has no
// WebCrypto ChaCha20 — feature-detected on workerd, where the only native path is node:crypto, and
// taking it would cost the package its "nothing but the web platform" property.
test('ChaCha20-Poly1305 is refused without an implementation, and works with one', async () => {
  const key = new Uint8Array(32).fill(9);
  const iv = new Uint8Array(12).fill(3);
  const CHACHA = 0x1303;

  // The refusal must name the way out. It says "no implementation supplied" rather than "unknown
  // suite", which is the difference between a fixable configuration and an apparent dead end.
  await assert.rejects(
    () => createAead({ cipher: CHACHA, key, iv }),
    (e) => e.code === 'CONFIG_INVALID' && /no implementation was supplied/.test(e.message),
  );

  // A stand-in AEAD: XOR with a keystream byte, then a trivial tag. Not cryptography — the point
  // is that the record layer routes through whatever it is given and round-trips correctly.
  const impl = {
    seal: (k, n, p, aad) => {
      const out = new Uint8Array(p.length + 16);
      for (let i = 0; i < p.length; i++) out[i] = p[i] ^ k[i % 32] ^ n[i % 12];
      for (let i = 0; i < 16; i++) out[p.length + i] = (aad[i % aad.length] + p.length) & 0xff;
      return out;
    },
    open: (k, n, c, aad) => {
      const len = c.length - 16;
      for (let i = 0; i < 16; i++) {
        if (c[len + i] !== ((aad[i % aad.length] + len) & 0xff)) return null; // authentication fails
      }
      const out = new Uint8Array(len);
      for (let i = 0; i < len; i++) out[i] = c[i] ^ k[i % 32] ^ n[i % 12];
      return out;
    },
  };

  const aead = await createAead({ cipher: CHACHA, key, iv, impl });
  const msg = utf8('chacha over the record layer');
  const ct = await aead.encrypt(0n, 23, msg);
  const header = Uint8Array.from([23, 3, 3, ct.length >> 8, ct.length & 0xff]);
  const got = await aead.decrypt(0n, ct, header);
  assert.equal(latin1(got.plaintext), 'chacha over the record layer');
  assert.equal(got.type, 23);

  // `open` returning null must surface as the same authentication failure the AES path throws,
  // not as a null plaintext handed to the caller.
  const tampered = Uint8Array.from(ct);
  tampered[tampered.length - 1] ^= 1;
  await assert.rejects(() => aead.decrypt(0n, tampered, header), (e) => e.code === 'TLS_RECORD');
});

test('the ChaCha20 suite is never offered by default', async () => {
  // Having parameters for it must not put it in the offer. An offer is a claim, and without an
  // injected implementation this package cannot honour it.
  const { TLS13_CIPHERS } = await import('../../src/tls/constants.js');
  assert.ok(!TLS13_CIPHERS.includes(0x1303));
});
