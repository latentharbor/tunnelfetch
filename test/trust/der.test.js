// DER reader: exact ranges on well-formed input, named rejection of every BER-laxness.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rejectsWithCode } from '../_harness.js';
import { codes } from '../../src/errors.js';
import {
  TAG, readTlv, readAll, readSequence, children, content, element,
  readInteger, readOid, readBitString, readBoolean, readUtcTime, readGeneralizedTime,
  readString,
} from '../../src/trust/der.js';

const u8 = (...b) => Uint8Array.of(...b);
const rejects = (fn, re) => rejectsWithCode(async () => fn(), codes.CERT_PARSE, re);

test('readTlv reports exact byte ranges', () => {
  //          0     1     2     3     4     5     6
  const b = u8(0x30, 0x05, 0x02, 0x01, 0x2a, 0x05, 0x00);
  const seq = readTlv(b, 0);
  assert.deepEqual(
    [seq.tag, seq.constructed, seq.start, seq.headerLen, seq.contentStart, seq.contentEnd, seq.end],
    [TAG.SEQUENCE, true, 0, 2, 2, 7, 7],
  );
  const [i, n] = children(b, seq);
  assert.equal(i.tag, TAG.INTEGER);
  assert.deepEqual([i.start, i.contentStart, i.end], [2, 4, 5]);
  assert.equal(n.tag, TAG.NULL);
  assert.deepEqual(Array.from(element(b, i)), [0x02, 0x01, 0x2a]);
  assert.deepEqual(Array.from(content(b, i)), [0x2a]);
});

test('long-form length is accepted where required', () => {
  const body = new Uint8Array(200).fill(0xab);
  const b = new Uint8Array([0x04, 0x81, 200, ...body]);
  const t = readAll(b);
  assert.equal(t.contentEnd - t.contentStart, 200);
});

test('multi-byte tag numbers decode and must be minimal', async () => {
  // context-class primitive tag 128: 0x9f, VLQ 0x81 0x00
  const t = readTlv(u8(0x9f, 0x81, 0x00, 0x01, 0xaa), 0);
  assert.equal(t.tag, 128);
  assert.equal(t.cls, 2);
  await rejects(() => readTlv(u8(0x9f, 0x80, 0x01, 0x00), 0), /non-minimal multi-byte tag/);
  await rejects(() => readTlv(u8(0x9f, 0x81), 0), /truncated multi-byte tag/);
  // tag < 31 spelled in high-tag form
  await rejects(() => readTlv(u8(0x9f, 0x05, 0x00), 0), /high-tag-number form unnecessarily/);
});

test('indefinite length is rejected', async () => {
  await rejects(() => readTlv(u8(0x30, 0x80, 0x00, 0x00), 0), /indefinite length/);
});

test('non-minimal lengths are rejected', async () => {
  // long form where short fits
  await rejects(() => readTlv(u8(0x04, 0x81, 0x05, 1, 2, 3, 4, 5), 0), /non-minimal length/);
  // leading zero length byte
  const big = new Uint8Array([0x04, 0x82, 0x00, 0x81, ...new Uint8Array(129)]);
  await rejects(() => readTlv(big, 0), /leading zero length byte/);
  // reserved 0xff
  await rejects(() => readTlv(u8(0x04, 0xff, 0x00), 0), /reserved length byte/);
  // length-of-length over 4 bytes
  await rejects(() => readTlv(u8(0x04, 0x85, 1, 1, 1, 1, 1), 0), /length of length 5/);
});

test('length past end of buffer is rejected with both numbers', async () => {
  const e = await rejects(() => readTlv(u8(0x30, 0x05, 0x01), 0), /runs past end/);
  assert.match(e.message, /7 > 3/);
});

test('truncated header is rejected', async () => {
  await rejects(() => readTlv(u8(0x30), 0), /length byte expected/);
  await rejects(() => readTlv(u8(), 0), /buffer ends/);
});

test('readAll rejects trailing bytes', async () => {
  const e = await rejects(() => readAll(u8(0x05, 0x00, 0xde, 0xad)), /trailing bytes/);
  assert.match(e.message, /2 trailing/);
});

test('children must exactly fill their container', () => {
  const ok = u8(0x30, 0x04, 0x05, 0x00, 0x05, 0x00);
  assert.equal(children(ok, readTlv(ok, 0)).length, 2);
  // child length runs past the container's content but not the buffer
  const bad = u8(0x30, 0x04, 0x04, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00);
  assert.throws(() => children(bad, readTlv(bad, 0)), /overruns|runs past/);
});

test('readSequence enforces tag and constructedness', async () => {
  await rejects(() => readSequence(u8(0x04, 0x00), 0), /expected SEQUENCE/);
  // primitive tag 16 (impossible in DER for SEQUENCE)
  await rejects(() => readSequence(u8(0x10, 0x00), 0), /constructed/);
});

test('readInteger: values, sign, and minimality', async () => {
  const read = (...b) => {
    const buf = u8(...b);
    return readInteger(buf, readTlv(buf, 0));
  };
  assert.equal(read(0x02, 0x01, 0x2a).value, 42);
  assert.equal(read(0x02, 0x02, 0x00, 0x80).value, 128); // leading zero required here: minimal
  assert.equal(read(0x02, 0x01, 0x00).value, 0);
  const neg = read(0x02, 0x01, 0x80);
  assert.equal(neg.negative, true);
  assert.equal(neg.value, null);
  const wide = read(0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0);
  assert.equal(wide.value, null); // too wide for a safe JS number
  assert.equal(wide.bytes.byteLength, 9);
  await rejects(() => read(0x02, 0x00), /empty/);
  await rejects(() => read(0x02, 0x02, 0x00, 0x7f), /non-minimal/);
  await rejects(() => read(0x02, 0x02, 0xff, 0x80), /non-minimal/);
});

test('readOid: decoding, the 2.x split, and minimality', async () => {
  const read = (...b) => {
    const buf = u8(...b);
    return readOid(buf, readTlv(buf, 0));
  };
  assert.equal(read(0x06, 0x03, 0x2a, 0x86, 0x48), '1.2.840');
  assert.equal(read(0x06, 0x03, 0x55, 0x04, 0x03), '2.5.4.3');
  assert.equal(read(0x06, 0x03, 0x88, 0x37, 0x03), '2.999.3'); // first subidentifier 1079
  await rejects(() => read(0x06, 0x00), /empty/);
  await rejects(() => read(0x06, 0x02, 0x80, 0x01), /non-minimal sub-identifier/);
  await rejects(() => read(0x06, 0x02, 0x2a, 0x81), /truncated sub-identifier/);
});

test('readBitString: unused bits bounded and zero-padded', async () => {
  const read = (...b) => {
    const buf = u8(...b);
    return readBitString(buf, readTlv(buf, 0));
  };
  const ok = read(0x03, 0x02, 0x01, 0x02);
  assert.equal(ok.unusedBits, 1);
  assert.deepEqual(Array.from(ok.bytes), [0x02]);
  await rejects(() => read(0x03, 0x02, 0x08, 0xff), /unused-bits 8 > 7/);
  await rejects(() => read(0x03, 0x02, 0x01, 0x01), /padding bits are not zero/);
  await rejects(() => read(0x03, 0x00), /empty/);
  await rejects(() => read(0x03, 0x01, 0x03), /no payload/);
});

test('readBoolean: only canonical encodings', async () => {
  const read = (...b) => {
    const buf = u8(...b);
    return readBoolean(buf, readTlv(buf, 0));
  };
  assert.equal(read(0x01, 0x01, 0xff), true);
  assert.equal(read(0x01, 0x01, 0x00), false);
  await rejects(() => read(0x01, 0x01, 0x01), /0x00 or 0xff/);
  await rejects(() => read(0x01, 0x02, 0x00, 0x00), /must be 1 byte/);
});

const timeBuf = (tag, s) => {
  const bytes = Uint8Array.from(s, (c) => c.charCodeAt(0));
  return u8(tag, bytes.length, ...bytes);
};
const utc = (s) => {
  const b = timeBuf(0x17, s);
  return readUtcTime(b, readTlv(b, 0));
};
const gen = (s) => {
  const b = timeBuf(0x18, s);
  return readGeneralizedTime(b, readTlv(b, 0));
};

test('UTCTime: pivot at 50, Z required, no fractions', async () => {
  assert.equal(utc('490101000000Z'), Date.UTC(2049, 0, 1));
  assert.equal(utc('500101000000Z'), Date.UTC(1950, 0, 1));
  assert.equal(utc('991231235959Z'), Date.UTC(1999, 11, 31, 23, 59, 59));
  assert.equal(utc('240229120000Z'), Date.UTC(2024, 1, 29, 12)); // leap day
  await rejects(() => utc('990101000000'), /malformed UTCTime/); // missing Z
  await rejects(() => utc('9901010000Z'), /malformed/); // seconds are mandatory
  await rejects(() => utc('990101000000.5Z'), /malformed/); // fractional seconds
  await rejects(() => utc('990101000000+0100'), /malformed/); // zone offsets
  await rejects(() => utc('991301000000Z'), /malformed/); // month 13
  await rejects(() => utc('990230000000Z'), /malformed/); // Feb 30
  await rejects(() => utc('230229000000Z'), /malformed/); // Feb 29 of a non-leap year
  await rejects(() => utc('990101000060Z'), /malformed/); // leap second
});

test('GeneralizedTime: 4-digit year, Z required, no fractions', async () => {
  assert.equal(gen('20500101000000Z'), Date.UTC(2050, 0, 1));
  assert.equal(gen('19700101000000Z'), 0);
  await rejects(() => gen('20500101000000.123Z'), /malformed GeneralizedTime/);
  await rejects(() => gen('20500101000000'), /malformed/);
  await rejects(() => gen('205001010000Z'), /malformed/);
});

const str = (tag, ...bytes) => {
  const b = u8(tag, bytes.length, ...bytes);
  return readString(b, readTlv(b, 0));
};

test('string types enforce their alphabets', async () => {
  assert.equal(str(0x13, 0x41, 0x62, 0x20, 0x2d), 'Ab -'); // PrintableString
  await rejects(() => str(0x13, 0x40), /PrintableString alphabet/); // '@'
  await rejects(() => str(0x13, 0x2a), /PrintableString alphabet/); // '*'
  assert.equal(str(0x16, 0x61, 0x40, 0x62), 'a@b'); // IA5
  await rejects(() => str(0x16, 0xc3), /non-ASCII/);
  assert.equal(str(0x0c, 0xc3, 0xa9), 'é'); // UTF-8
  await rejects(() => str(0x0c, 0xc3), /invalid UTF-8/);
  assert.equal(str(0x14, 0xe9), 'é'); // Teletex read as Latin-1
  assert.equal(str(0x1e, 0x00, 0x41, 0x30, 0x42), 'Aあ'); // BMP UCS-2
  await rejects(() => str(0x1e, 0x00), /odd-length BMPString/);
  await rejects(() => str(0x1e, 0xd8, 0x00), /surrogate/);
  await rejects(() => str(0x04, 0x41), /unsupported string type/);
});
