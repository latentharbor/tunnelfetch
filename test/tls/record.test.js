// Record layer: framing, reassembly, key changes, alerts, KeyUpdate, and the full RFC 8448
// section 3 wire replay in both directions. Every parser path also runs under
// underAllChunkings, because a record layer that needs records to align with transport
// chunks is broken in exactly the way production traffic exposes.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RecordLayer } from '../../src/tls/record.js';
import { createAead } from '../../src/tls/aead.js';
import { trafficKeys, nextTrafficSecret } from '../../src/tls/keyschedule.js';
import { CIPHER, TLS12, MAX_CIPHERTEXT } from '../../src/tls/constants.js';
import { ByteReader, concat, readU16, toHex, u8, u16, u24, utf8 } from '../../src/util/bytes.js';
import { codes } from '../../src/errors.js';
import {
  underAllChunkings, readableFrom, recordingWritable, duplexPair, collect, rejectsWithCode,
} from '../_harness.js';
import { RFC8448_1RTT as V } from './_vectors.js';

const S256 = 'SHA-256';
const AES128 = CIPHER.TLS_AES_128_GCM_SHA256;
const GCM12 = CIPHER.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
const eq = (got, want, what) => assert.equal(toHex(got), toHex(want), what);

// Arbitrary-but-fixed traffic secrets for tests that do not replay the RFC trace. Client
// sends under CS, server under SS.
const CS = V.clientApTraffic;
const SS = V.serverApTraffic;

/** A wire record. */
const record = (type, body, version = 0x0303) =>
  concat([u8(type), u16(version), u16(body.length ?? body.byteLength), Uint8Array.from(body)]);
/** A handshake message with its 4-byte header. */
const hs = (type, body) =>
  concat([u8(type), u24(body.length ?? body.byteLength), Uint8Array.from(body)]);
const pattern = (n) => Uint8Array.from({ length: n }, (_, i) => i & 0xff);

async function aeadFor(secret, cipher = AES128) {
  const { key, iv } = await trafficKeys(S256, secret, 16, 12);
  return createAead({ cipher, key, iv });
}
/** Encrypt a full TLS 1.3 record with an independent AEAD (the "peer" side of a test). */
async function seal(aead, seq, innerType, plaintext, pad = 0) {
  const body = await aead.encrypt(seq, innerType, plaintext, { padding: pad });
  return concat([u8(23), u16(0x0303), u16(body.byteLength), body]);
}

/** Layer under test fed interactively; writes land in a recording sink immediately. */
function interactive(opts) {
  const t = new TransformStream();
  const out = recordingWritable();
  const rl = new RecordLayer({ readable: t.readable, writable: out.stream }, opts);
  const w = t.writable.getWriter();
  return {
    rl,
    out,
    push: (bytes) => {
      const p = w.write(bytes);
      p.catch(() => {});
      return p;
    },
    end: () => w.close().catch(() => {}),
  };
}

/** Layer over a fixed byte sequence. */
function fixed(bytes, opts) {
  const out = recordingWritable();
  const rl = new RecordLayer({ readable: readableFrom([bytes]), writable: out.stream }, opts);
  return { rl, out };
}

/** Read one raw record off a manual peer's ByteReader. */
async function readRec(br) {
  const header = (await br.readExactly(5, 'test record header')).slice();
  const body = (await br.readExactly(readU16(header, 3), 'test record body')).slice();
  return { header, type: header[0], body };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
async function eventually(cond, what) {
  for (let i = 0; i < 1000; i++) {
    if (cond()) return;
    await tick();
  }
  throw new Error(`timed out waiting for ${what}`);
}

// ================================================================ plaintext reassembly

test('reassembly: 3 messages in 1 record, 1 message across 3 records, any chunks', async () => {
  const m1 = hs(1, pattern(40));
  const m2 = hs(2, new Uint8Array(0)); // zero-length body is a legal message
  const m3 = hs(11, pattern(90));
  const big = hs(13, pattern(400));
  const wire = concat([
    record(22, concat([m1, m2, m3])),
    record(22, big.subarray(0, 3)), // splits inside the 4-byte message header
    record(22, big.subarray(3, 250)),
    record(22, big.subarray(250)),
    record(21, [1, 0]), // clean close so the reader loop ends without a truncation error
  ]);
  const seen = await underAllChunkings(wire, async (readable) => {
    const rl = new RecordLayer({ readable, writable: recordingWritable().stream });
    const out = [];
    for (;;) {
      const m = await rl.nextHandshakeMessage();
      if (m === null) break;
      out.push([m.type, toHex(m.raw)]);
    }
    return out;
  });
  assert.deepEqual(seen, [
    [1, toHex(m1)], [2, toHex(m2)], [11, toHex(m3)], [13, toHex(big)],
  ]);
});

test('RFC 8448 receive replay: full server wire image, all chunkings', async () => {
  const wire = concat([
    V.serverHelloRecord, V.serverFlightRecord, V.newSessionTicketRecord,
    V.serverAppDataRecord, V.serverCloseNotifyRecord,
  ]);
  const result = await underAllChunkings(wire, async (readable) => {
    const tickets = [];
    const rl = new RecordLayer(
      { readable, writable: recordingWritable().stream },
      { onPostHandshake: (m) => { tickets.push(toHex(m.raw)); } },
    );
    const events = [];
    const sh = await rl.nextHandshakeMessage();
    events.push(['msg', sh.type, toHex(sh.raw)]);
    await rl.setReceiveKeys({ cipher: AES128, secret: V.serverHsTraffic });
    for (let i = 0; i < 4; i++) {
      const m = await rl.nextHandshakeMessage();
      events.push(['msg', m.type, toHex(m.raw)]);
    }
    await rl.setReceiveKeys({ cipher: AES128, secret: V.serverApTraffic });
    rl.markHandshakeComplete();
    events.push(['data', toHex(await rl.readAppData())]);
    events.push(['eof', await rl.readAppData()]);
    events.push(['after-eof', await rl.readAppData()]); // records after close_notify: ignored
    events.push(['tickets', tickets]);
    return events;
  });
  assert.deepEqual(result, [
    ['msg', 2, toHex(V.serverHello)],
    ['msg', 8, toHex(V.encryptedExtensions)],
    ['msg', 11, toHex(V.certificate)],
    ['msg', 15, toHex(V.certificateVerify)],
    ['msg', 20, toHex(V.serverFinished)],
    ['data', toHex(V.appDataPlaintext)],
    ['eof', null],
    ['after-eof', null],
    ['tickets', [toHex(V.newSessionTicket)]],
  ]);
});

test('RFC 8448 send replay: our wire bytes equal the trace client image exactly', async () => {
  const out = recordingWritable();
  const rl = new RecordLayer({ readable: readableFrom([]), writable: out.stream });
  await rl.writeHandshake(V.clientHello); // first record: legacy version 0x0301
  await rl.setSendKeys({ cipher: AES128, secret: V.clientHsTraffic });
  await rl.writeHandshake(V.clientFinished);
  await rl.setSendKeys({ cipher: AES128, secret: V.clientApTraffic });
  rl.markHandshakeComplete();
  await rl.writeAppData(V.appDataPlaintext);
  await rl.close();
  eq(out.bytes, concat([
    V.clientHelloRecord, V.clientFinishedRecord, V.clientAppDataRecord,
    V.clientCloseNotifyRecord,
  ]));
});

// ================================================================ framing failures

test('record length over the ciphertext limit names the length', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  push(concat([u8(23), u16(0x0303), u16(MAX_CIPHERTEXT + 1)]));
  const err = await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /16641/);
  assert.equal(err.detail.length, 16641);
});

test('plaintext records are capped at 2^14 even before keys', async () => {
  const { rl, push } = interactive();
  push(concat([u8(22), u16(0x0303), u16(16385)]));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /16385.*16384/);
});

test('unknown record types fail closed and name the byte', async () => {
  for (const t of [0x00, 0x18, 0xff]) {
    const { rl } = fixed(record(t, [0]));
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD,
      new RegExp(`0x${t.toString(16).padStart(2, '0')}`));
  }
});

test('truncation: mid-header, mid-body, and EOF without close_notify', async () => {
  {
    const { rl } = fixed(Uint8Array.from([22, 3]));
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_TRUNCATED,
      /mid record header/);
  }
  {
    const { rl } = fixed(concat([u8(22), u16(0x0303), u16(100), pattern(40)]));
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_TRUNCATED, /40 of 100/);
  }
  {
    const { rl } = fixed(record(22, hs(1, pattern(5))));
    const m = await rl.nextHandshakeMessage();
    assert.equal(m.type, 1);
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_TRUNCATED,
      /without close_notify/);
  }
});

test('the first error is sticky', async () => {
  const { rl } = fixed(record(0x55, [1]));
  const first = await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD);
  const again = await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD);
  assert.equal(again, first, 'the very same error object is rethrown');
});

test('zero-length handshake records are rejected', async () => {
  const { rl } = fixed(record(22, []));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /zero-length/);
});

test('a handshake message over the per-message cap is rejected by declared length', async () => {
  const { rl } = fixed(record(22, hs(11, new Uint8Array(0)).map((b, i) => (i === 2 ? 0xff : b))),
    { maxHandshakeMessage: 1024 });
  // header declares 0x00ff00 = 65280 bytes; nothing more need arrive for the cap to fire
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_HANDSHAKE, /65280.*1024/);
});

// ================================================================ change_cipher_spec

test('compat CCS is ignored mid-handshake, with the exact byte 0x01 only', async () => {
  const m = hs(2, pattern(8));
  const { rl } = fixed(concat([record(20, [1]), record(22, m)]));
  const got = await rl.nextHandshakeMessage();
  eq(got.raw, m, 'the message after the ignored CCS comes through');
});

test('CCS with the wrong body fails closed', async () => {
  for (const body of [[2], [1, 1], []]) {
    const { rl } = fixed(record(20, body));
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /change_cipher_spec/);
  }
});

test('CCS after handshake completion fails closed', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  rl.markHandshakeComplete();
  push(record(20, [1]));
  await rejectsWithCode(() => rl.readAppData(), codes.TLS_RECORD, /after handshake completion/);
});

test('a flood of compat CCS records fails closed', async () => {
  const many = [];
  for (let i = 0; i < 9; i++) many.push(record(20, [1]));
  const { rl } = fixed(concat(many));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /change_cipher_spec/);
});

// ================================================================ alerts

test('close_notify mid-handshake is a clean close; later records never surface', async () => {
  const { rl } = fixed(concat([record(21, [1, 0]), record(22, hs(1, pattern(4)))]));
  assert.equal(await rl.nextHandshakeMessage(), null);
  assert.equal(await rl.nextHandshakeMessage(), null, 'record after close_notify is ignored');
});

test('a fatal alert surfaces its NAME, not just the number', async () => {
  const { rl } = fixed(record(21, [2, 40]));
  const err = await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_ALERT,
    /handshake_failure/);
  assert.equal(err.detail.name, 'handshake_failure');
  assert.equal(err.detail.description, 40);
});

test('an unknown alert description still names itself', async () => {
  const { rl } = fixed(record(21, [2, 200]));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_ALERT, /unknown_200/);
});

test('TLS 1.3: warning-level alerts other than user_canceled are still fatal', async () => {
  const { rl } = fixed(record(21, [1, 112])); // warning unrecognized_name: 1.2 leniency only
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_ALERT, /unrecognized_name/);
});

test('user_canceled is ignored until close_notify follows', async () => {
  const { rl } = fixed(concat([record(21, [1, 90]), record(21, [1, 0])]));
  assert.equal(await rl.nextHandshakeMessage(), null);
});

test('a stream of ignorable alerts trips the flood cap', async () => {
  const many = [];
  for (let i = 0; i < 5; i++) many.push(record(21, [1, 90]));
  const { rl } = fixed(concat(many));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /warning alerts/);
});

test('malformed alert record length fails closed', async () => {
  for (const body of [[2], [2, 40, 0]]) {
    const { rl } = fixed(record(21, body));
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /exactly 2/);
  }
});

test('TLS 1.2: warning alerts are ignored, fatal alerts throw by name', async () => {
  const m = hs(2, pattern(6));
  {
    const { rl } = fixed(concat([record(21, [1, 112]), record(22, m)]));
    rl.setVersion(TLS12);
    eq((await rl.nextHandshakeMessage()).raw, m);
  }
  {
    const { rl } = fixed(record(21, [2, 40]));
    rl.setVersion(TLS12);
    await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_ALERT, /handshake_failure/);
  }
});

// ================================================================ key-change guards

test('a plaintext handshake message must not span an installed key change', async () => {
  const { rl, push, end } = interactive();
  const big = hs(1, pattern(500));
  push(record(22, big.subarray(0, 100)));
  const pending = rl.nextHandshakeMessage().catch((e) => e);
  await eventually(() => rl._hsLen > 0, 'partial message buffered');
  await rejectsWithCode(() => rl.setReceiveKeys({ cipher: AES128, secret: SS }),
    codes.TLS_RECORD, /spans a key change/);
  end();
  await pending; // unblocks with a (also failing) truncation, which we do not assert on
});

test('an encrypted handshake message must not span a key change either', async () => {
  const { rl, push, end } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: V.serverHsTraffic });
  const peer = await aeadFor(V.serverHsTraffic);
  const big = hs(8, pattern(300));
  push(await seal(peer, 0n, 22, big.subarray(0, 150)));
  const pending = rl.nextHandshakeMessage().catch((e) => e);
  await eventually(() => rl._hsLen > 0, 'partial message buffered');
  await rejectsWithCode(() => rl.setReceiveKeys({ cipher: AES128, secret: V.serverApTraffic }),
    codes.TLS_RECORD, /spans a key change/);
  end();
  await pending;
});

test('plaintext handshake records after the peer began encrypting fail closed', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  push(record(22, hs(2, pattern(4))));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD,
    /plaintext handshake record after encryption started/);
});

test('AEAD failure surfaces as TLS_RECORD and sends bad_record_mac', async () => {
  const { a, b } = duplexPair();
  const rl = new RecordLayer(a);
  await rl.setSendKeys({ cipher: AES128, secret: CS });
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  const wireP = collect(b.readable);
  const bw = b.writable.getWriter();
  void bw.write(record(23, pattern(40))).catch(() => {}); // not a valid ciphertext
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD,
    /authentication failed/);
  const wire = await wireP; // terminates because the failure path closes our write side
  const peer = await aeadFor(CS);
  const opened = await peer.decrypt(0n, wire.subarray(5), wire.subarray(0, 5));
  assert.equal(opened.type, 21);
  eq(opened.plaintext, Uint8Array.from([2, 20]), 'fatal bad_record_mac');
});

test('a failure with no keys sends the fatal alert in plaintext', async () => {
  const { a, b } = duplexPair();
  const rl = new RecordLayer(a);
  const wireP = collect(b.readable);
  const bw = b.writable.getWriter();
  void bw.write(record(0x18, [0])).catch(() => {});
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD, /0x18/);
  eq(await wireP, record(21, [2, 10]), 'fatal unexpected_message on the wire');
});

// ================================================================ inner content rules

test('forbidden inner content type (protected CCS) fails closed', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  const peer = await aeadFor(SS);
  push(await seal(peer, 0n, 20, Uint8Array.from([1])));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD,
    /forbidden inner content type 0x14/);
});

test('application data during the handshake phase fails closed', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  const peer = await aeadFor(SS);
  push(await seal(peer, 0n, 23, utf8('too early')));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD,
    /application data received during the handshake/);
});

test('empty app-data records are skipped; an endless stream of them is not', async () => {
  {
    const { rl, push } = interactive();
    await rl.setReceiveKeys({ cipher: AES128, secret: SS });
    rl.markHandshakeComplete();
    const peer = await aeadFor(SS);
    for (let i = 0; i < 3; i++) push(await seal(peer, BigInt(i), 23, new Uint8Array(0)));
    push(await seal(peer, 3n, 23, utf8('real')));
    eq(await rl.readAppData(), utf8('real'));
  }
  {
    const { rl, push } = interactive();
    await rl.setReceiveKeys({ cipher: AES128, secret: SS });
    rl.markHandshakeComplete();
    const peer = await aeadFor(SS);
    for (let i = 0; i < 33; i++) push(await seal(peer, BigInt(i), 23, new Uint8Array(0)));
    await rejectsWithCode(() => rl.readAppData(), codes.TLS_RECORD, /empty application_data/);
  }
});

test('padded records from the peer decrypt transparently', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  rl.markHandshakeComplete();
  const peer = await aeadFor(SS);
  push(await seal(peer, 0n, 23, utf8('hidden length'), 200));
  eq(await rl.readAppData(), utf8('hidden length'));
});

// ================================================================ KeyUpdate

test('KeyUpdate(update_requested): rotate receive, answer under old key, rotate send', async () => {
  const { a, b } = duplexPair();
  const A = new RecordLayer(a);
  await A.setSendKeys({ cipher: AES128, secret: CS });
  await A.setReceiveKeys({ cipher: AES128, secret: SS });
  A.markHandshakeComplete();
  const bw = b.writable.getWriter();
  const br = new ByteReader(b.readable);

  // Peer sends KeyUpdate(update_requested) under its current key, then data under the next.
  const sendB0 = await aeadFor(SS);
  void bw.write(await seal(sendB0, 0n, 22, hs(24, [1]))).catch(() => {});
  const ss1 = await nextTrafficSecret(S256, SS);
  const sendB1 = await aeadFor(ss1);
  void bw.write(await seal(sendB1, 0n, 23, utf8('after rotation'))).catch(() => {});

  eq(await A.readAppData(), utf8('after rotation'), 'receive keys rotated in time');

  // Our KeyUpdate response must decrypt under the OLD client secret...
  const rec1 = await readRec(br);
  const recvOld = await aeadFor(CS);
  const opened = await recvOld.decrypt(0n, rec1.body, rec1.header);
  assert.equal(opened.type, 22);
  eq(opened.plaintext, hs(24, [0]), 'update_not_requested response');

  // ...and everything after it must NOT: the send chain rotated. (Write and read
  // concurrently: a zero-buffer pair completes a write only when the peer reads.)
  const freshP = A.writeAppData(utf8('fresh'));
  const rec2 = await readRec(br);
  await freshP;
  await rejectsWithCode(() => recvOld.decrypt(1n, rec2.body, rec2.header), codes.TLS_RECORD,
    undefined, 'old keys must fail after rotation');
  const recvNew = await aeadFor(await nextTrafficSecret(S256, CS));
  const opened2 = await recvNew.decrypt(0n, rec2.body, rec2.header);
  assert.equal(opened2.type, 23);
  eq(opened2.plaintext, utf8('fresh'));
});

test('KeyUpdate(update_not_requested) rotates receive only, no response', async () => {
  const { a, b } = duplexPair();
  const A = new RecordLayer(a);
  await A.setSendKeys({ cipher: AES128, secret: CS });
  await A.setReceiveKeys({ cipher: AES128, secret: SS });
  A.markHandshakeComplete();
  const bw = b.writable.getWriter();
  const sendB0 = await aeadFor(SS);
  void bw.write(await seal(sendB0, 0n, 22, hs(24, [0]))).catch(() => {});
  const sendB1 = await aeadFor(await nextTrafficSecret(S256, SS));
  void bw.write(await seal(sendB1, 0n, 23, utf8('rotated'))).catch(() => {});
  eq(await A.readAppData(), utf8('rotated'));
  // No response record: our next write is the first thing on the wire, still under CS gen 0.
  const oursP = A.writeAppData(utf8('ours'));
  const br = new ByteReader(b.readable);
  const rec = await readRec(br);
  await oursP;
  const recvB = await aeadFor(CS);
  eq((await recvB.decrypt(0n, rec.body, rec.header)).plaintext, utf8('ours'));
});

test('updateKeys() initiated locally rotates our send chain', async () => {
  const { a, b } = duplexPair();
  const A = new RecordLayer(a);
  await A.setSendKeys({ cipher: AES128, secret: CS });
  await A.setReceiveKeys({ cipher: AES128, secret: SS });
  A.markHandshakeComplete();
  // The write chain guarantees the rotation lands between these two even though neither has
  // hit the wire yet when the second is queued.
  const kuP = A.updateKeys();
  const postP = A.writeAppData(utf8('post-update'));
  const br = new ByteReader(b.readable);
  const rec1 = await readRec(br);
  const recvOld = await aeadFor(CS);
  eq((await recvOld.decrypt(0n, rec1.body, rec1.header)).plaintext, hs(24, [0]),
    'KeyUpdate itself under the old key');
  const rec2 = await readRec(br);
  await rejectsWithCode(() => recvOld.decrypt(1n, rec2.body, rec2.header), codes.TLS_RECORD);
  const recvNew = await aeadFor(await nextTrafficSecret(S256, CS));
  eq((await recvNew.decrypt(0n, rec2.body, rec2.header)).plaintext, utf8('post-update'));
  await kuP;
  await postP;
});

test('two record layers survive a requested KeyUpdate in both directions', async () => {
  const { a, b } = duplexPair();
  const A = new RecordLayer(a);
  const B = new RecordLayer(b);
  await A.setSendKeys({ cipher: AES128, secret: CS });
  await A.setReceiveKeys({ cipher: AES128, secret: SS });
  await B.setSendKeys({ cipher: AES128, secret: SS });
  await B.setReceiveKeys({ cipher: AES128, secret: CS });
  A.markHandshakeComplete();
  B.markHandshakeComplete();
  const kuP = A.updateKeys({ requestPeer: true });
  const pingP = A.writeAppData(utf8('ping'));
  eq(await B.readAppData(), utf8('ping'), 'B rotated receive and answered');
  await kuP;
  await pingP;
  const pongP = B.writeAppData(utf8('pong'));
  eq(await A.readAppData(), utf8('pong'), 'A processed the answer and rotated receive');
  await pongP;
});

test('a KeyUpdate flood past the cap fails closed', async () => {
  const { rl, push } = interactive({ maxKeyUpdates: 3 });
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  rl.markHandshakeComplete();
  let secret = SS;
  for (let i = 0; i < 4; i++) {
    const peer = await aeadFor(secret);
    push(await seal(peer, 0n, 22, hs(24, [0]))); // each generation restarts at seq 0
    secret = await nextTrafficSecret(S256, secret);
  }
  await rejectsWithCode(() => rl.readAppData(), codes.TLS_RECORD, /KeyUpdates/);
});

test('malformed KeyUpdate bodies fail closed', async () => {
  for (const body of [[2], [0, 0], []]) {
    const { rl, push } = interactive();
    await rl.setReceiveKeys({ cipher: AES128, secret: SS });
    rl.markHandshakeComplete();
    const peer = await aeadFor(SS);
    push(await seal(peer, 0n, 22, hs(24, body)));
    await rejectsWithCode(() => rl.readAppData(), codes.TLS_HANDSHAKE, /KeyUpdate/);
  }
});

test('KeyUpdate against non-rotatable (raw) receive keys fails closed', async () => {
  const { key, iv } = await trafficKeys(S256, SS, 16, 12);
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, key, iv });
  rl.markHandshakeComplete();
  const peer = await aeadFor(SS);
  push(await seal(peer, 0n, 22, hs(24, [0])));
  await rejectsWithCode(() => rl.readAppData(), codes.TLS_RECORD, /not rotatable/);
});

test('unexpected post-handshake messages fail closed', async () => {
  const { rl, push } = interactive();
  await rl.setReceiveKeys({ cipher: AES128, secret: SS });
  rl.markHandshakeComplete();
  const peer = await aeadFor(SS);
  push(await seal(peer, 0n, 22, hs(11, pattern(8)))); // Certificate, post-handshake
  await rejectsWithCode(() => rl.readAppData(), codes.TLS_HANDSHAKE, /post-handshake/);
});

test('updateKeys() refuses before the handshake completes', async () => {
  const { rl } = interactive();
  await rl.setSendKeys({ cipher: AES128, secret: CS });
  await rejectsWithCode(() => rl.updateKeys(), codes.CONFIG_INVALID);
});

// ================================================================ write side

test('several handshake messages coalesce into one record', async () => {
  const m1 = hs(1, pattern(30));
  const m2 = hs(11, pattern(60));
  const m3 = hs(15, pattern(10));
  const out = recordingWritable();
  const rl = new RecordLayer({ readable: readableFrom([]), writable: out.stream });
  await rl.writeHandshake([m1, m2, m3]);
  eq(out.bytes, record(22, concat([m1, m2, m3]), 0x0301), 'one record, first-flight version');
});

test('plaintext handshake larger than 2^14 fragments and reassembles', async () => {
  const big = hs(11, pattern(20000));
  const out = recordingWritable();
  const rl = new RecordLayer({ readable: readableFrom([]), writable: out.stream });
  await rl.writeHandshake(big);
  assert.equal(out.chunks.length, 2);
  assert.equal(readU16(out.chunks[0], 3), 16384);
  assert.equal(readU16(out.chunks[1], 3), 20004 - 16384);
  const back = new RecordLayer({
    readable: readableFrom([out.bytes]), writable: recordingWritable().stream,
  });
  eq((await back.nextHandshakeMessage()).raw, big);
});

test('encrypted app data fragments at 2^14 and reassembles by sequence', async () => {
  const data = pattern(40000);
  const out = recordingWritable();
  const rl = new RecordLayer({ readable: readableFrom([]), writable: out.stream });
  await rl.setSendKeys({ cipher: AES128, secret: CS });
  rl.markHandshakeComplete();
  await rl.writeAppData(data);
  assert.equal(out.chunks.length, 3);
  const peer = await aeadFor(CS);
  const parts = [];
  for (let i = 0; i < 3; i++) {
    const rec = out.chunks[i];
    const opened = await peer.decrypt(BigInt(i), rec.subarray(5), rec.subarray(0, 5));
    assert.equal(opened.type, 23);
    parts.push(opened.plaintext);
  }
  assert.deepEqual(parts.map((p) => p.byteLength), [16384, 16384, 7232]);
  eq(concat(parts), data);
});

test('the padding policy pads records; default is none', async () => {
  const out = recordingWritable();
  const rl = new RecordLayer(
    { readable: readableFrom([]), writable: out.stream },
    { padding: (type, len) => 13 },
  );
  await rl.setSendKeys({ cipher: AES128, secret: CS });
  rl.markHandshakeComplete();
  await rl.writeAppData(utf8('short'));
  const rec = out.chunks[0];
  assert.equal(readU16(rec, 3), 5 + 1 + 13 + 16, 'record length reflects the padding');
  const peer = await aeadFor(CS);
  eq((await peer.decrypt(0n, rec.subarray(5), rec.subarray(0, 5))).plaintext, utf8('short'));

  const out2 = recordingWritable();
  const rl2 = new RecordLayer({ readable: readableFrom([]), writable: out2.stream });
  await rl2.setSendKeys({ cipher: AES128, secret: CS });
  rl2.markHandshakeComplete();
  await rl2.writeAppData(utf8('short'));
  assert.equal(readU16(out2.chunks[0], 3), 5 + 1 + 16, 'no padding by default');
});

test('abort() sends the named fatal alert and closes', async () => {
  const { a, b } = duplexPair();
  const rl = new RecordLayer(a);
  const wireP = collect(b.readable);
  await rl.abort(40);
  eq(await wireP, record(21, [2, 40]));
  await rejectsWithCode(() => rl.writeHandshake(hs(1, [0])), codes.CONFIG_INVALID,
    /after close_notify or a fatal alert/);
});

test('close() sends close_notify exactly once', async () => {
  const { a, b } = duplexPair();
  const rl = new RecordLayer(a);
  const wireP = collect(b.readable);
  await rl.close();
  await rl.close(); // idempotent
  eq(await wireP, record(21, [1, 0]));
});

test('writeAppData before keys and readAppData before completion are refused', async () => {
  const { rl } = interactive();
  await rejectsWithCode(() => rl.writeAppData(utf8('x')), codes.CONFIG_INVALID);
  await rejectsWithCode(() => rl.readAppData(), codes.CONFIG_INVALID);
});

test('concurrent reads are refused', async () => {
  const { rl, end } = interactive();
  const first = rl.nextHandshakeMessage().catch((e) => e);
  await tick();
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.CONFIG_INVALID, /concurrent/);
  end();
  await first;
});

test('setVersion validates and locks once keys exist', async () => {
  const { rl } = interactive();
  await rejectsWithCode(async () => rl.setVersion(0x0301), codes.TLS_VERSION_UNSUPPORTED,
    /0x0301/);
  await rl.setSendKeys({ cipher: AES128, secret: CS });
  await rejectsWithCode(async () => rl.setVersion(TLS12), codes.CONFIG_INVALID);
});

// ================================================================ full duplex integration

test('plaintextDuplex end to end: echo, fragmentation, KeyUpdate, clean close', async () => {
  const { a, b } = duplexPair();
  const A = new RecordLayer(a);
  const B = new RecordLayer(b);
  await A.setSendKeys({ cipher: AES128, secret: CS });
  await A.setReceiveKeys({ cipher: AES128, secret: SS });
  await B.setSendKeys({ cipher: AES128, secret: SS });
  await B.setReceiveKeys({ cipher: AES128, secret: CS });
  A.markHandshakeComplete();
  B.markHandshakeComplete();

  const echo = (async () => {
    for (;;) {
      const chunk = await B.readAppData();
      if (chunk === null) break;
      await B.writeAppData(chunk);
    }
    await B.close();
  })();

  const ad = A.plaintextDuplex();
  const echoedP = collect(ad.readable);
  const w = ad.writable.getWriter();
  await w.write(utf8('hello '));
  await A.updateKeys({ requestPeer: true }); // rekey mid-stream; the echo must not notice
  const blob = pattern(40000);
  await w.write(blob);
  await w.close();
  const echoed = await echoedP;
  await echo;
  eq(echoed, concat([utf8('hello '), blob]));
});

// ================================================================ TLS 1.2 mode

test('TLS 1.2: CCS surfaces as an event, then encrypted handshake flows', async () => {
  const key = pattern(16);
  const iv = pattern(4);
  const { rl, push } = interactive();
  rl.setVersion(TLS12);
  push(record(20, [1]));
  assert.deepEqual(await rl.nextHandshakeMessage(), { ccs: true });
  await rl.setReceiveKeys({ cipher: GCM12, key, iv });
  const peer = await createAead({ version: TLS12, cipher: GCM12, key, iv });
  const fin = hs(20, pattern(12));
  const body = await peer.encrypt(0n, 22, fin);
  push(concat([u8(22), u16(0x0303), u16(body.byteLength), body]));
  eq((await rl.nextHandshakeMessage()).raw, fin);
});

test('TLS 1.2: a second CCS (renegotiation) fails closed', async () => {
  const key = pattern(16);
  const iv = pattern(4);
  const { rl, push } = interactive();
  rl.setVersion(TLS12);
  push(record(20, [1]));
  await rl.nextHandshakeMessage();
  await rl.setReceiveKeys({ cipher: GCM12, key, iv });
  push(record(20, [1]));
  await rejectsWithCode(() => rl.nextHandshakeMessage(), codes.TLS_RECORD,
    /after keys were installed/);
});

test('TLS 1.2: full duplex with key_block-style raw keys', async () => {
  const { a, b } = duplexPair();
  const A = new RecordLayer(a);
  const B = new RecordLayer(b);
  A.setVersion(TLS12);
  B.setVersion(TLS12);
  const ck = pattern(16);
  const civ = Uint8Array.from([1, 2, 3, 4]);
  const sk = pattern(16).reverse();
  const siv = Uint8Array.from([5, 6, 7, 8]);
  await A.setSendKeys({ cipher: GCM12, key: ck, iv: civ });
  await A.setReceiveKeys({ cipher: GCM12, key: sk, iv: siv });
  await B.setSendKeys({ cipher: GCM12, key: sk, iv: siv });
  await B.setReceiveKeys({ cipher: GCM12, key: ck, iv: civ });
  A.markHandshakeComplete();
  B.markHandshakeComplete();
  const echo = (async () => {
    for (;;) {
      const chunk = await B.readAppData();
      if (chunk === null) break;
      await B.writeAppData(chunk);
    }
    await B.close();
  })();
  const echoedP = collect(A.plaintextDuplex().readable);
  const data = pattern(50000); // several records each way
  await A.writeAppData(data);
  await A.close();
  const echoed = await echoedP;
  await echo;
  eq(echoed, data);
});
