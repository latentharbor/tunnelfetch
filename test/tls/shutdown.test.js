// Shutdown must terminate even when the peer has stopped reading.
//
// A close_notify or fatal alert is a courtesy: once the transport's write buffer fills against a
// peer that is not reading, the write can never complete. Awaiting it without a bound hangs
// close() on the ordinary path and abort() on the failure path — and on the failure path it also
// swallows the error the caller was about to receive, so a diagnosable failure becomes a request
// that simply never returns. These tests pin the bound.

import test from 'node:test';
import assert from 'node:assert/strict';
import { RecordLayer } from '../../src/tls/record.js';
import { ALERT_LEVEL } from '../../src/tls/constants.js';
import { readableFrom } from '../_harness.js';
import { utf8 } from '../../src/util/bytes.js';

/** A transport whose writes never settle: exactly a peer that stopped reading. */
function stalledTransport() {
  const attempted = [];
  return {
    attempted,
    readable: readableFrom([]),
    writable: new WritableStream({
      write(chunk) {
        attempted.push(chunk);
        return new Promise(() => {});
      },
      close() {
        return new Promise(() => {});
      },
    }),
  };
}

/** A transport that accepts writes immediately, for the fast path. */
function liveTransport() {
  const written = [];
  return {
    written,
    readable: readableFrom([]),
    writable: new WritableStream({
      write(chunk) {
        written.push(chunk);
      },
    }),
  };
}

test('close() returns when the peer has stopped reading', async () => {
  const t = stalledTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 30 });
  // No timeout wrapper here on purpose: if the bound is missing, this test hangs and the runner
  // reports it, which is exactly the signal we want.
  await record.close();
  assert.equal(t.attempted.length, 1, 'the close_notify was attempted before being abandoned');
});

test('abort() returns when the peer has stopped reading', async () => {
  const t = stalledTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 30 });
  await record.abort(40);
  assert.equal(t.attempted.length, 1);
});

test('an abort on a stalled transport does not swallow the error being reported', async () => {
  // The shape the failure path actually takes: a driver catching an error, telling the peer, and
  // rethrowing. If abort() blocks, the original error never surfaces.
  const t = stalledTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 30 });
  const original = new Error('certificate chain rejected');
  const surfaced = await (async () => {
    try {
      throw original;
    } catch (err) {
      try {
        await record.abort();
      } catch {
        /* best effort */
      }
      return err;
    }
  })();
  assert.equal(surfaced, original);
});

test('a live transport still gets a real close_notify, and quickly', async () => {
  const t = liveTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 5000 });
  await record.close();
  assert.equal(t.written.length, 1, 'exactly one record: the close_notify');
  const rec = t.written[0];
  assert.equal(rec[0], 21, 'record type alert');
  // 5-byte header, then level + description.
  assert.equal(rec[5], ALERT_LEVEL.warning);
  assert.equal(rec[6], 0, 'close_notify is description 0');
  // The grace is generous here; a live peer must not wait any of it.
});

test('abort sends a fatal alert naming the description', async () => {
  const t = liveTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 5000 });
  await record.abort(48); // unknown_ca
  const rec = t.written[0];
  assert.equal(rec[0], 21);
  assert.equal(rec[5], ALERT_LEVEL.fatal);
  assert.equal(rec[6], 48);
});

test('shutdown is idempotent and sends the alert only once', async () => {
  const t = liveTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 5000 });
  await record.close();
  await record.close();
  await record.abort();
  assert.equal(t.written.length, 1, 'a second shutdown must not put another alert on the wire');
});

test('writing after shutdown is refused rather than silently dropped', async () => {
  const t = liveTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 5000 });
  await record.close();
  await assert.rejects(() => record.writeHandshake(utf8('x')), (e) => e.code === 'CONFIG_INVALID');
});

test('a grace of zero abandons the courtesy immediately without an unhandled rejection', async () => {
  const t = stalledTransport();
  const record = new RecordLayer(t, { shutdownGraceMs: 0 });
  await record.close();
  // Give any abandoned promise a turn to reject; an unhandled rejection would fail the run.
  await new Promise((r) => setTimeout(r, 10));
});
