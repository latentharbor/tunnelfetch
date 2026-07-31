// Deadlines are tested against a virtual clock, never a real one. Two reasons: real sleeps make
// the suite slow and flaky, and more importantly the production runtime freezes Date.now() during
// synchronous execution — so a test that passed by wall-clock luck would prove nothing about the
// behaviour that actually matters, which is that timers fire from events and not from clock polls.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DeadlineController,
  withIdleDeadline,
  withDeadline,
  DEFAULT_DEADLINES,
} from '../../src/util/deadline.js';
import { collect, readableFrom } from '../_harness.js';
import { utf8, latin1 } from '../../src/util/bytes.js';

/** A controllable timer environment. Nothing here consults the real clock. */
function fakeTimers() {
  let now = 0;
  let seq = 0;
  const timers = new Map();
  const setTimer = (fn, ms) => {
    const id = ++seq;
    timers.set(id, { at: now + ms, fn });
    return id;
  };
  const clearTimer = (id) => timers.delete(id);
  const advance = async (ms) => {
    const target = now + ms;
    for (;;) {
      let next = null;
      for (const [id, t] of timers) {
        if (t.at <= target && (next === null || t.at < next[1].at)) next = [id, t];
      }
      if (!next) break;
      timers.delete(next[0]);
      now = next[1].at;
      next[1].fn();
      await Promise.resolve();
      await Promise.resolve();
    }
    now = target;
    await Promise.resolve();
  };
  return {
    setTimer,
    clearTimer,
    advance,
    get pending() {
      return timers.size;
    },
  };
}

const settle = () => new Promise((r) => queueMicrotask(r));

test('defaults leave the total ceiling off so long streams are not killed by wall time', () => {
  assert.equal(DEFAULT_DEADLINES.totalMs, 0);
  assert.ok(DEFAULT_DEADLINES.idleMs > 0, 'idle is the control, so it must have a default');
});

test('the connect phase fires TIMEOUT_CONNECT and aborts the signal', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 100 }, env);
  d.beginPhase('connect');
  assert.equal(d.aborted, false);
  await env.advance(99);
  assert.equal(d.aborted, false);
  await env.advance(1);
  assert.equal(d.aborted, true);
  assert.equal(d.error.code, 'TIMEOUT_CONNECT');
  assert.match(d.error.message, /connect deadline of 100ms/);
  assert.equal(d.signal.reason, d.error);
});

test('each phase reports its own code', async () => {
  for (const [phase, code, opt] of [
    ['connect', 'TIMEOUT_CONNECT', { connectMs: 10 }],
    ['handshake', 'TIMEOUT_HANDSHAKE', { handshakeMs: 10 }],
    ['headers', 'TIMEOUT_HEADERS', { headersMs: 10 }],
  ]) {
    const env = fakeTimers();
    const d = new DeadlineController(opt, env);
    d.beginPhase(phase);
    await env.advance(10);
    assert.equal(d.error.code, code, `${phase} should produce ${code}`);
  }
});

test('a completed phase does not fire later', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 100 }, env);
  const end = d.beginPhase('connect');
  await env.advance(50);
  end();
  await env.advance(500);
  assert.equal(d.aborted, false);
  assert.equal(env.pending, 0, 'the phase timer must be released, not left pending');
});

test('starting a phase implicitly ends the previous one', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 100, handshakeMs: 1000 }, env);
  d.beginPhase('connect');
  await env.advance(50);
  d.beginPhase('handshake');
  await env.advance(100); // would have tripped connect had it survived
  assert.equal(d.aborted, false);
  await env.advance(1000);
  assert.equal(d.error.code, 'TIMEOUT_HANDSHAKE');
});

test('a phase with no configured deadline is a no-op', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 0 }, env);
  d.beginPhase('connect');
  await env.advance(1_000_000);
  assert.equal(d.aborted, false);
});

test('the idle deadline fires only after a gap, and every touch resets it', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ idleMs: 100 }, env);
  d.beginIdle();
  for (let i = 0; i < 20; i++) {
    await env.advance(90);
    assert.equal(d.aborted, false, `still active after ${(i + 1) * 90}ms of steady traffic`);
    d.touch();
  }
  // 1800ms of wall time has passed with no total deadline: a slow stream must survive that.
  await env.advance(100);
  assert.equal(d.aborted, true);
  assert.equal(d.error.code, 'TIMEOUT_IDLE');
});

test('the total ceiling fires even while data is flowing', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ idleMs: 100, totalMs: 250 }, env);
  d.beginIdle();
  await env.advance(90);
  d.touch();
  await env.advance(90);
  d.touch();
  assert.equal(d.aborted, false);
  await env.advance(90);
  assert.equal(d.aborted, true);
  assert.equal(d.error.code, 'TIMEOUT_TOTAL');
});

test('an outer AbortSignal tears the controller down and preserves its reason', async () => {
  const env = fakeTimers();
  const outer = new AbortController();
  const d = new DeadlineController({ connectMs: 100 }, { ...env, signal: outer.signal });
  d.beginPhase('connect');
  const reason = new Error('caller changed their mind');
  outer.abort(reason);
  await settle();
  assert.equal(d.aborted, true);
  assert.equal(d.signal.reason, reason);
  assert.equal(env.pending, 0, 'timers must be released when the caller aborts');
});

test('an already-aborted outer signal aborts immediately', async () => {
  const env = fakeTimers();
  const outer = new AbortController();
  outer.abort(new Error('pre-aborted'));
  const d = new DeadlineController({ connectMs: 100 }, { ...env, signal: outer.signal });
  assert.equal(d.aborted, true);
});

test('dispose releases every timer', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 100, idleMs: 100, totalMs: 100 }, env);
  d.beginPhase('connect');
  d.touch();
  assert.ok(env.pending >= 2);
  d.dispose();
  assert.equal(env.pending, 0);
  await env.advance(10_000);
  assert.equal(d.aborted, false, 'a disposed controller must not fire afterwards');
});

test('dispose is idempotent', () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 10 }, env);
  d.dispose();
  d.dispose();
  assert.equal(env.pending, 0);
});

test('race rejects with the typed timeout, not a bare abort', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 50 }, env);
  d.beginPhase('connect');
  const never = new Promise(() => {});
  const p = d.race(never);
  await env.advance(50);
  const err = await p.then(
    () => null,
    (e) => e,
  );
  assert.equal(err.code, 'TIMEOUT_CONNECT');
});

test('race resolves normally when the promise wins', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 50 }, env);
  d.beginPhase('connect');
  assert.equal(await d.race(Promise.resolve('ok')), 'ok');
  d.dispose();
});

test('race on an already-aborted controller rejects immediately', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ connectMs: 1 }, env);
  d.beginPhase('connect');
  await env.advance(1);
  await assert.rejects(() => d.race(Promise.resolve('never seen')));
});

// ------------------------------------------------------------------ stream wrapper

test('withIdleDeadline passes data through unchanged', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ idleMs: 1000 }, env);
  d.beginIdle();
  const out = await collect(withIdleDeadline(readableFrom([utf8('hel'), utf8('lo')]), d));
  assert.equal(latin1(out), 'hello');
});

test('withIdleDeadline errors the stream when the gap is too long', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ idleMs: 100 }, env);
  d.beginIdle();

  // A source that yields once and then stalls forever.
  let sent = false;
  const stalling = new ReadableStream({
    pull(c) {
      if (!sent) {
        sent = true;
        c.enqueue(utf8('first'));
        return;
      }
      return new Promise(() => {});
    },
  });

  const stream = withIdleDeadline(stalling, d);
  const reader = stream.getReader();
  const first = await reader.read();
  assert.equal(latin1(first.value), 'first');

  const pending = reader.read().then(
    () => null,
    (e) => e,
  );
  await env.advance(100);
  const err = await pending;
  assert.ok(err, 'the stalled read must reject');
  assert.equal(err.code, 'TIMEOUT_IDLE');
});

test('withIdleDeadline keeps a slow but steady stream alive past the idle window', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ idleMs: 100 }, env);
  d.beginIdle();

  let n = 0;
  const drip = new ReadableStream({
    pull(c) {
      if (n >= 5) {
        c.close();
        return;
      }
      n++;
      // Each chunk arrives 90ms after the previous one; total 450ms, well past idleMs.
      return env.advance(90).then(() => c.enqueue(utf8('x')));
    },
  });

  const out = await collect(withIdleDeadline(drip, d));
  assert.equal(latin1(out), 'xxxxx');
  assert.equal(d.aborted, false);
});

test('cancelling the wrapped stream disposes the deadlines', async () => {
  const env = fakeTimers();
  const d = new DeadlineController({ idleMs: 100 }, env);
  d.beginIdle();
  const stream = withIdleDeadline(readableFrom([utf8('a'), utf8('b')]), d);
  const reader = stream.getReader();
  await reader.read();
  await reader.cancel(new Error('caller stopped reading'));
  assert.equal(env.pending, 0);
});

// ------------------------------------------------------------------ one-shot helper

test('withDeadline rejects with the code it was given', async () => {
  const env = fakeTimers();
  const p = withDeadline(new Promise(() => {}), 40, 'TIMEOUT_CONNECT', 'socket open', env);
  const caught = p.then(
    () => null,
    (e) => e,
  );
  await env.advance(40);
  const err = await caught;
  assert.equal(err.code, 'TIMEOUT_CONNECT');
  assert.match(err.message, /socket open did not complete within 40ms/);
});

test('withDeadline passes a value straight through and clears its timer', async () => {
  const env = fakeTimers();
  assert.equal(await withDeadline(Promise.resolve(7), 40, 'TIMEOUT_CONNECT', 'x', env), 7);
  assert.equal(env.pending, 0);
});

test('withDeadline with no timeout is a pass-through', async () => {
  const env = fakeTimers();
  assert.equal(await withDeadline(Promise.resolve(1), 0, 'TIMEOUT_CONNECT', 'x', env), 1);
  assert.equal(env.pending, 0);
});

test('withDeadline propagates the original rejection, not a timeout', async () => {
  const env = fakeTimers();
  const boom = new Error('connection refused');
  await assert.rejects(
    () => withDeadline(Promise.reject(boom), 40, 'TIMEOUT_CONNECT', 'x', env),
    /connection refused/,
  );
  assert.equal(env.pending, 0);
});
