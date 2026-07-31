// warmup() — the opt-in JIT warmer that replays a recorded handshake through the real code.
//
// The load-bearing assertions:
//   * The replay COMPLETES: every parser, the key schedule, the AEAD opens, path validation and
//     both signature checks all accept the recorded bytes. This doubles as the fixture drift
//     detector — any change to a ClientHello default (ciphers, groups, extensions, ALPN) makes
//     the recording undecryptable, fails this suite, and the fix is to rerun
//     scripts/gen-warmup-fixture.mjs, not to touch the recording by hand.
//   * warmup() never throws and keeps no state: calling it twice returns equal reports, and
//     behaviour with and without it is identical by construction (it only calls pure/derive
//     functions plus verifyChain under its own explicit anchors config).

import test from 'node:test';
import assert from 'node:assert/strict';
import { warmup } from '../src/warmup.js';
import { WARMUP_FIXTURE, WARMUP_HOSTNAME, WARMUP_NOW } from '../src/warmup-fixture.js';
import { verifyChain } from '../src/trust/index.js';

test('the recorded replay completes end to end (fixture drift detector)', async () => {
  const report = await warmup({ iterations: 1 });
  assert.deepEqual(report, { ok: true, iterations: 1, error: null },
    report.error
      ? `warmup failed at: ${report.error} — if a ClientHello default changed, rerun ` +
        'scripts/gen-warmup-fixture.mjs'
      : 'unexpected report shape');
});

test('warmup is idempotent and stateless across calls', async () => {
  const first = await warmup({ iterations: 2 });
  const second = await warmup({ iterations: 2 });
  assert.deepEqual(first, second);
  assert.equal(first.ok, true);
});

test('iteration count is clamped and bad input cannot make it throw', async () => {
  assert.equal((await warmup({ iterations: 0 })).iterations, 1);
  assert.equal((await warmup({ iterations: 99 })).iterations, 10);
  assert.equal((await warmup({ iterations: Number.NaN })).iterations, 5);
  assert.equal((await warmup({ iterations: 2.9 })).iterations, 2);
  assert.equal((await warmup()).iterations, 5);
});

test('the fixture chain anchors only to its own baked root, under a reserved name', async () => {
  assert.match(WARMUP_HOSTNAME, /\.invalid$/, 'fixture hostname must be RFC 2606 reserved');
  // The recorded chain must be verifiable ONLY via the explicit fixture anchor — proving the
  // warmup never needs (and its material could never pass) the bundled store.
  const root = WARMUP_FIXTURE.rootDer();
  assert.ok(root.byteLength > 200, 'fixture root looks like DER');
  await assert.rejects(
    () => verifyChain({ chain: [root], hostname: WARMUP_HOSTNAME, now: WARMUP_NOW }),
    /certification path|trust anchor|self-signed/i,
    'the fixture root must not validate against the bundled system store',
  );
});

test('fixture accessors return fresh copies, so no caller can corrupt another', () => {
  const a = WARMUP_FIXTURE.serverBytes();
  const b = WARMUP_FIXTURE.serverBytes();
  assert.notEqual(a, b, 'each call must decode afresh');
  a[0] ^= 0xff;
  assert.notEqual(a[0], b[0], 'mutating one copy must not affect the next');
});
