// Property-based fuzzing of every parser that consumes bytes a peer controls.
//
// Targets are auto-discovered from test/fuzz/targets/, so adding one is dropping a file in — there
// is no list here to forget to update. Each target declares a corpus of real, valid inputs and a
// `run`; the engine mutates the corpus and asserts the only property that matters for a fail-closed
// parser: it either succeeds or throws a TunnelFetchError. Anything else — a TypeError from a
// missing bounds check, a RangeError from a bad offset — is a finding.
//
// Deterministic. The seed is fixed so this suite is reproducible and can gate CI; a failure prints
// the seed, the iteration and the exact case in base64.
//
//   FUZZ_ITERATIONS=200000 npm test    # a long soak, e.g. nightly
//   FUZZ_SEED=12345 npm test           # a different corner of the space
//
// The default is deliberately small. This runs on every commit, and a fuzz pass that makes the
// suite slow is a fuzz pass someone will delete.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fuzzTarget } from './_engine.js';
import { TunnelFetchError, codes } from '../../src/errors.js';

const here = dirname(fileURLToPath(import.meta.url));
const ITERATIONS = Number(process.env.FUZZ_ITERATIONS ?? 500);
const SEED = Number(process.env.FUZZ_SEED ?? 0x5eed1e);

const files = readdirSync(join(here, 'targets')).filter((f) => f.endsWith('.js')).sort();

test('there are fuzz targets at all, so an empty directory cannot pass as a clean run', () => {
  assert.ok(files.length >= 5, `only ${files.length} fuzz targets found`);
});

// The harness has to be shown to work, or a green fuzz suite means only that the fuzzer never
// looks. Two synthetic targets, one throwing the untyped error the property forbids and one
// throwing the typed error it allows, prove detection and its absence of false positives.
//
// This was worth writing: an earlier attempt to validate by deleting a real bounds check proved
// nothing, because the parser's downstream checks caught the damage and still threw a typed error.
// Defence in depth is good news for the code and useless as a test of the detector.
test('the fuzz engine reports an untyped throw, and only an untyped throw', async () => {
  const corpus = [new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])];

  await assert.rejects(
    () =>
      fuzzTarget(
        { name: 'synthetic.untyped', corpus, run: (b) => { if (b[0] !== 1) null.boom; } },
        { iterations: 500, seed: SEED },
      ),
    (e) => /escaped the typed-error contract/.test(e.message) && /case \(base64\)/.test(e.message),
    'the engine did not flag a raw TypeError',
  );

  const typed = await fuzzTarget(
    {
      name: 'synthetic.typed',
      corpus,
      run: (b) => {
        if (b[0] !== 1) throw new TunnelFetchError(codes.CONFIG_INVALID, 'refused, as designed');
      },
    },
    { iterations: 500, seed: SEED },
  );
  assert.ok(typed.typed > 0, 'the engine saw no typed rejections in a target that only rejects');
  assert.equal(typed.accepted + typed.typed, 500);
});

for (const file of files) {
  const target = (await import(join(here, 'targets', file))).default;

  test(`fuzz: ${target.name}`, async () => {
    assert.ok(target.corpus.length > 0, `${file} has an empty corpus`);
    // Every corpus entry must actually parse. A corpus of inputs the parser already rejects would
    // fuzz nothing — every mutation would be refused for the reason the seed was refused.
    for (const [i, seedCase] of target.corpus.entries()) {
      await target.run(Uint8Array.from(seedCase));
      assert.ok(seedCase.length > 0, `${file} corpus[${i}] is empty`);
    }

    const { accepted, typed, iterations } = await fuzzTarget(target, {
      iterations: ITERATIONS,
      seed: SEED,
    });

    // A run where nothing was ever rejected means the mutations are not reaching the validation,
    // and a run where nothing was ever accepted means they destroy the input too thoroughly to
    // exercise anything past the first check. Either way the run proved much less than it appears
    // to, and silence about that is how a fuzz suite rots into decoration.
    assert.equal(accepted + typed, iterations);
    assert.ok(typed > 0, `${target.name}: no input was ever rejected — mutations are not landing`);
    assert.ok(
      accepted > 0,
      `${target.name}: no mutated input was ever accepted, so nothing past the first validation ` +
        'check was reached. Widen the corpus or soften the mutation mix.',
    );
  });
}
