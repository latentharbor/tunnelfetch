// The checked-in declarations must match the source they were generated from.
//
// `types/` is committed so that consumers never run a build. The cost of that convenience is that
// the declarations can drift: change a signature, forget to regenerate, and the package starts
// telling TypeScript callers something that is no longer true — with no error anywhere, because
// nothing at runtime reads a .d.ts. That is the same silent-staleness failure the trust store's
// provenance block exists to prevent, so it gets the same treatment: regenerate, compare, fail.
//
// This test needs the typescript devDependency. If it is missing the test FAILS rather than
// skipping: a suite that goes green because it could not check anything is worse than a red one.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile, mkdtemp, rm } from 'node:fs/promises';
import { execFile, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tscBin = join(root, 'node_modules', '.bin', 'tsc');

async function walk(dir) {
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(full)));
    else if (e.name.endsWith('.d.ts')) out.push(full);
  }
  return out.sort();
}

test('the checked-in declarations are current', async (t) => {
  await assert.doesNotReject(
    () => readFile(tscBin).catch(() => run(tscBin, ['--version'])),
    'typescript is not installed; run `npm install` before `npm test`',
  );

  const tmp = await mkdtemp(join(tmpdir(), 'tunnelfetch-types-'));
  t.after(() => rm(tmp, { recursive: true, force: true }));

  // Same configuration as `npm run types`, redirected so the committed tree is never touched by
  // a test run.
  await run(tscBin, ['-p', 'tsconfig.json', '--outDir', tmp], { cwd: root });

  const fresh = await walk(tmp);
  const committed = await walk(join(root, 'types'));
  assert.ok(fresh.length > 0, 'the declaration build produced nothing');

  const rel = (base) => (f) => relative(base, f);
  assert.deepEqual(
    committed.map(rel(join(root, 'types'))),
    fresh.map(rel(tmp)),
    'the set of declaration files differs — run `npm run types` and commit the result',
  );

  for (const f of fresh) {
    const name = relative(tmp, f);
    const want = await readFile(f, 'utf8');
    const have = await readFile(join(root, 'types', name), 'utf8');
    assert.equal(
      have,
      want,
      `types/${name} is out of date — run \`npm run types\` and commit the result`,
    );
  }
});

test('the public entry point declares the types a caller actually reaches for', async () => {
  const index = await readFile(join(root, 'types', 'index.d.ts'), 'utf8');
  for (const name of ['Client', 'createFetch', 'install', 'verifyChain', 'openTunnel']) {
    assert.match(index, new RegExp(`\\b${name}\\b`), `index.d.ts should surface ${name}`);
  }
});

test('the discriminated trust union survives into the declarations', async () => {
  // The whole argument for generating types was that a caller cannot ask for pinning without
  // pins, nor reach `mode: 'none'` without spelling out the flag that says they meant it. If the
  // union collapses to `object`, that argument is gone and this file should say so.
  const trust = await readFile(join(root, 'types', 'trust', 'index.d.ts'), 'utf8');
  assert.match(trust, /TrustConfig/);
  assert.match(trust, /insecureAcceptAnyCertificate:\s*true/, 'the flag must be a literal true');
  assert.match(trust, /pins:\s*string\[\]/, 'pinned mode must require pins');
  assert.match(trust, /mode:\s*'pinned'|mode:\s*"pinned"/, 'the discriminant must be a literal');
});

/** tsc over one fixture, with the same settings a consumer's strict project would use. */
async function typecheck(file) {
  try {
    const { stdout } = await run(
      tscBin,
      ['--noEmit', '--strict', '--target', 'es2022', '--lib', 'es2022,dom', '--module', 'nodenext',
        '--moduleResolution', 'nodenext', '--skipLibCheck', join(root, 'test', 'typecheck', file)],
      { cwd: root },
    );
    return { ok: true, output: stdout };
  } catch (e) {
    return { ok: false, output: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

test('legitimate configurations type-check', async () => {
  // Written first because a union tight enough to reject bad input is only useful if it still
  // accepts every good shape, and it is easy to write one that does the first without the second.
  const r = await typecheck('must-pass.ts');
  assert.ok(r.ok, `must-pass.ts should compile cleanly but did not:\n${r.output}`);
});

test('configurations the runtime would reject do not compile', async () => {
  // must-fail.ts marks every line `@ts-expect-error`, so tsc succeeds only if EVERY line really
  // is an error: an unused expect-error is itself reported. That makes one clean run prove both
  // directions at once — nothing has quietly started compiling.
  const r = await typecheck('must-fail.ts');
  assert.ok(
    r.ok,
    'every line in must-fail.ts must be a compile error; an "Unused \'@ts-expect-error\'" below ' +
      `means the types stopped catching that misuse:\n${r.output}`,
  );
});

test('public entry points are not typed as any', async () => {
  const client = await readFile(join(root, 'types', 'client.d.ts'), 'utf8');
  assert.match(client, /ClientOptions/, 'the Client constructor should name its options type');
  assert.doesNotMatch(
    client,
    /export function createFetch\(options\?: \{\}\)/,
    'createFetch must take ClientOptions, not an empty object',
  );
});

test('the shipped declarations type-check on their own', async () => {
  // `npm run types` EMITS declarations; it never checks the thing it emitted. A consumer compiling
  // with skipLibCheck:false does, and three broken typedefs shipped in 1.0.0 because of that gap:
  // an import path pointing at a module that did not export the type, a union the setters
  // destructured across, and a typedef declared inside a constructor body where the emitted
  // declaration could not see it. The runtime was fine and every other test passed.
  //
  // skipLibCheck:false is the whole point — it is the setting that looks at our output.
  const { status, stdout, stderr } = spawnSync(
    'npx',
    ['tsc', '--noEmit', '--skipLibCheck', 'false', '--module', 'nodenext',
      '--moduleResolution', 'nodenext', '--target', 'es2022', '--strict', 'types/index.d.ts'],
    { encoding: 'utf8' },
  );
  assert.equal(status, 0,
    `the declarations this package publishes do not type-check:\n${stdout}${stderr}`);
});
