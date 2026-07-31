// House rules, enforced mechanically rather than by review.
//
// Two of these are load-bearing rather than stylistic:
//
//  * Every module under src/ is imported here. A module with a syntax error or a bad import path
//    would otherwise simply have no tests, and a suite that silently omits a broken file reports
//    "all passed" while shipping something that cannot even load.
//  * No `node:` import may appear under src/. The package targets a runtime where node:crypto's
//    X509Certificate is missing the fields a path validator needs — a security check that reads
//    undefined and carries on is the worst failure mode available — and staying free of node:
//    also keeps the package runnable on Deno, Bun and browsers.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const srcDir = join(root, 'src');
const testDir = join(root, 'test');

async function walk(dir, filter = (f) => f.endsWith('.js')) {
  /** @type {string[]} */
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walk(full, filter)));
    else if (filter(e.name)) out.push(full);
  }
  return out.sort();
}

/**
 * Remove comments so the content rules apply to code, not to prose explaining the runtime.
 *
 * Line-based rather than a real lexer on purpose: a character-by-character scanner has to decide
 * whether a quote inside a regex character class opens a string, gets it wrong, and then silently
 * mis-classifies the rest of the file. Being approximate in a way that only ever leaves MORE text
 * for the checks to see is the safe direction to be wrong in.
 */
function stripComments(source) {
  const out = [];
  let inBlock = false;
  for (const raw of source.split('\n')) {
    let line = raw;
    if (inBlock) {
      const end = line.indexOf('*/');
      if (end === -1) {
        out.push('');
        continue;
      }
      line = line.slice(end + 2);
      inBlock = false;
    }
    line = line.replace(/\/\*[\s\S]*?\*\//g, ' ');
    const open = line.indexOf('/*');
    if (open !== -1) {
      line = line.slice(0, open);
      inBlock = true;
    }
    // Find a `//` that starts a comment. A `//` preceded by `:` is a URL scheme separator, and
    // must stay visible — catching URLs inside string literals is the whole point of one check.
    for (let i = 0; i < line.length - 1; i++) {
      if (line[i] === '/' && line[i + 1] === '/' && line[i - 1] !== ':') {
        line = line.slice(0, i);
        break;
      }
    }
    out.push(line);
  }
  return out.join('\n');
}

const srcFiles = await walk(srcDir);
const testFiles = await walk(testDir, (f) => f.endsWith('.js'));
const rel = (f) => relative(root, f);

test('the source tree is not empty, so an empty glob cannot masquerade as success', () => {
  assert.ok(srcFiles.length >= 5, `expected several source modules, found ${srcFiles.length}`);
  assert.ok(testFiles.length >= 5, `expected several test modules, found ${testFiles.length}`);
});

test('every module under src/ imports cleanly', async (t) => {
  for (const file of srcFiles) {
    await t.test(rel(file), async () => {
      // A throw here means a syntax error, a bad specifier, or a bad top-level side effect.
      // Any of those must be a test failure, never a silently absent suite.
      const mod = await import(pathToFileURL(file).href);
      assert.ok(mod && typeof mod === 'object', `${rel(file)} produced no module namespace`);
    });
  }
});

test('no module under src/ imports from node:', async () => {
  const offenders = [];
  for (const file of srcFiles) {
    const code = stripComments(await readFile(file, 'utf8'));
    const found = code.match(/from\s+['"]node:[^'"]+['"]|import\(\s*['"]node:[^'"]+['"]|require\(\s*['"]node:/g);
    if (found) offenders.push(`${rel(file)}: ${found.join(', ')}`);
  }
  assert.deepEqual(
    offenders,
    [],
    'src/ must run on a runtime with no node: builtins:\n  ' + offenders.join('\n  '),
  );
});

test('src/ declares no dependencies beyond the standard platform', async () => {
  const offenders = [];
  for (const file of srcFiles) {
    const code = stripComments(await readFile(file, 'utf8'));
    for (const m of code.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      if (!spec.startsWith('.')) offenders.push(`${rel(file)} imports "${spec}"`);
    }
  }
  assert.deepEqual(offenders, [], 'the package is zero-dependency:\n  ' + offenders.join('\n  '));
});

test('src/ contains no hardcoded hosts or URLs', async () => {
  const offenders = [];
  for (const file of srcFiles) {
    const code = stripComments(await readFile(file, 'utf8'));
    for (const m of code.matchAll(/https?:\/\/[^\s'"`)]+/g)) {
      offenders.push(`${rel(file)}: ${m[0]}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    'this client is for arbitrary sites; a URL in src/ means something was special-cased:\n  ' +
      offenders.join('\n  '),
  );
});

test('src/ names no vendor in code (comments about the runtime are fine)', async () => {
  // The rule is that no behaviour may be conditioned on a particular company's service. Prose
  // explaining why the runtime behaves as it does is not only allowed but wanted.
  const vendors = /\b(anthropic|openai|cloudflare|workerd|googleapis|amazonaws|azure|webshare|squid)\b/i;
  const offenders = [];
  for (const file of srcFiles) {
    const code = stripComments(await readFile(file, 'utf8'));
    const m = code.match(vendors);
    if (m) offenders.push(`${rel(file)}: "${m[0]}"`);
  }
  assert.deepEqual(offenders, [], 'vendor names in src/ code:\n  ' + offenders.join('\n  '));
});

test('src/ uses no non-injectable randomness or ambient logging', async () => {
  const offenders = [];
  for (const file of srcFiles) {
    const code = stripComments(await readFile(file, 'utf8'));
    if (/\bMath\.random\b/.test(code)) {
      offenders.push(`${rel(file)}: Math.random (randomness must be injectable and cryptographic)`);
    }
    if (/\bconsole\.(log|debug|info|warn|error)\b/.test(code)) {
      offenders.push(`${rel(file)}: console.* (a library must not write to the host's log)`);
    }
  }
  assert.deepEqual(offenders, [], offenders.join('\n  '));
});

test('every src/ directory has a matching test/ directory', async () => {
  const srcDirs = new Set(srcFiles.map((f) => relative(srcDir, dirname(f))).filter((d) => d !== ''));
  const testDirs = new Set(testFiles.map((f) => relative(testDir, dirname(f))));
  const missing = [...srcDirs].filter((d) => !testDirs.has(d));
  assert.deepEqual(missing, [], `src directories with no tests: ${missing.join(', ')}`);
});

test('every substantive src/ module is exercised by some test file', async () => {
  const testSources = await Promise.all(testFiles.map((f) => readFile(f, 'utf8')));
  const joined = testSources.join('\n');
  const unreferenced = [];
  for (const file of srcFiles) {
    const base = relative(srcDir, file);
    // Barrels and generated data have no behaviour of their own to test directly; the import
    // check above already proves they load.
    if (base.endsWith('index.js') || base.endsWith('roots.js') || base.endsWith('constants.js')) continue;
    const name = base.replace(/\\/g, '/');
    if (!joined.includes(`src/${name}`)) unreferenced.push(name);
  }
  assert.deepEqual(
    unreferenced,
    [],
    `src modules no test imports (a module with no test is an untested security boundary):\n  ` +
      unreferenced.join('\n  '),
  );
});

test('no test file under test/ reaches a real host', async () => {
  // Live tests live beside these as *.live.js and are run by a separate script on purpose:
  // a suite that goes green because the network was unreachable is worse than no suite.
  //
  // The check is for real destinations rather than for the identifier `fetch`, because the
  // offline suite legitimately calls a fetch built over an in-memory socket factory. What must
  // not appear is a runtime socket import or a hostname that resolves anywhere: RFC 2606 and
  // RFC 6761 reserve .example/.invalid/.test/localhost precisely so tests can name a host that
  // provably does not exist.
  // RFC 2606 reserves example.com/.net/.org and the .example/.invalid/.test TLDs; RFC 6761
  // reserves localhost. Everything else is a name somebody could own.
  const reserved = /(^|\.)(example\.(com|net|org)|example|invalid|test|localhost)$/i;
  // Literals that cannot route to anyone: loopback, RFC 1918 private space, link-local, and the
  // RFC 5737 documentation ranges.
  const unroutableIp =
    /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0$)/;
  // RFC 3849 reserves 2001:db8::/32 for documentation; ::1 is loopback.
  const docIpv6 = /^(2001:0?db8:|::1$|fe80:)/i;
  const offenders = [];
  for (const file of testFiles) {
    if (file === fileURLToPath(import.meta.url)) continue;
    const code = stripComments(await readFile(file, 'utf8'));
    if (/['"]cloudflare:sockets['"]/.test(code)) {
      offenders.push(`${rel(file)}: imports the runtime socket module`);
    }
    // The authority is either a bracketed IPv6 literal or a run of non-delimiter characters.
    // A bracketed IPv6 authority must actually close before any delimiter, so an unterminated
    // `http://[` in a malformed-URL fixture matches nothing rather than swallowing the file.
    for (const m of code.matchAll(/https?:\/\/(\[[^\]\s'"`)]*\]|[^\s/'"`)[\]]+)/g)) {
      const host = m[1].replace(/^[^@]*@/, '').replace(/:\d+$/, '');
      const bare = host.replace(/^\[|\]$/g, '');
      const ok =
        reserved.test(bare) ||
        unroutableIp.test(bare) ||
        docIpv6.test(bare) ||
        // A single-label name has no public resolution without a local search domain, so it
        // cannot reach anyone; `localhost`, `origin`, `h` and friends are all in this class.
        !bare.includes('.');
      if (!ok) offenders.push(`${rel(file)}: ${m[0]}`);
    }
  }
  assert.deepEqual(offenders, [], 'offline suite must not name a real host:\n  ' + offenders.join('\n  '));
});

test('package.json ships src/ and nothing that leaks the development rig', async () => {
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.license, 'MIT');
  assert.deepEqual(pkg.dependencies, undefined, 'the package must have no runtime dependencies');
  assert.ok(pkg.files.includes('src'));
  assert.ok(!pkg.files.includes('probe'), 'the probe is a development rig, not part of the package');
  assert.ok(!pkg.files.includes('test'));
  for (const [name, target] of Object.entries(pkg.exports)) {
    assert.ok(target.startsWith('./src/'), `export "${name}" must point into src/, got ${target}`);
    // A subpath export naming a file that does not exist fails only for the consumer who tries
    // it, which is the worst place to find out; `npm pack` will happily ship the broken map.
    const resolved = join(root, target.slice(2));
    const mod = await import(pathToFileURL(resolved).href);
    assert.ok(
      Object.keys(mod).length > 0,
      `export "${name}" resolves to ${target} but exports nothing`,
    );
  }
});

test('the offline and live test globs cannot overlap', async () => {
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.match(pkg.scripts.test, /test\/\*\*\/\*\.test\.js/);
  assert.match(pkg.scripts['test:live'], /test\/live\/\*\*\/\*\.live\.js/);
  // The suffixes differ, so a live test can never be picked up by the default run.
  const live = await walk(join(testDir, 'live'), (f) => f.endsWith('.test.js'));
  assert.deepEqual(
    live.map(rel),
    [],
    'files under test/live/ must be named *.live.js so they never join the offline suite',
  );
});

test('no credential-shaped literal is committed anywhere in src/ or test/', async () => {
  const suspicious = [];
  const patterns = [
    /\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}/,
    /\b[A-Za-z0-9_-]{20,}:[A-Za-z0-9_-]{12,}@/, // user:pass@host
    /\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}:[A-Za-z0-9]+:[A-Za-z0-9]+/, // host:port:user:pass
  ];
  for (const file of [...srcFiles, ...testFiles]) {
    const code = await readFile(file, 'utf8');
    for (const p of patterns) {
      const m = code.match(p);
      if (m) suspicious.push(`${rel(file)}: ${m[0].slice(0, 24)}...`);
    }
  }
  assert.deepEqual(suspicious, [], 'credentials must come from the environment only:\n  ' + suspicious.join('\n  '));
});
