// Deploy a rig Worker with a fingerprint of its own source baked in, and print where it landed.
//
// Two callers, one script, deliberately: a human deploying the long-lived probe, and CI deploying a
// throwaway one per run. The drift test in test/live/ asks a DEPLOYED Worker what the runtime can
// do, and that answer is only worth anything if the deployment matches the source in this checkout
// — otherwise an edited rig silently keeps testing whatever was deployed months ago and "no drift"
// means nothing. Passing the source hash as a deploy-time var, and having the test refuse to run
// unless it matches, makes that mismatch impossible to miss rather than impossible to cause.
//
//   node scripts/deploy-probe.mjs [--dir probe] [--name tunnelfetch-probe] [--var K:V ...]
//
// Prints `DEPLOYED_URL=<url>` on its own line so a workflow can read it without guessing the
// account's workers.dev subdomain.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

function arg(flag, fallback = null) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
function allArgs(flag) {
  const out = [];
  for (let i = 0; i < process.argv.length; i++) if (process.argv[i] === flag && process.argv[i + 1]) out.push(process.argv[i + 1]);
  return out;
}

const dir = arg('--dir', 'probe');
const name = arg('--name');

/** Content hash of the rig's sources, sorted so it depends on content and not directory order. */
function sourceHash(srcDir) {
  const h = createHash('sha256');
  for (const entry of readdirSync(srcDir).sort()) {
    if (!entry.endsWith('.js')) continue;
    h.update(entry);
    h.update(readFileSync(join(srcDir, entry)));
  }
  return h.digest('hex').slice(0, 16);
}

const sha = sourceHash(join(dir, 'src'));
const args = ['wrangler', 'deploy', '--var', `PROBE_SRC_SHA:${sha}`];
if (name) args.push('--name', name);
for (const v of allArgs('--var')) args.push('--var', v);

console.log(`deploying ${dir} (source ${sha})${name ? ` as ${name}` : ''}`);
const r = spawnSync('npx', args, { cwd: dir, encoding: 'utf8' });
process.stdout.write(r.stdout ?? '');
process.stderr.write(r.stderr ?? '');
if (r.status !== 0) process.exit(r.status ?? 1);

// wrangler prints the workers.dev URL; the account's subdomain is not knowable from config, so read
// it back rather than constructing it.
const url = (`${r.stdout}\n${r.stderr}`).match(/https:\/\/[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev/i)?.[0];
if (!url) {
  console.error('could not find the deployed URL in wrangler output — is workers_dev enabled?');
  process.exit(1);
}
console.log(`DEPLOYED_URL=${url}`);
