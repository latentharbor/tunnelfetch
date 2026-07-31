// Deploy the capability probe with a fingerprint of its own source baked in.
//
// The drift test in test/live/ asks a DEPLOYED Worker what the runtime can do. That answer is only
// worth anything if the deployment matches the probe source in this checkout — otherwise an edited
// probe silently keeps testing whatever was deployed months ago, and a "no drift" result means
// nothing. Passing the source hash as a deploy-time var, and having the test refuse to run unless
// the deployed hash matches the local one, makes that mismatch impossible to miss rather than
// impossible to cause.
//
// Usage: npm run probe:deploy

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

const DIR = 'probe/src';

function sourceHash() {
  const h = createHash('sha256');
  // Sorted so the hash depends on content, not on directory order.
  for (const name of readdirSync(DIR).sort()) {
    if (!name.endsWith('.js')) continue;
    h.update(name);
    h.update(readFileSync(join(DIR, name)));
  }
  return h.digest('hex').slice(0, 16);
}

const sha = sourceHash();
console.log(`probe source ${sha}`);

const r = spawnSync('npx', ['wrangler', 'deploy', '--var', `PROBE_SRC_SHA:${sha}`], {
  cwd: 'probe',
  stdio: 'inherit',
});
if (r.status !== 0) process.exit(r.status ?? 1);

console.log(`\nDeployed. test/live/nodecompat.live.js will now accept this deployment.`);
