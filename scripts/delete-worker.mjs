// Delete a Worker by name. Used by CI to remove the throwaway rigs it deploys per run.
//
// Exits 0 whether or not the Worker existed, because this runs in an `if: always()` cleanup step
// and a cleanup that fails the build when there was nothing to clean turns a red test into two red
// things to investigate. A genuine API failure is still reported on stderr and distinguishable in
// the log; what it must not do is mask the result of the run it is cleaning up after.
//
//   node scripts/delete-worker.mjs <name> [<name> ...]
//
// Requires CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID in the environment.

const token = process.env.CLOUDFLARE_API_TOKEN;
const account = process.env.CLOUDFLARE_ACCOUNT_ID;
const names = process.argv.slice(2).filter(Boolean);

if (!token || !account) {
  console.error('CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are required');
  process.exit(0); // nothing can be cleaned; do not fail the run over it
}
if (names.length === 0) {
  console.error('usage: node scripts/delete-worker.mjs <name> [<name> ...]');
  process.exit(0);
}

for (const name of names) {
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${account}/workers/scripts/${name}?force=true`,
      { method: 'DELETE', headers: { authorization: `Bearer ${token}` } },
    );
    const body = await res.json().catch(() => ({}));
    if (body?.success) console.log(`deleted ${name}`);
    else console.error(`could not delete ${name}: ${JSON.stringify(body?.errors ?? res.status)}`);
  } catch (e) {
    console.error(`could not delete ${name}: ${e?.message ?? e}`);
  }
}
