// Query Cloudflare's Billable Usage API — the only authoritative number in this repository.
//
// Every cost figure in the README is derived from `cpuTime` as reported by `wrangler tail`. That is
// a per-invocation reading, not a billing statement, and the two have never been compared. This
// script exists to compare them: run a known number of requests, sum the cpuTime observed, and
// divide the CPU-milliseconds Cloudflare actually billed by the same request count.
//
// If they agree, the measurement method behind every number in this repo is calibrated. If they do
// not, the ratio between them is the correction factor for all of it — and given how many times an
// instrument in this project has turned out to be measuring something other than what it claimed,
// that is worth knowing before anyone budgets from these figures.
//
//   CF_ACCOUNT_ID=... CF_BILLING_TOKEN=... node scripts/billable-usage.mjs [--from YYYY-MM-DD] [--to YYYY-MM-DD]
//
// The token needs the **Billing Read** permission and nothing else. wrangler's own OAuth credential
// does not carry it — it is scoped to Workers — so this cannot reuse the existing login.

const account = process.env.CF_ACCOUNT_ID;
const token = process.env.CF_BILLING_TOKEN;
if (!account || !token) {
  console.error('need CF_ACCOUNT_ID and CF_BILLING_TOKEN (an API token with Billing Read)');
  process.exit(2);
}

const arg = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : null;
};

const url = new URL(`https://api.cloudflare.com/client/v4/accounts/${account}/billable-usage`);
for (const k of ['from', 'to']) {
  const v = arg(k);
  if (v) url.searchParams.set(k, v);
}

const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
const body = await res.json();
if (!body.success) {
  console.error('API refused:', JSON.stringify(body.errors ?? body, null, 2));
  process.exit(1);
}

const rows = body.result ?? [];
if (!rows.length) {
  console.log('no rows for that period — usage lands daily, so today will be empty');
  process.exit(0);
}

// Workers bills requests and CPU time as separate lines. Both are wanted: the request count is the
// denominator for a per-request figure, and the CPU line is what gets compared against summed
// cpuTime.
const interesting = rows.filter((r) =>
  /worker/i.test(`${r.ServiceName ?? ''} ${r.ServiceFamilyName ?? ''}`));

const show = interesting.length ? interesting : rows;
if (!interesting.length) console.log('(no Workers rows; showing everything)\n');

const w = (s, n) => String(s ?? '').slice(0, n).padEnd(n);
console.log(
  w('service', 34) + w('unit', 16) + 'quantity'.padStart(16) + 'cost'.padStart(12) + '  period',
);
console.log('-'.repeat(96));
let cpuMs = 0;
let requests = 0;
for (const r of show) {
  const qty = Number(r.PricingQuantity ?? 0);
  const unit = String(r.ConsumedUnit ?? '');
  console.log(
    w(r.ServiceName ?? r.ServiceFamilyName, 34) + w(unit, 16) +
    qty.toLocaleString().padStart(16) +
    `$${Number(r.ContractedCost ?? 0).toFixed(4)}`.padStart(12) +
    '  ' + String(r.ChargePeriodStart ?? '').slice(0, 10),
  );
  if (/cpu|millisecond/i.test(unit)) cpuMs += qty;
  if (/request/i.test(unit)) requests += qty;
}

console.log();
if (cpuMs) console.log(`billed CPU: ${cpuMs.toLocaleString()} ms`);
if (requests) console.log(`billed requests: ${requests.toLocaleString()}`);
if (cpuMs && requests) {
  console.log(`\nbilled CPU per request: ${(cpuMs / requests).toFixed(3)} ms`);
  console.log('Compare that against the cpuTime this repo measures for the same shape. A gap is not');
  console.log('noise — it is the conversion between what `wrangler tail` reports and what is charged,');
  console.log('and every figure in the README is stated in the former.');
}
