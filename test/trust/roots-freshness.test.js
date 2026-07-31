// The bundled trust anchors are a snapshot, and snapshots rot. This test is the alarm clock.
//
// Expiry is NOT the failure mode people expect it to be: of the anchors shipped today, none expire
// within two years and the earliest is in 2028. What actually breaks, and much sooner, is the two
// directions a snapshot cannot follow:
//
//   * ADDITIONS — a CA rotates to a new root, sites start chaining to it, and we reject a
//     certificate every browser accepts. An availability bug that arrives host by host and looks
//     like "TLS randomly fails".
//   * REMOVALS — a root is distrusted for cause upstream and we keep trusting it. This one is
//     silent, and it is a security bug rather than an availability one.
//
// Both move on the timescale of months, which is why the threshold below is months and not years.
// A failure here is not a defect in the code; it means run `npm run roots:refresh` and commit the
// result. It lives in the offline suite deliberately: tests are not published to npm, so the only
// people this can interrupt are the ones who can fix it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { provenance, systemAnchors } from '../../src/trust/roots.js';

/** Quarterly refresh policy, with a month of slack before the suite starts complaining. */
const MAX_AGE_DAYS = 120;
const DAY = 24 * 60 * 60 * 1000;

test('the bundled trust anchors are not stale', () => {
  const retrieved = Date.parse(provenance.retrievedAt);
  assert.ok(
    Number.isFinite(retrieved),
    `provenance.retrievedAt is ${JSON.stringify(provenance.retrievedAt)}, which is not a date`,
  );

  const ageDays = Math.floor((Date.now() - retrieved) / DAY);
  assert.ok(
    ageDays <= MAX_AGE_DAYS,
    `the trust anchor store was retrieved ${ageDays} days ago (${provenance.retrievedAt}), over ` +
      `the ${MAX_AGE_DAYS}-day refresh policy. This is not a code defect: roots added upstream ` +
      'since then are ones we now reject and every browser accepts, and roots distrusted upstream ' +
      'since then are ones we still trust. Run `npm run roots:refresh` and commit the result.',
  );
});

test('provenance records what would be needed to reproduce the store', () => {
  // A snapshot whose origin is not recorded cannot be audited or regenerated, which turns a
  // refresh into an act of faith.
  assert.match(provenance.source, /^ccadb:/, 'the upstream source must be named');
  assert.match(provenance.upstreamSha256, /^[0-9a-f]{64}$/, 'the upstream digest must be recorded');
  assert.ok(provenance.anchorCount > 0, 'anchorCount must be recorded');
});

test('the shipped store holds exactly the anchors provenance claims', () => {
  // Guards the generator. A truncated write that still parses would ship a store trusting fewer
  // CAs than declared, and nothing at runtime would notice: a missing anchor looks identical to a
  // certificate that legitimately does not chain to us. The raw index is deliberately not exported
  // — callers get forIssuer() — so this counts entries in the generated source instead.
  const src = readFileSync('src/trust/roots.js', 'utf8');
  const counted = (src.match(/\{ name: "/g) ?? []).length;
  assert.equal(
    counted,
    provenance.anchorCount,
    `the generated store contains ${counted} anchors but provenance claims ` +
      `${provenance.anchorCount}. Regenerate with \`npm run roots:refresh\`.`,
  );
  assert.equal(typeof systemAnchors.forIssuer, 'function', 'systemAnchors must expose forIssuer()');
});
