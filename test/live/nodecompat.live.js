// Capability drift detector: has workerd's Node compatibility layer changed under us?
//
// This package implements TLS in JavaScript for one reason — nothing on the runtime can perform a
// TLS handshake over a socket that is already open, which is what a proxy CONNECT tunnel is.
// `startTls()` verifies the peer against the hostname given to `connect()`, which inside a tunnel
// is the proxy. Node's answer to the same problem is `tls.connect({ socket })`, and Cloudflare has
// been filling in `node:*` steadily, so the honest expectation is that this becomes possible one
// day. When it does, the right response is to reconsider the architecture, not to keep shipping a
// userland TLS stack out of habit.
//
// So these assertions are pinned to what was MEASURED, and they fail in BOTH directions. A failure
// here is usually good news and never a regression in this package: it means the platform moved.
// Read the failure message, re-run the probe by hand, and re-read "Why this exists" in the README.
//
// Measured 2026-07-31 against workerd on the Cloudflare edge with `nodejs_compat` and
// compatibility_date 2026-07-01.
//
// Requires a deployed probe (`npm run probe:deploy`) and, in the environment:
//   PROBE_URL     base URL of the deployed probe Worker
//   PROBE_TOKEN   its shared secret
//   PROXY_1       host:port:user:pass of a proxy that speaks CONNECT
// Missing configuration FAILS. A drift detector that skips when it is inconvenient reports "no
// drift" for years and then surprises you, which is worse than having no detector at all.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const BASE = process.env.PROBE_URL;
const TOKEN = process.env.PROBE_TOKEN;
const PROXY = process.env.PROXY_1;

function required(name, value) {
  assert.ok(
    value,
    `${name} is not set. This suite talks to a deployed probe and must never be skipped: ` +
      'run `npm run probe:deploy`, then set PROBE_URL, PROBE_TOKEN and PROXY_1.',
  );
  return value;
}

/** The same fingerprint scripts/deploy-probe.mjs bakes into the deployment. */
function localProbeSha() {
  const h = createHash('sha256');
  for (const name of readdirSync('probe/src').sort()) {
    if (!name.endsWith('.js')) continue;
    h.update(name);
    h.update(readFileSync(join('probe/src', name)));
  }
  return h.digest('hex').slice(0, 16);
}

async function probe(path, extraHeaders = {}) {
  const res = await fetch(`${required('PROBE_URL', BASE)}${path}`, {
    headers: { 'x-probe-token': required('PROBE_TOKEN', TOKEN), ...extraHeaders },
  });
  assert.equal(res.status, 200, `probe ${path} answered ${res.status}`);
  return (await res.json()).result;
}

let capsCache = null;
const caps = async () => (capsCache ??= await probe('/nodecompat'));

test('the deployed probe is the probe in this checkout', async () => {
  const { srcSha } = await caps();
  assert.equal(
    srcSha,
    localProbeSha(),
    'the deployed probe was built from different source than this checkout, so anything it ' +
      'reports describes code you are not looking at. Run `npm run probe:deploy`.',
  );
});

test('node:tls still cannot wrap an already-open socket', async () => {
  const r = await probe(`/nodetls?target=example.com`, {
    'x-proxy': required('PROXY_1', PROXY),
  });

  // The CONNECT tunnel itself works over node:net — that part is not in question and its success
  // is what makes the TLS failure below meaningful rather than incidental.
  const tunnelErr = String(r.overTunnel?.err ?? '');
  assert.match(
    tunnelErr,
    /connectStatus\\?":\s*200/,
    `the CONNECT tunnel did not open, so this run says nothing about TLS: ${tunnelErr}`,
  );

  assert.equal(
    r.overTunnel?.ok,
    false,
    'tls.connect({ socket }) COMPLETED a handshake over a CONNECT tunnel. This is not a ' +
      'regression — it means the runtime can now do natively what this package implements in ' +
      'JavaScript. Re-read "Why this exists" in the README and decide whether the userland TLS ' +
      'stack should become a fallback. Verify the identity gate first: a handshake that succeeds ' +
      'while demanding a hostname the certificate does not carry is worse than none.',
  );

  // The failure has a specific shape: the runtime's net.Socket holds a reader on the underlying
  // stream and the TLS layer cannot take it over, so no ClientHello is ever written. If the shape
  // changes, the reasoning above may no longer hold even though the outcome is still failure.
  assert.match(
    tunnelErr,
    /releaseLock|outstanding read/,
    `tls.connect({ socket }) now fails for a DIFFERENT reason than stream ownership: ${tunnelErr}`,
  );
  assert.match(
    tunnelErr,
    /bytesWrittenAfterTlsAttach\\?":\s*0/,
    `the TLS layer now writes bytes to a tunnelled socket where it previously wrote none: ${tunnelErr}`,
  );
});

test('node:tls still has no root store of its own', async () => {
  const { crypto: c } = await caps();
  assert.equal(c.rootCertificates?.ok, true, 'tls.rootCertificates became unreadable');
  assert.equal(
    c.rootCertificates.v.count,
    0,
    `tls.rootCertificates now contains ${c.rootCertificates.v.count} anchors. If the runtime ` +
      'ships a real root store, src/trust/roots.js and its refresh cadence may be replaceable.',
  );
});

test('the synchronous node:crypto primitives are still available', async () => {
  // Not a dependency — the package runs on the bare web platform and repo-hygiene enforces that.
  // Pinned because it is the strongest known lever on CPU cost: every AEAD operation in the record
  // layer is currently an await. If these disappear, an optimisation avenue closes.
  const { crypto: c } = await caps();
  assert.equal(c.createHash?.ok, true, `node:crypto createHash regressed: ${c.createHash?.err}`);
  assert.equal(c.createHmac?.ok, true, `node:crypto createHmac regressed: ${c.createHmac?.err}`);
  assert.equal(c.aesGcmSync?.ok, true, `synchronous AES-GCM regressed: ${c.aesGcmSync?.err}`);
});

test('synchronous X25519 is still absent', async () => {
  const { crypto: c } = await caps();
  assert.equal(
    c.x25519?.ok,
    false,
    'node:crypto can now do X25519 synchronously. Key exchange currently goes through WebCrypto ' +
      'because it had to; that constraint may have lifted.',
  );
});

test('tls.connect still rejects ALPNProtocols and checkServerIdentity', async () => {
  const r = await probe(`/nodetls?target=example.com`, {
    'x-proxy': required('PROXY_1', PROXY),
  });
  assert.equal(
    r.options?.alpn?.ok,
    false,
    'tls.connect now accepts ALPNProtocols; protocol negotiation is no longer out of reach.',
  );
  assert.equal(
    r.options?.checkServerIdentity?.ok,
    false,
    'tls.connect now accepts checkServerIdentity, which is the hook a caller would need to ' +
      'impose its own identity policy. Worth re-examining.',
  );
});
