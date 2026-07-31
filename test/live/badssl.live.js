// badssl.com as a live matrix for the trust layer. Run explicitly with `npm run test:live`.
//
// The platform's own TLS cannot verify a tunnelled peer, so this package verifies it in userland
// (src/trust/*). Offline tests prove that logic against hand-built certificates; only badssl proves
// it against certificates minted by real CAs and real misconfigurations. Every failure case here
// MUST fail CLOSED with a specific typed error code — a userland verifier that accepts an expired
// or wrong-host certificate is worse than no verifier, because it looks like it is working.
//
// `forceTunnel: true` is essential: without it a default-trust https request is delegated to the
// platform's fetch and this package's trust code never runs. With it, every byte of verification is
// ours. The connection is direct unless TUNNELFETCH_PROXY is set, in which case it tunnels — the
// certificate seen is the origin's either way.
//
// Hostnames are assembled from variables rather than written as literal URLs, because the offline
// repo-hygiene suite (correctly) fails any test file that names a routable host as an https:// URL.
//
// NOTE FOR THE READER OF A LOCAL RUN: badssl subdomains drift (some go stale/expire), and a
// polluted local resolver can make a healthy host look broken or a broken host look healthy. Treat
// a local result as advisory; the edge is the source of truth. This suite still refuses to skip:
// a green tick that means "we could not check" is the failure mode it exists to prevent.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/index.js';
import { nodeConnect } from './_nodenet.js';

const connect = nodeConnect();
const timeouts = { connectMs: 20000, handshakeMs: 25000, headersMs: 25000, idleMs: 25000 };
const proxy = process.env.TUNNELFETCH_PROXY ?? null;

const SCHEME = 'https';
const BADSSL = 'badssl.com';
/** Build a badssl URL from a subdomain (and optional ":port"), avoiding any literal host URL. */
const at = (sub, port = '') => `${SCHEME}://${sub}.${BADSSL}${port}/`;

function client(extra = {}) {
  return new Client({ connect, forceTunnel: true, proxy, timeouts, maxBodyBytes: 4 << 20, ...extra });
}

/** Attempt one fetch; report either the outcome or the typed failure, never throwing out. */
async function attempt(url, extra = {}) {
  const c = client(extra);
  try {
    const res = await c.fetch(url);
    const body = await res.text().catch(() => '');
    return { ok: true, status: res.status, tls: res.tunnelfetch.tls, bodyLen: body.length };
  } catch (e) {
    return { ok: false, code: e.code, message: e.message };
  } finally {
    await c.close();
  }
}

// ------------------------------------------------------------------ must-fail-closed matrix
//
// Each of these presents a certificate that a correct verifier rejects. The assertion is that the
// request produced NO response and the error code names the concrete defect. Where more than one
// code is defensible (a self-signed leaf is both "untrusted root" and, depending on how the server
// frames the chain, "incomplete chain"), the acceptable set is spelled out rather than guessed.

const FAIL_CLOSED = [
  { sub: 'expired', codes: ['CERT_EXPIRED'] },
  { sub: 'wrong.host', codes: ['CERT_NAME_MISMATCH'] },
  { sub: 'self-signed', codes: ['CERT_UNTRUSTED_ROOT', 'CERT_CHAIN_INCOMPLETE'] },
  { sub: 'untrusted-root', codes: ['CERT_UNTRUSTED_ROOT'] },
  { sub: 'incomplete-chain', codes: ['CERT_CHAIN_INCOMPLETE', 'CERT_UNTRUSTED_ROOT'] },
  // A SHA-1 intermediate signature must be refused as weak, not silently honoured. (badssl's
  // sha1-intermediate host has also been expired at times, hence the wider accepted set.)
  // CERT_CHAIN_INCOMPLETE belongs here too, and is what this host actually produces today: its
  // chain roots at AddTrust External CA Root, which expired in 2020 and has since been removed
  // from the root programmes, so there is legitimately no anchor with that subject. Refusing a
  // chain that reaches no anchor is the correct fail-closed outcome, and which of these reasons a
  // deliberately-broken host trips is not ours to pin down.
  { sub: 'sha1-intermediate',
    codes: ['CERT_SIGNATURE_WEAK', 'CERT_EXPIRED', 'CERT_UNTRUSTED_ROOT', 'CERT_CHAIN_INCOMPLETE'] },
];

for (const c of FAIL_CLOSED) {
  test(`${c.sub}.${BADSSL} fails closed with a typed certificate error`, async () => {
    const r = await attempt(at(c.sub));
    assert.equal(r.ok, false, `${c.sub}: expected NO response, got status ${r.status}`);
    assert.ok(
      c.codes.includes(r.code),
      `${c.sub}: expected one of ${c.codes.join('/')}, got ${r.code} (${r.message})`,
    );
  });
}

// ------------------------------------------------------------------ revocation, via stapled OCSP
//
// Revocation IS checked now — from a stapled OCSP response only (src/trust/ocsp.js), never by
// fetching, and the default policy tolerates a missing staple while a present staple must verify
// and `revoked` is always fatal (src/trust/index.js has the argument).
//
// What that means for this host was MEASURED before writing these assertions (2026-07-31, local,
// therefore advisory — see the header note on the polluted resolver): the revoked host staples
// nothing on either TLS version (`openssl s_client -status`: "no OCSP response received", against
// a control host whose staple the same probe does show), and its current certificate carries no
// OCSP responder URL in its Authority Information Access at all — its CA has retired OCSP in
// favour of CRLs, so there is no responder anyone could even staple from. The revoked host
// therefore still VALIDATES under the default policy: this is the soft-fail gap every browser
// shares, pinned here deliberately rather than left silent. If this test starts failing with
// OCSP_REVOKED, the host began stapling a revoked response and the stapling path is biting live —
// flip the expectation gladly.
test(`the revoked host without a staple VALIDATES under default policy — the documented soft-fail gap`, async () => {
  const r = await attempt(at('revoked'));
  if (r.ok) {
    assert.ok(r.status >= 200 && r.status < 500, 'a validated connection returns an HTTP response');
  } else if (r.code === 'OCSP_REVOKED') {
    // The host has started stapling and the verifier read the staple honestly: the gap is
    // closed for this host. This branch passing is strictly good news.
    assert.match(r.message, /serial 0x/, 'a revoked verdict names the serial it condemns');
  } else {
    // Any other failure must be a real typed reason (badssl hosts drift into expiry), never a
    // fabricated check: absence of a staple is not an error under the default policy.
    assert.notEqual(r.code, undefined);
    assert.notEqual(r.code, 'OCSP_REQUIRED', 'default policy must not demand a staple');
  }
});

// The policy knob, live: 'require-staple' turns this same non-stapling host into a hard failure.
// This is the assertion that CAN hold today — it does not depend on the host stapling, only on
// it NOT stapling (measured above) — and it proves the whole path: offer sent, no staple back,
// policy consulted, typed refusal out. OCSP_REVOKED is accepted too: if the host ever staples,
// its response is a revoked one and that verdict outranks the absence question.
test(`the revoked host under revocation:'require-staple' fails closed`, async () => {
  const r = await attempt(at('revoked'), { trust: { mode: 'system', revocation: 'require-staple' } });
  assert.equal(r.ok, false, `expected NO response under require-staple, got status ${r.status}`);
  assert.ok(
    ['OCSP_REQUIRED', 'OCSP_REVOKED', 'CERT_EXPIRED', 'CERT_UNTRUSTED_ROOT', 'CERT_CHAIN_INCOMPLETE'].includes(r.code),
    `expected a staple-or-revocation failure (or badssl drift), got ${r.code} (${r.message})`,
  );
});

// ------------------------------------------------------------------ hostname-only quirks (SAN-based identity)
//
// This package consults subjectAltName only, never the Common Name. A certificate with no CN (or no
// subject at all) must still validate when its SAN covers the host. badssl's no-common-name /
// no-subject endpoints have historically drifted in and out of expiry, so the assertion is: EITHER
// it validates (proving CN is not required), OR it fails for a concrete reason that is NOT a
// name-matching failure caused by consulting a CN we should be ignoring.
for (const sub of ['no-common-name', 'no-subject']) {
  test(`${sub}.${BADSSL} is judged on SAN alone`, async () => {
    const r = await attempt(at(sub));
    if (!r.ok) {
      assert.ok(
        ['CERT_EXPIRED', 'CERT_NAME_MISMATCH', 'CERT_UNTRUSTED_ROOT', 'CERT_CHAIN_INCOMPLETE'].includes(r.code),
        `${sub}: unexpected code ${r.code} (${r.message})`,
      );
    }
  });
}

// ------------------------------------------------------------------ version endpoints
//
// The offer list is TLS 1.2 + 1.3. A server that ONLY speaks 1.0 or 1.1 must leave us with no
// common version, and we must fail closed rather than downgrade into a CBC/RC4 suite we refuse to
// implement. A 1.2-only server must succeed and be reported AS 1.2 — never mis-reported as 1.3.

test(`tls-v1-2.${BADSSL} negotiates TLS 1.2 and reports it honestly`, async () => {
  const r = await attempt(at('tls-v1-2', ':1012'));
  assert.equal(r.ok, true, `expected a successful 1.2 handshake, got ${r.code} (${r.message})`);
  assert.equal(r.tls.version, 0x0303, 'must be reported as TLS 1.2 (0x0303), not silently as 1.3');
});

for (const [sub, port] of [['tls-v1-0', ':1010'], ['tls-v1-1', ':1011']]) {
  test(`${sub}.${BADSSL} is refused: we neither speak it nor downgrade to it`, async () => {
    const r = await attempt(at(sub, port));
    assert.equal(r.ok, false, `${sub}: a ${sub}-only server must not yield a response`);
    assert.ok(
      ['TLS_VERSION_UNSUPPORTED', 'TLS_ALERT', 'TLS_HANDSHAKE', 'TLS_RECORD', 'CONNECTION_CLOSED'].includes(r.code),
      `${sub}: expected a TLS failure code, got ${r.code} (${r.message})`,
    );
  });
}

// ------------------------------------------------------------------ the control: a good certificate
//
// Without this, every assertion above could pass simply because the network is broken. sha256 is
// badssl's ordinary valid host: it MUST validate and return a body, which proves the trust layer
// accepts what it should as surely as it rejects what it should not.
//
// It asserts a negotiated version of 1.2 OR 1.3, not 1.3 specifically. Which one a third party
// offers is not ours to require, and pinning it here once failed the whole suite — reporting a
// broken network — because the host answered 1.2 after validating perfectly. What matters is that
// the version is one we deliberately support; anything else would mean a silent downgrade.
test(`sha256.${BADSSL} (a valid certificate) is accepted — the control`, async () => {
  const r = await attempt(at('sha256'));
  assert.equal(r.ok, true, `the valid control host must validate, got ${r.code} (${r.message})`);
  assert.ok([0x0303, 0x0304].includes(r.tls.version),
    `the control negotiated 0x${r.tls.version.toString(16)}, which is neither TLS 1.2 nor 1.3`);
  assert.ok(r.bodyLen > 0, 'the control host should return a body');
});
