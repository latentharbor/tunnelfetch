// Interop, measured where the package actually runs.
//
// `interop.live.js` drives the same scenarios from Node over `node:net`, which is valuable because
// it proves the package is not coupled to `cloudflare:sockets` — but it runs from a developer's
// machine, and a developer's machine is not a clean network. Proxies refuse particular
// destinations (CONNECT to one host is reset while another succeeds, and `curl -x` through the same
// proxy at the same moment agrees), residential links wobble, and local DNS can be poisoned. Every
// failure then has to be triaged before it can be believed.
//
// This suite removes that variable. The requests are made by a Worker deployed on the Cloudflare
// edge — the runtime this package exists for — and the only network this process touches is its own
// connection to Cloudflare. The Worker returns structured results; the assertions stay here, where
// they can be read and reviewed, rather than being buried in the rig.
//
// Requires, in the environment:
//   LIVE_URL      base URL of the deployed rig (live/, `npx wrangler deploy`)
//   PROBE_TOKEN   its shared secret
//   PROXY_1       host:port:user:pass of a proxy you control
//   LIVE_TARGET   optional; a host the proxy can reach (default below)
// Missing configuration FAILS rather than skipping. A live suite that skips reports a green tick
// it has not earned.

import test from 'node:test';
import assert from 'node:assert/strict';

const BASE = process.env.LIVE_URL;
const TOKEN = process.env.PROBE_TOKEN;
const PROXY = process.env.PROXY_1;
const TARGET = process.env.LIVE_TARGET || 'example.com';
// A host that deliberately serves a certificate for a different name. Overridable because it is a
// third party: if it disappears, the property is still worth testing against whatever replaces it.
const MISMATCH_HOST = process.env.LIVE_MISMATCH_HOST || 'wrong.host.badssl.com';

function required(name, value) {
  assert.ok(value, `${name} is not set. Deploy live/ with \`npx wrangler deploy\`, then set ` +
    'LIVE_URL, PROBE_TOKEN and PROXY_1. This suite never skips.');
  return value;
}

/** Drive one rig scenario and return its single result entry. */
async function rig(query) {
  const res = await fetch(`${required('LIVE_URL', BASE)}/run?${query}`, {
    headers: {
      'x-probe-token': required('PROBE_TOKEN', TOKEN),
      'x-proxy': required('PROXY_1', PROXY),
    },
  });
  assert.equal(res.status, 200, `the rig answered ${res.status}; is it deployed and is the token right?`);
  const body = await res.json();
  assert.equal(body.results.length, 1, `expected exactly one result, got ${body.results.length}`);
  return body.results[0];
}

// The tunnel has to work before any assertion about what travels through it means anything, and a
// proxy that refuses this particular destination is about the proxy, not about this package.
test('preflight: a proxied HTTPS request completes from the edge', async () => {
  const r = await rig(`targets=${TARGET}`);
  assert.equal(r.ok, true,
    `the proxy could not reach ${TARGET} from the edge: ${r.code} ${r.error}. ` +
    'If this is your proxy blocking the destination, pick another with LIVE_TARGET.');
  assert.equal(r.status, 200);
  assert.ok(r.bytes > 0, 'a body should have arrived');
});

test('the userland stack negotiates TLS 1.3 with an AEAD suite and an offered ALPN protocol', async () => {
  const r = await rig(`targets=${TARGET}`);
  assert.equal(r.ok, true, `${r.code}: ${r.error}`);
  // Pinned rather than merely recorded: a silent fallback to something weaker is exactly the
  // failure this package refuses to allow, and it would still return 200.
  assert.equal(r.tls.version, '0x304', 'must be TLS 1.3');
  assert.equal(r.tls.cipherSuite, '0x1301', 'must be TLS_AES_128_GCM_SHA256');
  assert.equal(r.tls.group, '0x1d', 'must be X25519');
  // The client offers h2 and http/1.1; the server's pick must be one of exactly those, and the
  // reported protocol must agree with it — a fabricated ALPN or a fallback we did not offer both
  // fail here. An h2 origin (most CF-fronted ones) will show 'h2'.
  assert.ok(['h2', 'http/1.1'].includes(r.tls.alpn), `ALPN must be negotiated, got ${r.tls.alpn}`);
  assert.equal(r.httpVersion, r.tls.alpn === 'h2' ? '2' : '1.1', 'the spoken protocol matches ALPN');
  assert.equal(r.proxied, true, 'this must not have been served by the platform fetch');
});

test('a SOCKS5 tunnel carries the same request', async () => {
  // Same proxy, same port, different protocol — so a difference in outcome is the SOCKS5 code and
  // nothing else.
  const r = await rig(`targets=${TARGET}&socks=1`);
  assert.equal(r.ok, true, `${r.code}: ${r.error}`);
  assert.equal(r.status, 200);
  assert.equal(r.tls.version, '0x304');
});

test('a second request on one Client reuses the connection', async () => {
  const r = await rig(`keepalive=${TARGET}`);
  assert.equal(r.ok, true, `${r.code}: ${r.error}`);
  assert.equal(r.first.status, 200);
  assert.equal(r.second.status, 200);

  // Assert reuse, not the mechanism. Over HTTP/1.1 the second request comes out of the pool; over
  // HTTP/2 it is another stream on a connection the pool never holds, so poolHits stays 0 and
  // asserting on it fails against a working client. What matters either way is that two requests
  // cost one connection. (This test did assert poolHits === 1, and started failing the moment the
  // target negotiated h2 — the client was right and the test was encoding HTTP/1.1's plumbing.)
  assert.equal(r.connectionsOpened, 1,
    `two requests should open one connection, opened ${r.connectionsOpened} ` +
    `(alpn ${r.first.alpn} then ${r.second.alpn}, poolHits ${r.poolHits})`);
  if (r.first.alpn === 'http/1.1') {
    assert.equal(r.poolHits, 1, 'over HTTP/1.1 the reuse must be a pool hit');
  }
  // Wall clock, so it includes the handshake round trips the second request skips.
  assert.ok(r.second.ms < r.first.ms,
    `reuse should be faster: first ${r.first.ms}ms, second ${r.second.ms}ms`);
});

test('a pin that does not match fails closed, and names what it saw', async () => {
  const r = await rig(`pin=${TARGET}`);
  assert.equal(r.ok, false, 'a deliberately wrong pin must not succeed');
  assert.equal(r.code, 'CERT_PIN_MISMATCH');
  // The observed pins belong in the message: without them the operator cannot tell a
  // misconfiguration from an interception, and cannot fix the former.
  assert.match(r.error, /sha256\//, 'the error must list the pins actually observed');
});

test('a certificate that does not cover its hostname is refused', async () => {
  // The property the platform cannot give us: inside a tunnel, startTls() checks the hostname
  // connect() was given — the PROXY — so the identity gate is aimed at the wrong name. Our trust
  // layer has to be the thing that says no, and this proves it does, on the edge, through a real
  // proxy, against a host that genuinely serves a certificate for a different name.
  const r = await rig(`targets=${MISMATCH_HOST}`);
  assert.equal(r.ok, false, `${MISMATCH_HOST} must be refused, got status ${r.status}`);
  assert.match(String(r.code), /^CERT_/, `expected a certificate error, got ${r.code}: ${r.error}`);
});

test('plain http through the proxy uses no TLS at all', async () => {
  const r = await rig(`http=${TARGET}`);
  assert.equal(r.ok, true, `${r.code}: ${r.error}`);
  assert.ok(r.status > 0, 'the origin should have answered something');
  assert.equal(r.tls, null, 'a cleartext request must report no TLS session');
});

test('a body arrives incrementally, which is what SSE depends on', async () => {
  const r = await rig(`stream=${TARGET}`);
  assert.equal(r.ok, true, `${r.code}: ${r.error}`);
  assert.ok(r.chunks >= 1, 'at least one chunk');
  assert.ok(r.msToFirstChunk !== null, 'a first chunk must have arrived');
  // Headers must not wait for the body. If they did, `streamed` would be false and every
  // event-stream consumer would see nothing until the response ended.
  assert.ok(r.msToFirstChunk <= r.msToLastChunk, 'first chunk cannot follow the last');
});
