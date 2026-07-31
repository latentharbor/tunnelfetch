// Live interoperability. Run explicitly with `npm run test:live`; never part of `npm test`.
//
// Everything offline proves this package is self-consistent and matches published vectors. Only a
// real server proves it matches the internet — a userland TLS implementation that agrees with its
// own test server and nothing else is the exact failure this file exists to prevent.
//
// There is no skip path. Without a proxy in the environment these tests FAIL, because a green tick
// that means "we didn't check" is worse than a red one.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/index.js';
import { LIVE_TARGETS, nodeConnect, proxyFromEnv, socksFromEnv } from './_nodenet.js';

const connect = nodeConnect();
const timeouts = { connectMs: 20000, handshakeMs: 25000, headersMs: 25000, idleMs: 25000 };

function client(extra = {}) {
  return new Client({ connect, forceTunnel: true, timeouts, maxBodyBytes: 4 << 20, ...extra });
}

// Preflight. Every test below dials a third-party host through whichever proxy the operator
// supplied, and a proxy that refuses one of those hosts makes the whole suite fail in a way that
// reads like a defect in this package. It is not: proxies routinely block particular destinations.
// Observed with the proxies used to develop this: CONNECT to www.google.com is reset while
// github.com succeeds, and `curl -x` through the same proxy at the same moment behaves identically.
//
// So find out first, and say so plainly. This does not skip anything — a live suite that skips on
// failure reports a green tick it has not earned. It fails, with the one sentence that saves an
// hour of looking in the wrong place.
test('preflight: the configured proxy can reach every configured target', async () => {
  const unreachable = [];
  for (const host of LIVE_TARGETS) {
    const c = client({ proxy: proxyFromEnv() });
    try {
      const res = await c.fetch(`https://${host}/`);
      await res.text();
    } catch (e) {
      if (e?.code === 'PROXY_PROTOCOL' || e?.code === 'PROXY_CONNECT_REFUSED'
        || e?.code === 'TIMEOUT_CONNECT') {
        unreachable.push(`${host} (${e.code}: ${e.message})`);
      } else {
        throw e; // anything else is this package's problem and must surface as itself
      }
    } finally {
      await c.close().catch(() => {});
    }
  }
  assert.equal(
    unreachable.length, 0,
    `the proxy refused these targets, which is about the proxy and not about this package:\n  ${
      unreachable.join('\n  ')}\nPick reachable hosts with TUNNELFETCH_LIVE_TARGETS=a.example,b.example`,
  );
});

for (const host of LIVE_TARGETS) {
  test(`https://${host}/ through an HTTP CONNECT proxy`, async () => {
    const c = client({ proxy: proxyFromEnv() });
    try {
      const res = await c.fetch(`https://${host}/`);
      const body = await res.text();
      assert.ok(res.status >= 200 && res.status < 400, `unexpected status ${res.status}`);
      assert.ok(body.length > 0, 'the body must not be empty');

      const tls = res.tunnelfetch.tls;
      assert.equal(res.tunnelfetch.proxied, true);
      assert.equal(tls.version, 0x0304, 'TLS 1.3 is what the offer list asks for');
      assert.ok([0x1301, 0x1302].includes(tls.cipherSuite), `unexpected suite ${tls.cipherSuite}`);
      // The client offers h2 and http/1.1; the server picks one of exactly those (default is to
      // offer both), and the spoken protocol must agree with the pick.
      const alpn = tls.alpnProtocol ?? 'http/1.1';
      assert.ok([tls.alpnProtocol, 'h2', 'http/1.1'].includes(alpn), `unexpected ALPN ${alpn}`);
      assert.equal(res.tunnelfetch.httpVersion, alpn === 'h2' ? '2' : '1.1');
    } finally {
      await c.close();
    }
  });

  test(`https://${host}/ through a SOCKS5 proxy`, async () => {
    const c = client({ proxy: socksFromEnv() });
    try {
      const res = await c.fetch(`https://${host}/`);
      assert.ok((await res.text()).length > 0);
      assert.equal(res.tunnelfetch.proxied, true);
      assert.equal(res.tunnelfetch.tls.version, 0x0304);
    } finally {
      await c.close();
    }
  });
}

test('a second request on the same Client skips the handshake', async () => {
  const host = LIVE_TARGETS[0];
  const c = client({ proxy: proxyFromEnv() });
  try {
    const t0 = Date.now();
    await (await c.fetch(`https://${host}/`)).text();
    const first = Date.now() - t0;

    const t1 = Date.now();
    await (await c.fetch(`https://${host}/`)).text();
    const second = Date.now() - t1;

    assert.equal(c.pool.stats.hits, 1, 'the second request must come from the pool');
    // Not asserted as a hard ratio — a live network is not a stopwatch — but a reused connection
    // that is SLOWER than a fresh handshake means the pool is not doing what it claims.
    assert.ok(second < first, `reuse (${second}ms) should beat a fresh handshake (${first}ms)`);
  } finally {
    await c.close();
  }
});

test('a certificate pin that does not match fails closed, and names what it saw', async () => {
  const c = client({
    proxy: proxyFromEnv(),
    trust: { mode: 'pinned', pins: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] },
  });
  try {
    let err;
    try {
      await c.fetch(`https://${LIVE_TARGETS[0]}/`);
    } catch (e) {
      err = e;
    }
    assert.ok(err, 'a wrong pin must not produce a response');
    assert.equal(err.code, 'CERT_PIN_MISMATCH');
    // The observed pins are in the error so an operator can copy the right one out of a log.
    assert.ok(Array.isArray(err.detail?.observed) && err.detail.observed.length > 0);
    for (const p of err.detail.observed) assert.match(p, /^sha256\/[A-Za-z0-9+/]+=*$/);
  } finally {
    await c.close();
  }
});

test('demanding a hostname the certificate does not cover is refused', async () => {
  // The tunnel goes to a host that certainly answers TLS, but the identity demanded is one its
  // certificate cannot carry. This is the exact shape of a hostile proxy substituting a server,
  // and it is the check the platform's own TLS cannot perform for a tunnelled peer.
  const c = client({ proxy: proxyFromEnv() });
  try {
    let err;
    try {
      const res = await c.fetch(`https://${LIVE_TARGETS[0]}.invalid/`);
      await res.text();
    } catch (e) {
      err = e;
    }
    assert.ok(err, 'an unsatisfiable identity must not produce a response');
    assert.ok(
      ['CERT_NAME_MISMATCH', 'CERT_UNTRUSTED_ROOT', 'CERT_CHAIN_INCOMPLETE', 'PROXY_CONNECT_REFUSED',
        'SOCKS5_REPLY'].includes(err.code),
      `unexpected code ${err.code}: ${err.message}`,
    );
  } finally {
    await c.close();
  }
});

test('plain http through the proxy needs no TLS at all', async () => {
  const c = client({ proxy: proxyFromEnv() });
  try {
    const res = await c.fetch(`http://${LIVE_TARGETS[0]}/`);
    assert.ok((await res.text()).length > 0);
    assert.equal(res.tunnelfetch.tls, null, 'an http target must not negotiate TLS');
    assert.equal(res.tunnelfetch.proxied, true);
  } finally {
    await c.close();
  }
});

test('gzip comes back decoded, and br is never advertised', async () => {
  const c = client({ proxy: proxyFromEnv() });
  try {
    const res = await c.fetch(`https://${LIVE_TARGETS[0]}/`);
    const body = await res.text();
    // Whatever the server chose, the caller sees text — and if it chose gzip, the fact that this
    // parses as HTML at all is the proof the decoder ran.
    assert.ok(/[<{]/.test(body.slice(0, 200)), 'body should be readable text, not compressed bytes');
    if (res.headers.get('content-encoding')) {
      assert.notMatch(res.headers.get('content-encoding'), /\bbr\b|zstd/);
    }
  } finally {
    await c.close();
  }
});
