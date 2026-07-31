// Live rig: runs the actual package on the Cloudflare edge, through a real proxy, against real
// servers. Token-gated; the proxy comes from a request header so no credential is ever stored in
// the Worker.
//
// This is the only test that can prove the userland TLS stack interoperates. Everything offline
// proves we are self-consistent and match published vectors; only a real server proves we match
// the internet.

import { connect } from 'cloudflare:sockets';
import { Client } from '../../src/client.js';
import { verifyChain, rootStoreProvenance } from '../../src/trust/index.js';
import { openConnection } from '../../src/transport.js';

const enc = new TextEncoder();

async function attempt(label, fn) {
  const t0 = Date.now();
  try {
    const v = await fn();
    return { label, ok: true, ms: Date.now() - t0, ...v };
  } catch (e) {
    return {
      label,
      ok: false,
      ms: Date.now() - t0,
      code: e?.code ?? null,
      name: e?.name ?? null,
      error: e?.message ?? String(e),
      detail: e?.detail ?? null,
    };
  }
}

/** One proxied HTTPS request through the full stack. */
async function httpsThroughProxy({ proxy, url, trust, tls }) {
  const client = new Client({
    connect,
    proxy,
    trust,
    tls,
    forceTunnel: true,
    timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000, idleMs: 20000 },
    maxBodyBytes: 512 * 1024,
  });
  try {
    const res = await client.fetch(url, { headers: { 'user-agent': 'tunnelfetch-live/0' } });
    const body = await res.text();
    return {
      status: res.status,
      httpVersion: res.tunnelfetch?.httpVersion,
      framing: res.tunnelfetch?.framing,
      proxied: res.tunnelfetch?.proxied,
      tls: res.tunnelfetch?.tls
        ? {
            version: `0x${res.tunnelfetch.tls.version.toString(16)}`,
            cipherSuite: `0x${res.tunnelfetch.tls.cipherSuite.toString(16)}`,
            group: `0x${res.tunnelfetch.tls.group.toString(16)}`,
            alpn: res.tunnelfetch.tls.alpnProtocol,
          }
        : null,
      contentType: res.headers.get('content-type'),
      contentEncoding: res.headers.get('content-encoding'),
      bytes: body.length,
      head: body.slice(0, 80).replace(/\s+/g, ' '),
    };
  } finally {
    await client.close();
  }
}

/** Two requests on one Client, to see whether the second reuses the connection. */
async function keepAlive({ proxy, url }) {
  const client = new Client({
    connect,
    proxy,
    forceTunnel: true,
    timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000, idleMs: 20000 },
  });
  try {
    const t0 = Date.now();
    const a = await client.fetch(url);
    await a.text();
    const t1 = Date.now();
    const b = await client.fetch(url);
    await b.text();
    const t2 = Date.now();
    return {
      first: { status: a.status, ms: t1 - t0 },
      second: { status: b.status, ms: t2 - t1 },
      poolHits: client.pool.stats.hits,
      poolMisses: client.pool.stats.misses,
    };
  } finally {
    await client.close();
  }
}

/** A deliberately wrong pin must fail closed, and must fail for the pinning reason. */
async function pinMismatch({ proxy, url }) {
  const client = new Client({
    connect,
    proxy,
    forceTunnel: true,
    trust: { mode: 'pinned', pins: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] },
    timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000 },
  });
  try {
    const res = await client.fetch(url);
    await res.text();
    return { status: res.status, unexpectedlySucceeded: true };
  } finally {
    await client.close();
  }
}

/** Claiming a hostname the certificate does not cover must be refused by our own trust layer. */
async function wrongHostname({ proxy, realHost, claimedHost }) {
  const conn = await openConnection({
    url: `https://${claimedHost}/`,
    connect,
    proxy,
    // The tunnel is opened to the REAL host, but the identity demanded is the claimed one.
    tls: {},
    trust: { mode: 'system' },
  }).catch((e) => {
    throw e;
  });
  await conn.close();
  return { unexpectedlySucceeded: true };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/') {
      return Response.json({ rig: 'tunnelfetch-live', roots: rootStoreProvenance });
    }
    if (!env.PROBE_TOKEN || request.headers.get('x-probe-token') !== env.PROBE_TOKEN) {
      return new Response('forbidden', { status: 403 });
    }
    const spec = request.headers.get('x-proxy');
    if (!spec) return new Response('need x-proxy: host:port:user:pass', { status: 400 });
    const [host, port, user, pass] = spec.split(':');
    const proxy = { protocol: url.searchParams.get('socks') ? 'socks5' : 'http', hostname: host, port: Number(port), username: user, password: pass };

    const targets = (url.searchParams.get('targets') || '').split(',').filter(Boolean);
    const results = [];

    for (const t of targets) {
      results.push(await attempt(`https ${t}`, () => httpsThroughProxy({ proxy, url: `https://${t}/` })));
    }
    if (url.searchParams.get('keepalive')) {
      const t = url.searchParams.get('keepalive');
      results.push(await attempt(`keepalive ${t}`, () => keepAlive({ proxy, url: `https://${t}/` })));
    }
    if (url.searchParams.get('pin')) {
      const t = url.searchParams.get('pin');
      results.push(await attempt(`pin-mismatch ${t}`, () => pinMismatch({ proxy, url: `https://${t}/` })));
    }
    if (url.searchParams.get('http')) {
      const t = url.searchParams.get('http');
      results.push(
        await attempt(`plain http ${t}`, async () => {
          const client = new Client({ connect, proxy, forceTunnel: true });
          try {
            const res = await client.fetch(`http://${t}/`);
            const body = await res.text();
            return { status: res.status, bytes: body.length, tls: res.tunnelfetch?.tls };
          } finally {
            await client.close();
          }
        }),
      );
    }

    return Response.json({
      proxyProtocol: proxy.protocol,
      roots: rootStoreProvenance.anchorCount,
      wallMs: results.reduce((s, r) => s + r.ms, 0),
      results,
    });
  },
};
