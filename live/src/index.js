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
import { RecordLayer } from '../../src/tls/record.js';
import { decodeChunked } from '../../src/http1/chunked.js';
import { ByteReader } from '../../src/util/bytes.js';
import { parseCertificate } from '../../src/trust/x509.js';
import { BENCH_CHAIN, BENCH_ANCHOR, BENCH_HOSTNAME } from './bench-chain.js';

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

/**
 * Does a body actually arrive incrementally over a real socket, through a real proxy, with our
 * own TLS record layer in the path? Offline tests prove the stack does not buffer; this proves the
 * production path does not either, which is the property SSE depends on.
 *
 * Date.now() is frozen during synchronous execution on this runtime but advances across I/O, and
 * a stream read IS I/O — so the gaps between chunk timestamps are real.
 */
async function streamShape({ proxy, url }) {
  const client = new Client({
    connect,
    proxy,
    forceTunnel: true,
    timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000, idleMs: 20000 },
    maxBodyBytes: 8 << 20,
    decompress: false, // measure what the socket delivered, not what the decoder emitted
  });
  try {
    const t0 = Date.now();
    const res = await client.fetch(url);
    const headersAt = Date.now();
    const reader = res.body.getReader();
    let chunks = 0;
    let bytes = 0;
    let firstChunkAt = null;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      if (firstChunkAt === null) firstChunkAt = Date.now();
      chunks++;
      bytes += value.byteLength;
    }
    const doneAt = Date.now();
    return {
      status: res.status,
      chunks,
      bytes,
      msToHeaders: headersAt - t0,
      msToFirstChunk: firstChunkAt === null ? null : firstChunkAt - t0,
      msToLastChunk: doneAt - t0,
      // If the body were buffered whole before the caller saw anything, first and last would
      // coincide and `chunks` would be 1.
      streamed: chunks > 1 && doneAt - firstChunkAt > 0,
    };
  } finally {
    await client.close();
  }
}

// Attribution needs to know which isolate ran a request and how many times that isolate has taken
// this particular code path — V8 tiers up per function, so "first time this isolate reached this
// path" is the axis that matters, and it is not the same axis as "first request after a deploy".
// Requests scatter across isolates, so a run of measurements silently mixes fresh and tiered ones
// unless each event says which it was. These are counters, not clocks: nothing here is timed
// in-Worker, because Date.now() does not advance during synchronous execution on this runtime.
let ISOLATE = null;
let REQ_SEQ = 0;
const PATH_COUNT = new Map();

function markPath(path, extra = {}) {
  ISOLATE ??= crypto.randomUUID().slice(0, 8);
  const nth = (PATH_COUNT.get(path) ?? 0) + 1;
  PATH_COUNT.set(path, nth);
  // Emitted as a log line so it lands in the same `wrangler tail` event as this request's cpuTime.
  console.log(JSON.stringify({ iso: ISOLATE, path, nth, req: ++REQ_SEQ, ...extra }));
}

function fixedSource(bytes, chunkSize) {
  let off = 0;
  return new ReadableStream({
    pull(c) {
      if (off >= bytes.length) return c.close();
      const end = Math.min(off + chunkSize, bytes.length);
      c.enqueue(bytes.subarray(off, end));
      off = end;
    },
  });
}
const nullSink = () => new WritableStream({ write() {} });

function chunkEncode(payload, chunkSize) {
  const parts = [];
  for (let o = 0; o < payload.length; o += chunkSize) {
    const n = Math.min(chunkSize, payload.length - o);
    parts.push(enc.encode(`${n.toString(16)}\r\n`), payload.subarray(o, o + n), enc.encode('\r\n'));
  }
  parts.push(enc.encode('0\r\n\r\n'));
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// TLS 1.3 record of a full-size fragment: 5 header + 16384 plaintext + 1 content type + 16 tag.
const RECORD_LEN = 16406;
const MAX_RECORDS = 512;
/** Ciphertext is built once per isolate and sliced per request, so the encrypt side — which is
 *  setup, not the thing under test — never lands inside a measured request after the first. */
const prebuilt = { plain: null, chunked: null };

async function prebuild(which, key16, iv) {
  if (prebuilt[which]) return prebuilt[which];
  const payload = new Uint8Array(MAX_RECORDS * 16384);
  prebuilt[which] = await buildRecords(
    which === 'chunked' ? chunkEncode(payload, 8192) : payload, key16, iv);
  return prebuilt[which];
}

/** Encrypt `payload` into TLS 1.3 application_data records, the way a server would frame it. */
async function buildRecords(payload, key16, iv) {
  const chunks = [];
  const rl = new RecordLayer(
    { readable: new ReadableStream({ start: (c) => c.close() }),
      writable: new WritableStream({ write: (c) => { chunks.push(c); } }) },
    {},
  );
  rl.setVersion(0x0304);
  await rl.setSendKeys({ cipher: 0x1301, key: key16, iv, secret: new Uint8Array(32) });
  for (let o = 0; o < payload.length; o += 16384) {
    await rl.writeAppData(payload.subarray(o, Math.min(o + 16384, payload.length)));
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/**
 * Pure-compute WebCrypto micro-benchmark, for deciding where the receive path's CPU actually
 * goes on this runtime.
 *
 * It deliberately reports no timings of its own. `Date.now()` does not advance during synchronous
 * execution here (measured: 0 ms delta on the edge where a local workerd showed 12 ms), so any
 * number this Worker computed about itself would be fiction. The real measurement is the CPU time
 * `wrangler tail` reports, differenced across two runs with different `n` — that isolates the
 * marginal cost of one operation from the fixed cost of the request.
 */
async function cryptoBench(op, n) {
  const key16 = new Uint8Array(16).fill(7);
  const iv = new Uint8Array(12).fill(9);
  let sink = 0;

  if (op === 'aead-records') {
    // n separate 16 KiB decrypts: exactly the shape TLS forces on us, since RFC 8446 s5.1 caps
    // a record's plaintext at 2^14. If per-call overhead dominates, this is where it shows.
    const k = await crypto.subtle.importKey('raw', key16, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const aad = new Uint8Array([23, 3, 3, 0x40, 0x10]);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, new Uint8Array(16384));
    for (let i = 0; i < n; i++) {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, k, ct);
      sink += pt.byteLength;
    }
    return { op, n, bytes: sink };
  }

  if (op === 'stack' || op === 'stack-chunked') {
    // The whole userland receive path over n records of pre-built ciphertext, with no socket
    // involved. Differencing this against aead-records at the same n isolates OUR plumbing from
    // the AEAD floor, on the runtime that actually bills us — the same split the offline Node
    // bench makes, but without assuming Node and workerd share a cost model.
    const chunked = op === 'stack-chunked';
    const full = await prebuild(chunked ? 'chunked' : 'plain', key16, iv);
    const ct = full.subarray(0, Math.min(n, MAX_RECORDS) * RECORD_LEN);
    const rl = new RecordLayer(
      { readable: fixedSource(ct, 65536), writable: nullSink() },
      {},
    );
    rl.setVersion(0x0304);
    await rl.setReceiveKeys({ cipher: 0x1301, key: key16, iv, secret: new Uint8Array(32) });
    rl.markHandshakeComplete();
    let src = rl.plaintextDuplex().readable;
    if (chunked) src = decodeChunked(new ByteReader(src), {}).stream;
    const rd = src.getReader();
    try {
      for (;;) {
        const { done, value } = await rd.read();
        if (done) break;
        sink += value.length;
      }
    } catch {
      // Expected: we feed a deliberate prefix of the record stream, so it ends without
      // close_notify and the record layer calls that truncation — correctly. The bytes were
      // still processed, which is the only thing being timed here.
    }
    return { op, n, bytes: sink };
  }

  if (op === 'hkdf') {
    // The key schedule runs a fixed number of these per handshake; this prices one.
    const k = await crypto.subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveBits']);
    for (let i = 0; i < n; i++) {
      sink += (await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new Uint8Array(8) },
        k, 256)).byteLength;
    }
    return { op, n, bytes: sink };
  }

  if (op === 'x25519') {
    for (let i = 0; i < n; i++) {
      const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      sink += (await crypto.subtle.deriveBits({ name: 'X25519', public: pair.publicKey },
        pair.privateKey, 256)).byteLength;
    }
    return { op, n, bytes: sink };
  }

  if (op === 'ecdsa-verify') {
    // Chain verification does one of these per certificate, plus one for CertificateVerify.
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const msg = new Uint8Array(128);
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, msg);
    for (let i = 0; i < n; i++) {
      sink += (await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, sig, msg)) ? 1 : 0;
    }
    return { op, n, verified: sink };
  }

  if (op === 'rsa-verify') {
    const pair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256' }, true, ['sign', 'verify']);
    const msg = new Uint8Array(128);
    const sig = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, pair.privateKey, msg);
    for (let i = 0; i < n; i++) {
      sink += (await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, pair.publicKey, sig, msg)) ? 1 : 0;
    }
    return { op, n, verified: sink };
  }

  if (op === 'cert-parse') {
    // DER parsing alone, no signature checks. The handshake's certificate work splits into this
    // and the verification below; measuring them apart says which one to attack.
    for (let i = 0; i < n; i++) for (const der of BENCH_CHAIN) sink += parseCertificate(der).tbsBytes.length;
    return { op, n, bytes: sink };
  }

  if (op === 'chain-verify') {
    // Everything a handshake does with certificates: parse, build the path, check names and
    // validity, verify every signature. Against a pinned anchor, so no network and no root-store
    // lookup skews the number.
    for (let i = 0; i < n; i++) {
      await verifyChain({ chain: BENCH_CHAIN, hostname: BENCH_HOSTNAME,
        trust: { mode: 'anchors', anchors: [BENCH_ANCHOR] } });
      sink++;
    }
    return { op, n, verified: sink };
  }

  if (op === 'noop') return { op, n, bytes: 0 }; // fixed request cost, to subtract off

  return { op, error: 'unknown op' };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/') {
      return Response.json({ rig: 'tunnelfetch-live', roots: rootStoreProvenance });
    }
    if (url.pathname === '/crypto-bench') {
      if (!env.PROBE_TOKEN || request.headers.get('x-probe-token') !== env.PROBE_TOKEN) {
        return new Response('forbidden', { status: 403 });
      }
      const op = url.searchParams.get('op') ?? 'noop';
      const n = Number(url.searchParams.get('n') ?? 1);
      // `prebuilt` is per-isolate, so whether this request paid for the fixture matters to the
      // reading and must be recorded before the work, not inferred after it.
      markPath(op, { prebuilt: Boolean(prebuilt.plain || prebuilt.chunked) });
      return Response.json(await cryptoBench(op, n));
    }
    if (!env.PROBE_TOKEN || request.headers.get('x-probe-token') !== env.PROBE_TOKEN) {
      return new Response('forbidden', { status: 403 });
    }
    const spec = request.headers.get('x-proxy');
    if (!spec) return new Response('need x-proxy: host:port:user:pass', { status: 400 });
    const [host, port, user, pass] = spec.split(':');
    const proxy = { protocol: url.searchParams.get('socks') ? 'socks5' : 'http', hostname: host, port: Number(port), username: user, password: pass };

    markPath('run');
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
    if (url.searchParams.get('stream')) {
      const t = url.searchParams.get('stream');
      results.push(await attempt(`stream ${t}`, () => streamShape({ proxy, url: `https://${t}/` })));
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
