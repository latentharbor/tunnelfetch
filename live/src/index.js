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
import { decodeBody } from '../../src/client/decode.js';
import { DeadlineController, withIdleDeadline } from '../../src/util/deadline.js';
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
    // Which mechanism carried the reuse depends on what ALPN negotiated, and the two look nothing
    // alike from outside: over HTTP/1.1 the second request takes the connection out of the pool
    // (a pool hit), while over HTTP/2 it opens another stream on a connection the pool never sees.
    // Reporting both, plus the ALPN, lets the assertion be about reuse rather than about whichever
    // mechanism happens to apply.
    return {
      first: { status: a.status, ms: t1 - t0, alpn: a.tunnelfetch?.tls?.alpnProtocol ?? null },
      second: { status: b.status, ms: t2 - t1, alpn: b.tunnelfetch?.tls?.alpnProtocol ?? null },
      poolHits: client.pool.stats.hits,
      poolMisses: client.pool.stats.misses,
      // One miss total means exactly one connection was opened for two requests, whichever
      // mechanism carried the second — which is the property worth asserting.
      connectionsOpened: client.pool.stats.misses,
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

/**
 * Claiming a hostname the certificate does not cover must be refused by our own trust layer.
 *
 * NOT REACHABLE as written, and kept only so the next person does not rediscover why: openConnection
 * takes one `url` and derives BOTH the tunnel target and the identity to verify from it, so the two
 * cannot be made to disagree without changing src/ to suit a test rig. Asking for a name nobody
 * serves just makes the proxy answer 502 for a host that does not exist, which tests the proxy.
 * The property is covered instead by fetching a real host whose certificate genuinely does not
 * cover its name — see test/live/edge-interop.live.js and test/live/badssl.live.js.
 */
// eslint-disable-next-line no-unused-vars
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
/** Per-isolate signature keys; see the keygen note in the sigverify op. */
const SIGKEYS = new Map();

/**
 * Body-path fixtures, cached per isolate: `mb` MB of the same highly compressible text the size
 * origin serves, plus its gzip. Building them costs real CPU (the gzip especially), so the cost
 * lands on whichever request builds them — `gz-fixture` exists to take that hit deliberately,
 * and markPath records `fixed` so a contaminated first measurement is visible, not inferred.
 */
const BODYFIX = new Map();

async function bodyFixture(mb) {
  if (BODYFIX.has(mb)) return BODYFIX.get(mb);
  const line = enc.encode('The quick brown fox jumps over the lazy dog 0123456789 abcdef.\n');
  const n = Math.round(mb * 1048576);
  const text = new Uint8Array(n);
  for (let o = 0; o < n; o += line.length) {
    text.set(line.subarray(0, Math.min(line.length, n - o)), o);
  }
  const gz = new Uint8Array(
    await new Response(
      new Response(text).body.pipeThrough(new CompressionStream('gzip')),
    ).arrayBuffer(),
  );
  const fix = { text, gz };
  BODYFIX.set(mb, fix);
  return fix;
}

/** Fail loudly if a decomposition op delivered the wrong byte count: a wrong-size run prices
 *  a failure path, not the operation, and must never be averaged into anything. */
function assertBytes(got, want, what) {
  if (got !== want) throw new Error(`${what}: delivered ${got} bytes, expected ${want}`);
}

/**
 * The PREVIOUS decompressionStage (pipeTo -> WritableStream -> TransformStream), gzip-only
 * copy (sniff and error wrapping dropped; the bench only feeds it valid gzip), kept so old and
 * new can be A/B-ed inside one isolate — comparing across deploys mixes machine-to-machine
 * variance (measured ~2x between sweeps) into the difference.
 */
function oldDecompressionStage(source, coding) {
  const { readable, writable } = new TransformStream();
  (async () => {
    const reader = source.getReader();
    const writer = writable.getWriter();
    try {
      const head = [];
      let headLen = 0;
      while (headLen < 2) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) {
          head.push(value);
          headLen += value.byteLength;
        }
      }
      if (headLen === 0) {
        await writer.close();
        return;
      }
      const ds = new DecompressionStream(coding);
      const pump = ds.readable.pipeTo(
        new WritableStream({ write: (chunk) => writer.write(chunk) }),
      );
      pump.catch(() => {});
      const dsWriter = ds.writable.getWriter();
      for (const chunk of head) await dsWriter.write(chunk);
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) await dsWriter.write(value);
      }
      await dsWriter.close();
      await pump;
      await writer.close();
    } catch (e) {
      await writer.abort(e).catch(() => {});
      await reader.cancel(e).catch(() => {});
    }
  })();
  return readable;
}

/**
 * Wrap the socket factory so the raw socket's readable is observed (mode 'count') or drained
 * with large BYOB reads and re-chunked (mode 'byob') before anything in the stack sees it.
 * The whole real client runs above the wrapper, so the e2e cpuTime difference between modes
 * prices exactly one thing: how many times the socket boundary is crossed per page.
 */
function shapeConnect(realConnect, mode, stats) {
  return (addr, options) => {
    const sock = realConnect(addr, options);
    stats.sockets++;
    const src = sock.readable;
    let reader = null;
    let byob = false;
    const readable = new ReadableStream({
      async pull(c) {
        if (reader === null) {
          if (mode === 'byob') {
            try {
              reader = src.getReader({ mode: 'byob' });
              byob = true;
            } catch (e) {
              stats.byobError = String(e?.message ?? e);
              reader = src.getReader();
            }
          } else {
            reader = src.getReader();
          }
          stats.byob = byob;
        }
        const { value, done } = byob
          ? await reader.read(new Uint8Array(65536))
          : await reader.read();
        if (done) {
          c.close();
          return;
        }
        stats.chunks++;
        stats.bytes += value.byteLength;
        if (value.byteLength < stats.min) stats.min = value.byteLength;
        if (value.byteLength > stats.max) stats.max = value.byteLength;
        c.enqueue(value);
      },
      cancel(reason) {
        return (reader ?? src.getReader()).cancel(reason);
      },
    });
    // Explicit properties rather than a spread: Socket's close/opened live on the prototype.
    return {
      readable,
      writable: sock.writable,
      opened: sock.opened,
      closed: sock.closed,
      close: () => sock.close(),
      startTls: sock.startTls ? (...a) => sock.startTls(...a) : undefined,
    };
  };
}

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
async function cryptoBench(op, n, params = null) {
  const key16 = new Uint8Array(16).fill(7);
  const iv = new Uint8Array(12).fill(9);
  const extra = params?.get?.('alg') ?? null;
  // Body-path decomposition knobs: size in MB and JS-source chunk size in bytes.
  const mb = Number(params?.get?.('mb') ?? 4);
  const ck = Number(params?.get?.('ck') ?? 16384);
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

  if (op === 'sigverify') {
    // Signature verification priced per curve, keygen hoisted out of the loop so differencing two
    // `n` values isolates the verify itself. Worth measuring precisely because chain validation
    // does one of these per link, and a claim that one curve is an order of magnitude slower than
    // another on this runtime is the kind of thing that gets reported upstream — so it should not
    // rest on a single second-hand number.
    const alg = extra || 'p256';
    // Keys are generated once per isolate. RSA-2048 keygen costs 50-400 ms with enormous variance
    // on this runtime, which swamps the differencing entirely — a first attempt at this produced a
    // NEGATIVE marginal cost, which is how the contamination announced itself.
    const cached = SIGKEYS.get(alg);
    let pair; let params; let signParams;
    if (cached) {
      ({ pair, params } = cached); signParams = params;
    } else if (alg === 'rsa2048') {
      pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
      params = { name: 'RSASSA-PKCS1-v1_5' }; signParams = params;
    } else {
      const curve = alg === 'p384' ? 'P-384' : alg === 'p521' ? 'P-521' : 'P-256';
      const hash = curve === 'P-384' ? 'SHA-384' : curve === 'P-521' ? 'SHA-512' : 'SHA-256';
      pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify']);
      params = { name: 'ECDSA', hash }; signParams = params;
    }
    const msg = new Uint8Array(256);
    const sig = cached ? cached.sig : await crypto.subtle.sign(signParams, pair.privateKey, msg);
    if (!cached) SIGKEYS.set(alg, { pair, params, sig });
    for (let i = 0; i < n; i++) {
      // A signature that fails fast would price the rejection path, not verification, so this
      // verifies a genuinely valid pair every time.
      if (!(await crypto.subtle.verify(params, pair.publicKey, sig, msg))) throw new Error('bad sig');
      sink++;
    }
    return { op, alg, n, verified: sink };
  }

  if (op === 'bodytext') {
    // The one per-byte cost the platform's own fetch still bills you for: turning a body into a
    // JS value. Its TLS, HTTP parsing and gunzip all happen in the runtime and never appear in
    // your CPU, so native fetch's total is roughly a fixed ~1 ms plus this. Measuring it here,
    // with no socket involved, is what makes the comparison against our per-MB cost meaningful
    // rather than a comparison of two different things.
    const bytes = new Uint8Array(n * 1024);
    bytes.fill(97);
    sink += (await new Response(bytes).text()).length;
    return { op, n, bytes: sink };
  }

  // ------------------------------------------------------------------ body-path decomposition
  // Where do ~25 ms per MB of body go? Each op below prices ONE slice of the decompressed-side
  // pipeline over identical bytes, so differences between ops attribute cost to a specific layer.
  // Every op asserts the byte count it delivered; a wrong count throws and the run is discarded.

  if (op === 'gz-fixture') {
    // Build (or confirm) the fixture so its cost never lands inside a measured op.
    const fix = await bodyFixture(mb);
    return { op, mb, textBytes: fix.text.byteLength, gzBytes: fix.gz.byteLength };
  }

  if (op === 'native-collect') {
    // Floor: materialise mb MB from a native body with no stream of ours anywhere.
    const fix = await bodyFixture(mb);
    const buf = await new Response(fix.text).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, bytes: buf.byteLength };
  }

  if (op === 'js-collect') {
    // A JS-backed ReadableStream of `ck`-byte subarray chunks, collected natively by Response.
    // Differenced against native-collect this prices the per-chunk JS<->runtime boundary.
    const fix = await bodyFixture(mb);
    const buf = await new Response(fixedSource(fix.text, ck)).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, ck, chunks: Math.ceil(fix.text.byteLength / ck), bytes: buf.byteLength };
  }

  if (op === 'idle-wrap') {
    // Same JS source, wrapped the way the client wraps every raw body. Differenced against
    // js-collect this prices withIdleDeadline: one race()d read, one touch() per chunk.
    const fix = await bodyFixture(mb);
    const dl = new DeadlineController({ idleMs: 60000 }, {});
    const buf = await new Response(withIdleDeadline(fixedSource(fix.text, ck), dl)).arrayBuffer();
    dl.dispose();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, ck, chunks: Math.ceil(fix.text.byteLength / ck), bytes: buf.byteLength };
  }

  if (op === 'gz-native') {
    // Inflate floor: native body -> native DecompressionStream -> native collection.
    const fix = await bodyFixture(mb);
    const buf = await new Response(
      new Response(fix.gz).body.pipeThrough(new DecompressionStream('gzip')),
    ).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, gzBytes: fix.gz.byteLength, bytes: buf.byteLength };
  }

  if (op === 'gz-jsread') {
    // Same inflate, but the decompressed side is drained by a JS reader loop. The report also
    // says how the decompressor chunks its output, which sets the N in every per-chunk cost.
    const fix = await bodyFixture(mb);
    const ds = new DecompressionStream('gzip');
    const pump = new Response(fix.gz).body.pipeTo(ds.writable);
    pump.catch(() => {});
    const r = ds.readable.getReader();
    let bytes = 0;
    let chunks = 0;
    let min = Infinity;
    let max = 0;
    const first = [];
    for (;;) {
      const { value, done } = await r.read();
      if (done) break;
      chunks++;
      bytes += value.byteLength;
      if (value.byteLength < min) min = value.byteLength;
      if (value.byteLength > max) max = value.byteLength;
      if (first.length < 6) first.push(value.byteLength);
    }
    await pump;
    assertBytes(bytes, fix.text.byteLength, op);
    return { op, mb, chunks, min, max, first, bytes };
  }

  if (op === 'gz-byob') {
    // Can the decompressed side be drained in LARGE reads? A BYOB read returns as soon as at
    // least one byte is available, so this cannot add latency — the question is whether the
    // runtime supports it on a DecompressionStream readable, and what it does to chunk count.
    const fix = await bodyFixture(mb);
    const ds = new DecompressionStream('gzip');
    const pump = new Response(fix.gz).body.pipeTo(ds.writable);
    pump.catch(() => {});
    let r;
    try {
      r = ds.readable.getReader({ mode: 'byob' });
    } catch (e) {
      return { op, mb, byob: false, error: String(e?.message ?? e) };
    }
    let bytes = 0;
    let reads = 0;
    let buf = new ArrayBuffer(ck);
    for (;;) {
      const { value, done } = await r.read(new Uint8Array(buf));
      if (done) break;
      reads++;
      bytes += value.byteLength;
      buf = value.buffer;
    }
    await pump;
    assertBytes(bytes, fix.text.byteLength, op);
    return { op, mb, ck, byob: true, reads, bytes };
  }

  if (op === 'gz-byob-partial') {
    // The property a BYOB drain must have before it can sit on a streaming path: a read into a
    // large view must resolve with a PARTIAL fill when the decompressor has some output but the
    // input has stalled — a reader that held out for a full view would add unbounded latency to
    // SSE-shaped bodies. No clocks: the proof is that the read resolves while the tail of the
    // gzip stream is provably unwritten, racing a generous timer only so a failure reports
    // 'stalled' instead of hanging the request.
    const fix = await bodyFixture(mb);
    const gz = fix.gz;
    // A short prefix of the compressed stream, chosen so the decodable output it carries is far
    // smaller than the `ck`-byte view — a full view therefore PROVES the read waited for more
    // input, and a partial one proves it did not. (256 compressed bytes of this fixture decode
    // to at most a few hundred KB; run with ck well above that.)
    const half = gz.subarray(0, Math.min(Number(params?.get?.('hb') ?? 256), gz.byteLength - 8));
    const ds = new DecompressionStream('gzip');
    const w = ds.writable.getWriter();
    let r;
    try {
      r = ds.readable.getReader({ mode: 'byob' });
    } catch (e) {
      return { op, mb, byob: false, error: String(e?.message ?? e) };
    }
    await w.write(half.slice());
    let tailWritten = false;
    const read = r.read(new Uint8Array(ck)).then((res) => ({ kind: 'read', res, tailWritten }));
    const timer = new Promise((resolve) => setTimeout(() => resolve({ kind: 'timeout' }), 3000));
    const firstEvent = await Promise.race([read, timer]);
    if (firstEvent.kind === 'timeout') {
      // Reads block until the view fills: BYOB is NOT streaming-safe on this runtime.
      tailWritten = true;
      await w.write(gz.subarray(half.byteLength).slice());
      await w.close();
      const settled = await read;
      return { op, mb, ck, partial: false, filledOnlyAfterTail: true,
        firstRead: settled.res.value?.byteLength ?? null };
    }
    const firstLen = firstEvent.res.value?.byteLength ?? 0;
    tailWritten = true;
    await w.write(gz.subarray(half.byteLength).slice());
    await w.close();
    let bytes = firstLen;
    let buf = new ArrayBuffer(ck);
    for (;;) {
      const { value, done } = await r.read(new Uint8Array(buf));
      if (done) break;
      bytes += value.byteLength;
      buf = value.buffer;
    }
    assertBytes(bytes, fix.text.byteLength, op);
    return { op, mb, ck, partial: firstLen > 0 && firstLen < ck,
      firstRead: firstLen, viewBytes: ck, tailWasUnwrittenAtFirstRead: !firstEvent.tailWritten,
      bytes };
  }

  if (op === 'gz-stage-old' || op === 'gz-stage-old-text') {
    const fix = await bodyFixture(mb);
    const out = oldDecompressionStage(new Response(fix.gz).body, 'gzip');
    if (op === 'gz-stage-old-text') {
      const s = await new Response(out).text();
      assertBytes(s.length, fix.text.byteLength, op);
      return { op, mb, bytes: s.length };
    }
    const buf = await new Response(out).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, bytes: buf.byteLength };
  }

  if (op === 'gz-stage' || op === 'gz-stage-text') {
    // The package's actual decode stage (decodeBody -> decompressionStage), fed and collected
    // exactly the way client.js feeds and Response collects it. gz-stage-text adds .text().
    const fix = await bodyFixture(mb);
    const out = decodeBody(new Response(fix.gz).body, 'gzip');
    if (op === 'gz-stage-text') {
      const s = await new Response(out).text();
      assertBytes(s.length, fix.text.byteLength, op); // ASCII: one code unit per byte
      return { op, mb, bytes: s.length };
    }
    const buf = await new Response(out).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, bytes: buf.byteLength };
  }

  if (op === 'codecs') {
    // Which content codings can this runtime actually decode? The package has been declining to
    // advertise brotli on the belief that DecompressionStream does not offer it — a belief that
    // was never tested here, and the whole point of this rig is that beliefs about the runtime
    // get tested. A constructor that does not throw proves nothing on its own, so each codec is
    // driven through a real round trip where one is possible.
    const out = {};
    for (const fmt of ['gzip', 'deflate', 'deflate-raw', 'br', 'brotli', 'zstd']) {
      try {
        const ds = new DecompressionStream(fmt);
        out[fmt] = { constructs: true, roundTrip: null };
        try {
          const cs = new CompressionStream(fmt);
          const w = cs.writable.getWriter();
          await w.write(new TextEncoder().encode('round trip me'));
          await w.close();
          const packed = await new Response(cs.readable).arrayBuffer();
          const back = await new Response(
            new Response(packed).body.pipeThrough(new DecompressionStream(fmt))).text();
          out[fmt].roundTrip = back === 'round trip me' ? 'ok' : `wrong: ${back.slice(0, 20)}`;
          out[fmt].packedBytes = packed.byteLength;
        } catch (e) {
          // Decompression can exist without the matching compressor; that is still usable for us,
          // since a server does the compressing.
          out[fmt].roundTrip = `no compressor: ${e?.message ?? e}`;
        }
        try { await ds.readable.cancel(); } catch { /* nothing to release */ }
      } catch (e) {
        out[fmt] = { constructs: false, error: String(e?.message ?? e).slice(0, 90) };
      }
    }
    return { op, codecs: out };
  }

  if (op === 'noop') return { op, n, bytes: 0 }; // fixed request cost, to subtract off

  return { op, error: 'unknown op' };
}

/**
 * Does a pooled socket survive from one invocation to the next?
 *
 * The pool's own header asserts it cannot — "I/O objects do not cross request contexts" — and the
 * whole design follows from that: per-Client pools, reuse only within a single invocation. But the
 * claim is not measured anywhere, and it decides something expensive. If a socket DOES survive,
 * a Client held at module scope makes every request after the first cost ~0.9 ms instead of the
 * ~9-12 ms a fresh connection costs, which is a larger win than everything else measured so far.
 *
 * So: one Client, built once per isolate, driven by successive HTTP invocations. The pool's own
 * hit/miss counters say whether the second invocation reused, and reading a real body says whether
 * the reused socket actually works rather than merely being handed back.
 */
let SHARED = null;
let SHARED_KEY = null;
let SHARED_SEQ = 0;

async function crossRequestPool({ proxy, url }) {
  const key = `${proxy.hostname}:${proxy.port}|${url}`;
  if (SHARED_KEY !== key) {
    if (SHARED) await SHARED.close().catch(() => {});
    SHARED = new Client({
      connect, proxy, forceTunnel: true,
      timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000, idleMs: 20000 },
    });
    SHARED_KEY = key;
    SHARED_SEQ = 0;
  }
  const invocation = ++SHARED_SEQ;
  const before = { ...SHARED.pool.stats };
  try {
    const res = await SHARED.fetch(url);
    const body = await res.text();
    return {
      invocation,
      status: res.status,
      bytes: body.length,
      // A hit here means this invocation reused a socket opened by an EARLIER invocation.
      hitsThisCall: SHARED.pool.stats.hits - before.hits,
      missesThisCall: SHARED.pool.stats.misses - before.misses,
      idleAfter: SHARED.pool.idleCount,
      reusedAcrossInvocations: invocation > 1 && SHARED.pool.stats.hits > before.hits,
    };
  } catch (e) {
    return { invocation, failed: true, code: e?.code ?? null, error: String(e?.message ?? e) };
  }
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
      // `prebuilt`/`fixed` are per-isolate, so whether this request paid for a fixture matters
      // to the reading and must be recorded before the work, not inferred after it.
      markPath(op, {
        prebuilt: Boolean(prebuilt.plain || prebuilt.chunked),
        fixed: [...BODYFIX.keys()].join('+') || null,
        mb: url.searchParams.get('mb') ?? null,
        ck: url.searchParams.get('ck') ?? null,
      });
      return Response.json(await cryptoBench(op, n, url.searchParams));
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
    if (url.searchParams.get('sizes')) {
      // The cost table. One Client per call so each measurement includes a full connection
      // (handshake + trust + request + body), which is the honest per-page cost for a crawler
      // that reaches a new origin; `reuse=N` then measures N pages down ONE connection, which is
      // what the same crawler pays for pages 2..N of the same host.
      const spec = url.searchParams.get('sizes');
      const origin = url.searchParams.get('origin');
      const reuse = Number(url.searchParams.get('reuse') ?? 1);
      const enc = url.searchParams.get('enc') ?? '';
      // dc=0 turns content decoding off; ae=gzip still asks the wire for gzip, so the pair
      // separates "receive compressed bytes" from "decompress them" in the end-to-end number.
      const dc = url.searchParams.get('dc') !== '0';
      const ae = url.searchParams.get('ae') ?? '';
      // sockshape=count observes how the raw socket chunks its delivery; sockshape=byob
      // re-chunks it through 64 KiB BYOB reads. The difference prices socket boundary crossings.
      const sockshape = url.searchParams.get('sockshape') ?? '';
      // h1=1 forces the client to offer only http/1.1, so the SAME origin can be measured over
      // both protocols and the cpuTime difference is attributable to h2's extra work (HPACK,
      // framing) rather than to any change in origin or bytes.
      const h2 = !url.searchParams.get('h1');
      const sockStats = { sockets: 0, chunks: 0, bytes: 0, min: Infinity, max: 0, byob: null };
      const connectFn = sockshape ? shapeConnect(connect, sockshape, sockStats) : connect;
      results.push(await attempt(`sizes ${spec}`, async () => {
        const client = new Client({
          connect: connectFn, proxy, forceTunnel: true, maxBodyBytes: 16 << 20, decompress: dc,
          http2: h2,
          timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000, idleMs: 20000 },
        });
        try {
          const out = [];
          for (const n of spec.split(',').map(Number)) {
            for (let i = 0; i < reuse; i++) {
              const q = `?n=${n}${enc ? `&enc=${enc}` : ''}&i=${i}`;
              const res = await client.fetch(`https://${origin}/${q}`, {
                headers: ae ? { 'accept-encoding': ae } : {},
              });
              const body = await res.text();
              out.push({ n, got: body.length, status: res.status,
                enc: res.headers.get('content-encoding'),
                proto: res.tunnelfetch?.httpVersion,
                framing: res.tunnelfetch?.framing });
            }
          }
          // With decoding on and no wire compression trickery, every page must deliver exactly
          // n bytes of 200 body — a short or non-200 page prices a failure, not a fetch.
          const okPages = out.filter((p) => p.status === 200 && (dc ? p.got === p.n : p.got > 0)).length;
          return { pages: out.length, okPages, proto: out[0]?.proto,
            hits: client.pool.stats.hits, misses: client.pool.stats.misses,
            sample: out[0],
            ...(sockshape ? { sock: { ...sockStats,
              min: Number.isFinite(sockStats.min) ? sockStats.min : null } } : {}) };
        } finally {
          await client.close();
        }
      }));
    }
    if (url.searchParams.get('native')) {
      // The platform's own fetch against the same origin and the same sizes, so the cost table has
      // something to be compared against. Not a like-for-like comparison and it must not be
      // presented as one: native fetch cannot traverse a proxy, so this measures "the cheapest
      // possible way to get these bytes" against "through a tunnel we terminate ourselves". The
      // gap is implementation AND proxy hop together, which is exactly the decision a caller makes
      // when native fetch would have sufficed.
      const spec = url.searchParams.get('native');
      const origin = url.searchParams.get('origin');
      const reps = Number(url.searchParams.get('reuse') ?? 1);
      results.push(await attempt(`native ${spec}`, async () => {
        const out = [];
        for (const n of spec.split(',').map(Number)) {
          for (let i = 0; i < reps; i++) {
            const res = await fetch(`https://${origin}/?n=${n}&i=${i}`, { cf: { cacheTtl: 0 } });
            const body = await res.text();
            // A short body means the fetch did not reach the origin. Recording the status and a
            // preview is what turned an apparent 100x win into a discovery that the request was
            // being short-circuited and never transferred anything.
            out.push({ n, got: body.length, status: res.status,
              enc: res.headers.get('content-encoding'),
              head: body.length < 200 ? body.slice(0, 120) : undefined });
          }
        }
        return { pages: out.length, sample: out[0] };
      }));
    }
    if (url.searchParams.get('direct')) {
      // No proxy at all: our own TLS stack straight down a socket the Worker opened itself. If this
      // works, most interop properties can be checked on the edge without any proxy credential —
      // only the CONNECT and SOCKS5 tunnelling tests actually need one.
      const t = url.searchParams.get('direct');
      results.push(await attempt(`direct ${t}`, async () => {
        const client = new Client({ connect, forceTunnel: true, maxBodyBytes: 1 << 20,
          timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000 } });
        try {
          const res = await client.fetch(`https://${t}/`);
          const body = await res.text();
          return { status: res.status, bytes: body.length, proxied: res.tunnelfetch?.proxied,
            tls: res.tunnelfetch?.tls ? { version: `0x${res.tunnelfetch.tls.version.toString(16)}` } : null };
        } finally { await client.close(); }
      }));
    }
    if (url.searchParams.get('reach')) {
      // Do real sites actually refuse or challenge an HTTP/1.1 client with this TLS fingerprint?
      // The question behind it is whether HTTP/2 is worth implementing, and that is an empirical
      // question, not an architectural one. A challenge announces itself: Cloudflare answers 403
      // with `cf-mitigated: challenge` and an interstitial, others send 403/429 with a body that
      // does not look like the site. Recording the status, the mitigation header and a slice of
      // the body distinguishes "refused us" from "served us fine" from "the proxy could not get
      // there at all", which are three different answers.
      const hosts = url.searchParams.get('reach').split(',').filter(Boolean);
      // h1=1 offers only http/1.1, so the SAME site can be probed on both protocols to see whether
      // h2 changes the outcome — the whole empirical question behind implementing it.
      const reachH2 = !url.searchParams.get('h1');
      results.push(await attempt(`reach ${hosts.length} hosts`, async () => {
        const client = new Client({
          connect, proxy, forceTunnel: true, maxBodyBytes: 512 * 1024, http2: reachH2,
          timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 20000, idleMs: 20000 },
        });
        const out = [];
        try {
          for (const h of hosts) {
            try {
              const res = await client.fetch(`https://${h}/`, {
                headers: {
                  // A plausible browser UA, because sending an obviously-automated one would test
                  // the UA string rather than the protocol and fingerprint.
                  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                    + '(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                  'accept-language': 'en-US,en;q=0.9',
                },
              });
              const body = await res.text();
              out.push({
                host: h,
                status: res.status,
                mitigated: res.headers.get('cf-mitigated'),
                server: res.headers.get('server'),
                bytes: body.length,
                challenge: /just a moment|checking your browser|captcha|cf-chl|attention required/i
                  .test(body.slice(0, 4000)),
                alpn: res.tunnelfetch?.tls?.alpnProtocol ?? null,
                proto: res.tunnelfetch?.httpVersion ?? null,
              });
            } catch (e) {
              out.push({ host: h, failed: true, code: e?.code ?? null,
                error: String(e?.message ?? e).slice(0, 90) });
            }
          }
        } finally {
          await client.close();
        }
        return { hosts: out };
      }));
    }
    if (url.searchParams.get('poolx')) {
      const t = url.searchParams.get('poolx');
      results.push(await attempt(`poolx ${t}`, () => crossRequestPool({ proxy, url: `https://${t}/` })));
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
