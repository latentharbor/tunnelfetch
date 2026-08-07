// Live rig: runs the actual package on the Cloudflare edge, through a real proxy, against real
// servers. Token-gated; the proxy comes from a request header so no credential is ever stored in
// the Worker.
//
// This is the only test that can prove the userland TLS stack interoperates. Everything offline
// proves we are self-consistent and match published vectors; only a real server proves we match
// the internet.

import { connect } from 'cloudflare:sockets';
import { CORPUS } from './corpus.js';
import { Client } from '../../src/client.js';
import { verifyChain, rootStoreProvenance } from '../../src/trust/index.js';
import { openConnection } from '../../src/transport.js';
import { RecordLayer } from '../../src/tls/record.js';
import { decodeChunked } from '../../src/http1/chunked.js';
import { ByteReader } from '../../src/util/bytes.js';
import { parseCertificate } from '../../src/trust/x509.js';
import { decodeBody } from '../../src/client/decode.js';
// Bundled at build time, not compiled at runtime: workerd refuses WebAssembly.instantiate() on
// bytes with "Wasm code generation disallowed by embedder". Any Wasm TLS would face the same
// rule — it must ship inside the script, and therefore counts against the Worker's size limit.
import WASMBYTES from './wasmbytes.wasm';
import EMCCBYTES from './emccbytes.wasm';
import CLANGBYTES from './clangbytes.wasm';
import { Http2Connection } from '../../src/http2/connection.js';
import { settingsFrame, headersFrame, dataFrame, windowUpdateFrame } from '../../src/http2/frames.js';
import { encodeHeaderBlock } from '../../src/http2/hpack.js';

import { chrome as chromeProfile } from '../../src/profile/chrome.js';
import { DeadlineController, withIdleDeadline } from '../../src/util/deadline.js';
import { BENCH_CHAIN, BENCH_ANCHOR, BENCH_HOSTNAME } from './bench-chain.js';
import { RAW_BYTES, BR, BR11, GZ, ZSTD } from './codec-fixture.js';
import { gunzipSync } from 'fflate';
// These two used to be imported by ABSOLUTE PATH out of a `.claude/worktrees/agent-…` directory —
// gitignored, machine-specific and transient — which meant the instrument that produced this
// README's codec figures could not be loaded from a clean checkout of the repository that quotes
// them. The files are byte-identical to the ones the package ships (verified by sha256), so this
// now imports those: one less copy, and the rig measures the decoder that actually ships.
import { zstd as zstdFree } from '../../src/profile/vendor/zstd-dec.js';
import { chacha20poly1305 as chachaWasm } from '../../src/profile/vendor/chacha20poly1305.js';
import { emccChacha } from './emcc-chacha.js';
import { br as brotliFree } from '../../src/profile/vendor/brotli-dec.js';
import brotliJs from 'brotli/decompress.js';
import { ungzip as pakoUngzip } from 'pako';
import brotliWasm from 'brotli-dec-wasm/web/bg.wasm';
import { initSync as brotliInit, decompress as brotliDecompress, BrotliDecStream, BrotliStreamResultCode } from 'brotli-dec-wasm/web';

// Instantiated at MODULE SCOPE, which is the whole question: WASM instantiation is a one-time cost
// and this runtime does not bill startup CPU, so if the expensive part of Brotli were the module
// coming up, it would be free here. What that cannot move is the decompression itself, which is
// per-request and per-byte — and that is what the benchmark below actually measures.
brotliInit({ module: brotliWasm });

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

/** Brotli as a streaming BodyDecoder, backed by the module-scope WASM instance. */
function brotliDecoder(stream) {
  const dec = new BrotliDecStream();
  return stream.pipeThrough(
    new TransformStream({
      transform(chunk, c) {
        let res = dec.dec(chunk, 1 << 20);
        if (res.buf.length) c.enqueue(res.buf);
        while (res.code === BrotliStreamResultCode.NeedsMoreOutput) {
          res = dec.dec(new Uint8Array(0), 1 << 20);
          if (res.buf.length) c.enqueue(res.buf);
        }
      },
    }),
  );
}

async function brThroughProxy({ proxy, url }) {
  const client = new Client({
    proxy,
    connect,
    decoders: { br: brotliDecoder },
    timeouts: { connectMs: 10000, handshakeMs: 15000, headersMs: 20000, idleMs: 20000 },
  });
  try {
    const res = await client.fetch(url, { headers: { 'user-agent': 'tunnelfetch-live' } });
    const body = await res.text();
    return {
      status: res.status,
      contentEncoding: res.headers.get('content-encoding'),
      httpVersion: res.tunnelfetch.httpVersion,
      decodedBytes: body.length,
      // If the decoder silently produced nothing, or produced compressed bytes, this is the tell.
      looksLikeHtml: /<html|<!doctype/i.test(body.slice(0, 2000)),
      head: body.slice(0, 80),
    };
  } finally {
    await client.close();
  }
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
let WASM_MOD = null;

async function bodyFixture(mb, src = 'real') {
  const cacheKey = `${src}:${mb}`;
  if (BODYFIX.has(cacheKey)) return BODYFIX.get(cacheKey);
  // `real` is the SAME 154 KiB of minified JavaScript the size origin serves, so a decomposition
  // measured here is differencing against the same bytes the end-to-end sweep timed. `line` is the
  // old fixture — a 63-byte phrase tiled — kept ONLY so the two can be compared inside one isolate.
  //
  // They are not interchangeable and the difference is not small. `line` compresses ~200:1, so its
  // gzip stream is a handful of long matches: inflating it is nearly free and the wire side costs
  // nothing. Real content is 2.76:1 and mostly literals. Any per-byte figure taken on `line` is a
  // floor for a body no origin will ever send.
  const period = src === 'line'
    ? enc.encode('The quick brown fox jumps over the lazy dog 0123456789 abcdef.\n')
    : CORPUS;
  const n = Math.round(mb * 1048576);
  const text = new Uint8Array(n);
  for (let o = 0; o < n; o += period.length) {
    text.set(period.subarray(0, Math.min(period.length, n - o)), o);
  }
  const gz = new Uint8Array(
    await new Response(
      new Response(text).body.pipeThrough(new CompressionStream('gzip')),
    ).arrayBuffer(),
  );
  const fix = { text, gz, src };
  BODYFIX.set(cacheKey, fix);
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
  // Which corpus the body fixtures use. It CHANGES every per-byte number, so it is a
  // discriminating field and must reach markPath — grouping two corpora into one bucket
  // is the same omission that has already spoiled two sweeps.
  const src = params?.get?.('src') ?? 'real';
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


  if (op === 'h2-recv' || op === 'h2-recv-idle') {
    // The HTTP/2 receive layer, priced on its own.
    //
    // The decomposition had a hole: the record layer is ~4 ms for a 4 MB body's worth of records
    // and the decode stage is ~49 ms, which leaves most of a 118 ms page unattributed. Everything
    // between them — frame parsing, flow control, the per-DATA `recvQueue.push(data.slice())`, and
    // the body stream's pull — had never been measured, because doing it needs a real
    // Http2Connection fed real frames rather than a probe that stands in for one.
    //
    // So: a genuine Http2Connection over a plain duplex, fed a prebuilt server flight (SETTINGS,
    // response HEADERS, then DATA frames of `fsz` bytes each), with its body drained and NOT
    // decoded. No TLS, because the record layer is already priced separately and stacking them
    // would just re-measure it. h2-recv-idle adds withIdleDeadline, which the client wraps every
    // body in, so the difference prices that wrapper on this path rather than on a synthetic one.
    const wire = Math.round(mb * 1048576);          // bytes of body to deliver
    const fsz = Number(params?.get?.('fsz') ?? 16384); // DATA frame size
    const idle = op === 'h2-recv-idle';

    const ab = new TransformStream();
    const ba = new TransformStream();
    const client = { readable: ba.readable, writable: ab.writable };
    const server = { readable: ab.readable, writable: ba.writable };

    const conn = new Http2Connection(client, {});
    const w = server.writable.getWriter();
    // Drain what the client writes (preface, SETTINGS, WINDOW_UPDATEs) so it never blocks.
    (async () => { const r = server.readable.getReader();
      for (;;) { const { done } = await r.read(); if (done) break; } })().catch(() => {});

    await w.write(settingsFrame([[3, 100], [4, 65536], [2, 0]]));
    const req = conn.request({ method: 'GET', scheme: 'https', authority: 'o.example',
                               path: '/', headers: [] });
    req.catch(() => {});
    await w.write(headersFrame(1, encodeHeaderBlock([{ name: ':status', value: '200' }]), {
      endStream: false, endHeaders: true }));
    const head = await req;

    const chunk = new Uint8Array(fsz);
    const pump = (async () => {
      let sent = 0;
      while (sent < wire) {
        const n = Math.min(fsz, wire - sent);
        sent += n;
        // The peer must be allowed to keep sending: this prices the RECEIVE path, not flow
        // control back-pressure, so the window is reopened generously from the server side.
        await w.write(dataFrame(1, chunk.subarray(0, n), sent >= wire));
        await w.write(windowUpdateFrame(0, n));
        await w.write(windowUpdateFrame(1, n));
      }
    })();
    pump.catch(() => {});

    let src = head.body;
    if (idle) { const dl = new DeadlineController({ idleMs: 60000 }, {});
                src = withIdleDeadline(src, dl); }
    if (params?.get?.('via') === 'identity') {
      // Route the h2 body through Cloudflare's native IdentityTransformStream. The shipped path
      // copies every DATA payload (`recvQueue.push(data.slice())`) into a JS array and dequeues it
      // on pull; if the bytes can live in the runtime instead, that copy and that queue go away.
      // This does not remove the copy — the connection still makes it — so it measures only the
      // downstream half, which is the part a redesign could actually reach.
      const t = new IdentityTransformStream();
      src.pipeTo(t.writable).catch(() => {});
      src = t.readable;
    }
    const rd = src.getReader();
    let got = 0;
    for (;;) { const { done, value } = await rd.read(); if (done) break; got += value.byteLength; }
    await pump.catch(() => {});
    assertBytes(got, wire, op);
    await conn.close().catch(() => {});
    return { op, mb, fsz, frames: Math.ceil(wire / fsz), bytes: got };
  }


  if (op === 'gz-nativepipe') {
    // Can the decode stage get JS out of the byte path entirely?
    //
    // The shipped stage reads every chunk in JS: it has to, because `maxBodyBytes` is enforced on
    // DECODED output and counting requires seeing bytes. This prices the alternative — sniff the
    // two bytes the deflate/empty check needs, then hand the REST to a native pipe and return the
    // decompressor's own readable, so no JS callback runs per chunk.
    //
    //   variant=pipe    sniff 2 bytes, native pipeTo for the rest, return ds.readable
    //   variant=hop     same, but ds.readable piped natively into a TransformStream first — what a
    //                   synchronous-return API contract would actually force
    //   variant=stage   the shipped decodeBody, for the same isolate and the same fixture
    const variant = params?.get?.('variant') ?? 'pipe';
    const fix = await bodyFixture(mb, src);
    const source = fixedSource(fix.gz, Number(params?.get?.('ick') ?? 65536));

    if (variant === 'stage') {
      const buf = await new Response(decodeBody(source, 'gzip')).arrayBuffer();
      assertBytes(buf.byteLength, fix.text.byteLength, op);
      return { op, mb, variant, bytes: buf.byteLength };
    }

    const rdr = source.getReader();
    const head = [];
    let headLen = 0;
    while (headLen < 2) {
      const { value, done } = await rdr.read();
      if (done) break;
      if (value?.byteLength) { head.push(value); headLen += value.byteLength; }
    }
    const ds = new DecompressionStream('gzip');
    // The remainder never touches JS again: releaseLock hands the source back so pipeTo can run
    // inside the runtime.
    const w = ds.writable.getWriter();
    for (const c of head) await w.write(c);
    w.releaseLock();
    const rest = new ReadableStream({
      start(c) { for (const _ of []) c.enqueue(_); },
      async pull(c) {
        const { value, done } = await rdr.read();
        if (done) { c.close(); return; }
        c.enqueue(value);
      },
    });
    const pump = rest.pipeTo(ds.writable);
    pump.catch(() => {});

    let out = ds.readable;
    if (variant === 'hop') {
      // An identity TransformStream, which is the obvious way to satisfy a synchronous return.
      const t = new TransformStream();
      out.pipeTo(t.writable).catch(() => {});
      out = t.readable;
    } else if (variant === 'hop-hwm') {
      // Same, but with a queue deep enough that the decompressor's 4 KiB chunks do not each wait
      // on backpressure. If chunk GRANULARITY is what makes `hop` slow, this moves.
      const t = new TransformStream({}, { highWaterMark: 64 }, { highWaterMark: 64 });
      out.pipeTo(t.writable).catch(() => {});
      out = t.readable;
    } else if (variant === 'hop-identity') {
      // Cloudflare's own IdentityTransformStream: byte-oriented, and its readable half supports
      // BYOB reads. The standard `new TransformStream()` is JS-backed and passes every 4 KiB
      // decompressor chunk through its queue individually, which is why `hop` costs MORE than the
      // wrapper it was meant to replace. If this one is native, a synchronous return costs nothing.
      const t = new IdentityTransformStream();
      out.pipeTo(t.writable).catch(() => {});
      out = t.readable;
    } else if (variant === 'hop-identity-byob') {
      // Same, drained with 16 KiB BYOB reads rather than handed to Response — the shape a caller
      // who wants chunks (rather than .arrayBuffer()) would actually see.
      const t = new IdentityTransformStream();
      out.pipeTo(t.writable).catch(() => {});
      const rr = t.readable.getReader({ mode: 'byob' });
      let n = 0;
      for (;;) {
        const { value, done } = await rr.read(new Uint8Array(16384));
        if (done) break;
        n += value.byteLength;
      }
      await pump.catch(() => {});
      assertBytes(n, fix.text.byteLength, op);
      return { op, mb, variant, bytes: n };
    } else if (variant === 'byob-nocount') {
      // The shipped stage's SHAPE — a pull-driven wrapper doing 16 KiB BYOB reads — with the
      // counting and the error wrapping removed. Differencing this against `stage` says whether
      // the cost is the wrapper or the bookkeeping inside it, which decides whether there is
      // anything to optimise short of changing the return contract.
      const rr = ds.readable.getReader({ mode: 'byob' });
      out = new ReadableStream({
        async pull(c) {
          for (;;) {
            const { value, done } = await rr.read(new Uint8Array(16384));
            if (done) { c.close(); return; }
            if (value.byteLength === 0) continue;
            c.enqueue(value);
            return;
          }
        },
      });
    }
    const buf = await new Response(out).arrayBuffer();
    await pump.catch(() => {});
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, variant, bytes: buf.byteLength };
  }


  if (op === 'slice-cost') {
    // What the h2 receive path pays for `recvQueue.push(data.slice())`: one copy of every DATA
    // payload. Priced on its own so the decision to remove a defensive copy from security-critical
    // framing code is made against a number rather than a feeling.
    const bytes = Math.round(mb * 1048576);
    const chunk = Math.round(Number(params?.get?.('fsz') ?? 16384));
    const src2 = new Uint8Array(bytes);
    const keep = [];
    for (let o = 0; o < bytes; o += chunk) {
      const view = src2.subarray(o, Math.min(o + chunk, bytes));
      keep.push(params?.get?.('copy') === '0' ? view : view.slice());
    }
    let n = 0;
    for (const k of keep) n += k.byteLength;
    assertBytes(n, bytes, op);
    return { op, mb, chunk, copies: keep.length, bytes: n };
  }

  if (op === 'plaintext-shape') {
    // The record layer hands its plaintext up as `new ReadableStream({ pull })` at highWaterMark 0.
    // That is a JS layer in the byte path, and replacing a JS layer is the shape that won for the
    // decode stage. `identity` pushes the same chunks through Cloudflare's native relay instead.
    // Not a drop-in: highWaterMark 0 is deliberate (an eager pull parks a socket read on every
    // connection before a request is written), so this measures whether the prize is worth
    // redesigning back-pressure for.
    const bytes = Math.round(mb * 1048576);
    const chunk = Math.round(Number(params?.get?.('fsz') ?? 16384));
    const shape = params?.get?.('shape') ?? 'js';
    const total = Math.ceil(bytes / chunk);
    let sent = 0;
    let out;
    if (shape === 'identity') {
      const t = new IdentityTransformStream();
      out = t.readable;
      (async () => {
        const w = t.writable.getWriter();
        while (sent < total) { sent++; await w.write(new Uint8Array(chunk)); }
        await w.close();
      })().catch(() => {});
    } else {
      out = new ReadableStream({
        async pull(c) {
          if (sent >= total) { c.close(); return; }
          sent++;
          c.enqueue(new Uint8Array(chunk));
        },
      }, { highWaterMark: 0 });
    }
    const rd = out.getReader();
    let got = 0;
    for (;;) { const { done, value } = await rd.read(); if (done) break; got += value.byteLength; }
    return { op, mb, shape, chunks: total, bytes: got };
  }


  if (op === 'native-decode-probe') {
    // Does the runtime decode a Content-Encoding on a Response we construct ourselves? If it does,
    // the whole decode stage could be C++ with no JS in the byte path at all. Probing rather than
    // reading docs, because what matters is what workerd does, not what the spec allows.
    const fix = await bodyFixture(1, 'real');
    const out = {};
    const tryIt = async (name, fn) => {
      try {
        const n = await fn();
        out[name] = n === fix.text.byteLength ? `DECODED (${n})`
          : n === fix.gz.byteLength ? `passthrough (${n}, still gzip)` : `other (${n})`;
      } catch (e) { out[name] = 'threw: ' + String(e?.message ?? e).slice(0, 90); }
    };
    await tryIt('Response + content-encoding', async () =>
      (await new Response(fix.gz, { headers: { 'content-encoding': 'gzip' } }).arrayBuffer()).byteLength);
    await tryIt('Response + encodeBody:manual', async () =>
      (await new Response(fix.gz, { headers: { 'content-encoding': 'gzip' }, encodeBody: 'manual' }).arrayBuffer()).byteLength);
    await tryIt('Response + encodeBody:automatic', async () =>
      (await new Response(fix.gz, { headers: { 'content-encoding': 'gzip' }, encodeBody: 'automatic' }).arrayBuffer()).byteLength);
    // A Request is the other side of the same machinery.
    await tryIt('Request + content-encoding', async () =>
      (await new Request('https://x/', { method: 'POST', body: fix.gz,
        headers: { 'content-encoding': 'gzip' } }).arrayBuffer()).byteLength);
    out.plain = (await new Response(fix.gz).arrayBuffer()).byteLength;
    out.expectDecoded = fix.text.byteLength;
    out.expectGzip = fix.gz.byteLength;
    return { op, ...out };
  }


  if (op === 'zlib-probe') {
    // node:zlib is a C++ binding in workerd, not a polyfill, and gunzipSync takes maxOutputLength —
    // a size cap enforced INSIDE the native call. If that works it falsifies the reasoning in
    // src/client/decode.js, which says a cap and a JS-free byte path are mutually exclusive because
    // counting needs the bytes in JavaScript. Counting in C++ is a third option I did not know about.
    //
    // The trade it asks for is real: gunzipSync is synchronous and buffering, so it needs the whole
    // coded body in memory and gives up streaming. That is only acceptable for a caller who was
    // going to buffer anyway — .text() or .arrayBuffer() on the whole thing.
    const fix = await bodyFixture(mb, src);
    const variant = params?.get?.('variant') ?? 'sync';
    const cap = Number(params?.get?.('cap') ?? 0) || Infinity;
    const zlib = await import('node:zlib');
    const z = zlib.default ?? zlib;
    if (variant === 'probe') {
      return { op, has: Object.keys(z).filter((k) => /gunzip|inflate|createGunzip/.test(k)).join(','),
               typeofSync: typeof z.gunzipSync };
    }
    if (variant === 'sync') {
      const out = z.gunzipSync(fix.gz, Number.isFinite(cap) ? { maxOutputLength: cap } : undefined);
      assertBytes(out.byteLength ?? out.length, fix.text.byteLength, op);
      return { op, mb, variant, cap: String(cap), bytes: out.byteLength ?? out.length };
    }
    if (variant === 'sync-text') {
      const out = z.gunzipSync(fix.gz, Number.isFinite(cap) ? { maxOutputLength: cap } : undefined);
      const t = new TextDecoder().decode(out);
      assertBytes(t.length, fix.text.byteLength, op);
      return { op, mb, variant, bytes: t.length };
    }
    if (variant === 'capfail') {
      // Does maxOutputLength actually REFUSE, or is it advisory? A cap that does not fire is worse
      // than no cap, because it reads as protection.
      try {
        z.gunzipSync(fix.gz, { maxOutputLength: 1024 });
        return { op, variant, result: 'NO ERROR — the cap did not fire' };
      } catch (e) { return { op, variant, result: 'refused: ' + String(e?.message ?? e).slice(0, 90) }; }
    }
    return { op, error: 'unknown variant' };
  }


  if (op === 'race-cost') {
    // The per-chunk cost of DeadlineController.race, both ways, in one isolate.
    //
    // The old shape registered and unregistered an abort listener on every call — invisible across
    // the few dozen chunks of a 4 MB body, and the dominant per-event cost on an SSE stream where a
    // single completion is a hundred thousand chunks of a few hundred bytes. The new shape creates
    // one rejecting promise for the controller's lifetime and races against it.
    const n = Math.max(1, Number(params?.get?.('n') ?? 20000));
    const variant = params?.get?.('variant') ?? 'shared';
    const ac = new AbortController();
    const sig = ac.signal;
    let shared = null;
    const sharedP = () => {
      if (!shared) {
        shared = new Promise((_, rej) => sig.addEventListener('abort', () => rej(sig.reason), { once: true }));
        shared.catch(() => {});
      }
      return shared;
    };
    let sink = 0;
    for (let i = 0; i < n; i++) {
      const p = Promise.resolve(i);
      let v;
      if (variant === 'listener') {
        // the old race(), verbatim in shape
        v = await new Promise((resolve, reject) => {
          const onAbort = () => reject(sig.reason);
          sig.addEventListener('abort', onAbort, { once: true });
          p.then((x) => { sig.removeEventListener('abort', onAbort); resolve(x); },
                 (e) => { sig.removeEventListener('abort', onAbort); reject(e); });
        });
      } else if (variant === 'shared') {
        v = await Promise.race([p, sharedP()]);
      } else {
        v = await p;   // floor: the await itself, no deadline machinery at all
      }
      sink += v & 1;
    }
    return { op, n, variant, sink };
  }


  if (op === 'wasm-boundary') {
    // What does a megabyte cost to cross into Wasm and be touched there, against the code in the
    // record layer it would replace? Moving TLS into Wasm removes the JS record parsing but ADDS
    // this boundary, and a native layer only wins when it REPLACES a JavaScript one. If the
    // boundary alone costs more than what it would replace, the idea is dead before anything is
    // compiled — which is where the `wire` ladder below left it: the TLS record layer adds
    // 2.7-3.0 ms per wire MB over the raw socket, of which WebCrypto AES-GCM is 1.67, so the
    // JavaScript record parsing is about 1.0-1.3 ms/MB and `frames` here costs more than that.
    //
    //   variant=fill    build the fixture and stop; every other variant contains this
    //   variant=js      fill, then traverse in JavaScript
    //   variant=copy    fill, then allocate in linear memory and copy the bytes in; no traversal
    //   variant=wasm    fill, copy in, then traverse inside Wasm
    //   variant=frames  fill, copy in, then walk TLS-record-shaped headers inside Wasm
    //
    // `tool` picks which toolchain compiled the module under test. Cloudflare's Kitesurf post
    // argues against Emscripten — "its many layers of mocked dependencies, the compiled binary can
    // get bulky and slow" — and that is a claim about a toolchain, cheap to check rather than
    // repeat. All three modules implement byte-identical `alloc`/`sum`/`frame_walk`:
    //
    //   tool=rust    Rust, wasm32-unknown-unknown, no_std             632 bytes
    //   tool=emcc    C, Emscripten -O3 -sSTANDALONE_WASM               460 bytes
    //   tool=clang   C, clang --target=wasm32 -nostdlib + rust-lld     647 bytes
    //
    // Built by live/wasm/build.sh from live/wasm/bench.{c,rs}. All three fix a 16 MiB arena, so
    // `mb` above 16 would run off the end of linear memory in every one of them.
    const tool = params?.get?.('tool') ?? 'rust';
    const mod = tool === 'emcc' ? EMCCBYTES : tool === 'clang' ? CLANGBYTES : WASMBYTES;
    WASM_MOD ??= {};
    WASM_MOD[tool] ??= new WebAssembly.Instance(mod, {});
    const ex = WASM_MOD[tool].exports;
    const bytes = Math.round(mb * 1048576);
    if (bytes > (16 << 20)) throw new Error(`wasm-boundary mb=${mb} exceeds the 16 MiB arena`);
    const variant = params?.get?.('variant') ?? 'wasm';
    const src2 = new Uint8Array(bytes);
    // Every byte, and pseudo-random: a buffer of zeroes makes the traversal's arithmetic collapse
    // (acc*31+0 stays 0 forever) and lets a compiler on either side skip work a real record layer
    // cannot skip. The first attempt wrote `i & 0xff` every 4096 bytes, which is zero at every
    // multiple of 4096 — the buffer stayed entirely zero and the sum came back 0.
    for (let i = 0; i < bytes; i++) src2[i] = (i * 2654435761) >>> 24;

    // Building the fixture is a per-byte JS loop and it is inside EVERY variant, including this
    // one. Quoting `js` or `frames` without subtracting it prices the fixture as if it were the
    // thing under test — so `variant=fill` returns having done nothing else, and every other
    // reading is only meaningful net of it.
    if (variant === 'fill') return { op, mb, variant, tool: 'none', first: src2[0] };

    if (variant === 'js') {
      let acc = 0;
      for (let i = 0; i < bytes; i++) acc = (Math.imul(acc, 31) + src2[i]) >>> 0;
      return { op, mb, variant, tool: 'js', acc };
    }
    // `n` splits the transfer into that many crossings. One big copy is not the shape a TLS record
    // layer has: a 1.45 MB body is ~93 records of 16 KiB, and the AEAD almost certainly has to stay
    // in JavaScript because crypto.subtle reaches AES-NI and a software AES inside Wasm does not.
    // So the real question is not what one crossing costs, it is what NINETY-THREE cost.
    const n = Math.max(1, Number(params?.get?.('n') ?? 1));
    if (n > 1) {
      // One allocation for the whole transfer, then a view per crossing. Calling alloc() inside the
      // loop was the earlier shape and it is not comparable across toolchains: the Rust module's
      // alloc replaces a Vec (a real allocation every crossing) while the C modules hand back a
      // fixed arena, so the loop would have been timing allocator policy, not the boundary.
      const base = ex.alloc(bytes);
      const per = Math.ceil(bytes / n);
      let acc = 0;
      for (let i = 0; i < n; i++) {
        const len = Math.min(per, bytes - i * per);
        if (len <= 0) break;
        const p2 = base + i * per;
        new Uint8Array(ex.memory.buffer, p2, len).set(src2.subarray(i * per, i * per + len));
        if (variant !== 'copy') acc = (acc + ex.frame_walk(p2, len)) >>> 0;
        // Read the result back out, as a record layer must to hand plaintext onward.
        if (variant === 'roundtrip') {
          const out = new Uint8Array(len);
          out.set(new Uint8Array(ex.memory.buffer, p2, len));
          acc = (acc + out[0]) >>> 0;
        }
      }
      return { op, mb, variant, tool, n, acc };
    }
    const ptr = ex.alloc(bytes);
    new Uint8Array(ex.memory.buffer, ptr, bytes).set(src2);
    if (variant === 'copy') return { op, mb, variant, tool, ptr };
    if (variant === 'frames') return { op, mb, variant, tool, records: ex.frame_walk(ptr, bytes) };
    return { op, mb, variant, tool, acc: ex.sum(ptr, bytes) >>> 0 };
  }

  if (op === 'gz-fixture') {
    // Build (or confirm) the fixture so its cost never lands inside a measured op.
    const fix = await bodyFixture(mb, src);
    return { op, mb, textBytes: fix.text.byteLength, gzBytes: fix.gz.byteLength };
  }

  if (op === 'native-collect') {
    // Floor: materialise mb MB from a native body with no stream of ours anywhere.
    const fix = await bodyFixture(mb, src);
    const buf = await new Response(fix.text).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, bytes: buf.byteLength };
  }

  if (op === 'js-collect') {
    // A JS-backed ReadableStream of `ck`-byte subarray chunks, collected natively by Response.
    // Differenced against native-collect this prices the per-chunk JS<->runtime boundary.
    const fix = await bodyFixture(mb, src);
    const buf = await new Response(fixedSource(fix.text, ck)).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, ck, chunks: Math.ceil(fix.text.byteLength / ck), bytes: buf.byteLength };
  }

  if (op === 'idle-wrap') {
    // Same JS source, wrapped the way the client wraps every raw body. Differenced against
    // js-collect this prices withIdleDeadline: one race()d read, one touch() per chunk.
    const fix = await bodyFixture(mb, src);
    const dl = new DeadlineController({ idleMs: 60000 }, {});
    const buf = await new Response(withIdleDeadline(fixedSource(fix.text, ck), dl)).arrayBuffer();
    dl.dispose();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, ck, chunks: Math.ceil(fix.text.byteLength / ck), bytes: buf.byteLength };
  }

  if (op === 'gz-native') {
    // Inflate floor: native body -> native DecompressionStream -> native collection.
    const fix = await bodyFixture(mb, src);
    const buf = await new Response(
      new Response(fix.gz).body.pipeThrough(new DecompressionStream('gzip')),
    ).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, gzBytes: fix.gz.byteLength, bytes: buf.byteLength };
  }

  if (op === 'gz-jsread') {
    // Same inflate, but the decompressed side is drained by a JS reader loop. The report also
    // says how the decompressor chunks its output, which sets the N in every per-chunk cost.
    const fix = await bodyFixture(mb, src);
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
    const fix = await bodyFixture(mb, src);
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

  if (op === 'gz-byob-alloc') {
    // gz-byob, but allocating a FRESH view per read instead of recycling the returned buffer —
    // which is what src/client/decode.js actually does. The two differ by exactly one line, and
    // if a BYOB read resolves on partial fill (it does, by design: gz-byob-partial proves it)
    // then the shipped stage allocates one `ck`-byte buffer per OUTPUT CHUNK, not per view-full.
    // At the runtime's 4 KiB output chunking and a 64 KiB view that is 16x the body in throwaway
    // buffers. Differencing this against gz-byob at the same ck prices that allocation alone.
    const fix = await bodyFixture(mb, src);
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
    let short = 0; // reads that came back with less than the view: the coalescing that did NOT happen
    for (;;) {
      const { value, done } = await r.read(new Uint8Array(ck));
      if (done) break;
      reads++;
      if (value.byteLength < ck) short++;
      bytes += value.byteLength;
    }
    await pump;
    assertBytes(bytes, fix.text.byteLength, op);
    return { op, mb, ck, byob: true, reads, short, allocBytes: reads * ck, bytes };
  }

  if (op === 'gz-stagex') {
    // A faithful replica of src/client/decode.js's wiring — JS input pump, pull-driven BYOB output
    // — instrumented to report how many reads it takes and how many came back SHORT.
    //
    // This exists because gz-byob answered a different question than the one that matters. It fed
    // the decompressor with a native pipeTo, which runs ahead, so every 64 KiB read found 64 KiB
    // waiting and returned full: 16 reads per MB. The shipped stage pumps input from a JS task on
    // the same event loop as the puller, so the decompressor may hold only one 4 KiB output chunk
    // when the read arrives — and a BYOB read resolves on partial fill BY DESIGN (that property is
    // what keeps an SSE body from stalling; gz-byob-partial proves it). Same code path, 16x the
    // reads, and a fresh 64 KiB view allocated for each one.
    //
    // variant=asis      allocate a new view per read, as shipped
    // variant=recycle   reuse the returned buffer; identical delivery, identical partial-fill
    //                   semantics, no allocation churn
    const variant = params?.get?.('variant') ?? 'asis';
    // The BYOB view size, swept rather than assumed: fills average ~11 KiB in this wiring, so the
    // shipped 64 KiB is mostly allocation that is never used.
    const view = Number(params?.get?.('view') ?? 65536);
    const fix = await bodyFixture(mb, src);
    // Candidate wirings for the real decompressionStage, fed by a JS ReadableStream (fixedSource) —
    // NOT a native Response body. This is the whole point: the product's source is always a JS
    // stream (readResponseBody -> withIdleDeadline), and a native-body pipeTo "runs ahead" and
    // measures a different program (the trap the brief names). `ick` sets the input chunk size.
    //   input:  jspump = JS pump loop | jspipe = source.pipeTo(ds.writable)
    //   output: native (hand ds.readable to Response) | byob (BYOB `view` drain + count) |
    //           cap (counting TransformStream)
    // variant = <input>-<output>, e.g. jspipe-native, jspump-native, jspipe-byob, jspipe-cap.
    if (variant.includes('-')) {
      const ick = Number(params?.get?.('ick') ?? 65536);
      const [inMode, outMode] = variant.split('-');
      const source = fixedSource(fix.gz, ick);
      const ds = new DecompressionStream('gzip');
      if (inMode === 'jspipe') {
        source.pipeTo(ds.writable).catch(() => {});
      } else {
        const rdr = source.getReader();
        const w = ds.writable.getWriter();
        (async () => {
          for (;;) { const { value, done } = await rdr.read(); if (done) break; if (value?.byteLength) await w.write(value); }
          await w.close();
        })().catch(() => {});
      }
      let produced = 0;
      const maxBytes = 16 << 20; // finite but not tripped by 4 MB; prices the counting only
      let out;
      if (outMode === 'native') {
        out = ds.readable;
      } else if (outMode === 'cap') {
        out = ds.readable.pipeThrough(new TransformStream({
          transform(chunk, c) { produced += chunk.byteLength; if (produced > maxBytes) throw new Error('cap'); c.enqueue(chunk); },
        }));
      } else { // byob: coarse BYOB drain that counts per read (few, large reads when input runs ahead)
        const r = ds.readable.getReader({ mode: 'byob' });
        out = new ReadableStream({
          async pull(c) {
            const { value, done } = await r.read(new Uint8Array(view));
            if (done) { c.close(); return; }
            if (value.byteLength === 0) return;
            produced += value.byteLength;
            if (produced > maxBytes) { c.error(new Error('cap')); return; }
            c.enqueue(value);
          },
        });
      }
      const buf2 = await new Response(out).arrayBuffer();
      assertBytes(buf2.byteLength, fix.text.byteLength, op);
      return { op, mb, variant, view, ick, bytes: buf2.byteLength };
    }
    const source = new Response(fix.gz).body;
    const srcReader = source.getReader();
    const ds = new DecompressionStream('gzip');
    const dsWriter = ds.writable.getWriter();
    const pump = (async () => {
      for (;;) {
        const { value, done } = await srcReader.read();
        if (done) break;
        if (value?.byteLength) await dsWriter.write(value);
      }
      await dsWriter.close();
    })();
    pump.catch(() => {});
    const useDefault = variant === 'default';
    const out = useDefault ? null : ds.readable.getReader({ mode: 'byob' });
    const outDefault = useDefault ? ds.readable.getReader() : null;
    let reads = 0, short = 0, bytes = 0, inChunks = 0;
    let buf = new ArrayBuffer(view);
    const stream = new ReadableStream({
      async pull(c) {
        for (;;) {
          // default: no BYOB at all — the runtime hands us its own buffer, so zero allocation,
          // at the cost of its own 4 KiB output chunking. small: a view sized near the fill that
          // actually arrives (measured ~11 KiB) rather than 64 KiB that never fills.
          const { value, done } = variant === 'default'
            ? await outDefault.read()
            : await out.read(
                variant === 'recycle' ? new Uint8Array(buf)
                : new Uint8Array(view));
          if (done) { await pump; c.close(); return; }
          if (value.byteLength === 0) continue;
          reads++;
          if (value.byteLength < view) short++;
          if (variant === 'recycle') buf = value.buffer;
          bytes += value.byteLength;
          c.enqueue(variant === 'recycle' ? value.slice() : value);
          return;
        }
      },
    });
    const buf2 = await new Response(stream).arrayBuffer();
    assertBytes(buf2.byteLength, fix.text.byteLength, op);
    return { op, mb, variant, reads, short, inChunks, view, allocBytes: variant === 'recycle' ? view : variant === 'default' ? 0 : reads * view, bytes: buf2.byteLength };
  }

  if (op === 'gz-byob-partial') {
    // The property a BYOB drain must have before it can sit on a streaming path: a read into a
    // large view must resolve with a PARTIAL fill when the decompressor has some output but the
    // input has stalled — a reader that held out for a full view would add unbounded latency to
    // SSE-shaped bodies. No clocks: the proof is that the read resolves while the tail of the
    // gzip stream is provably unwritten, racing a generous timer only so a failure reports
    // 'stalled' instead of hanging the request.
    const fix = await bodyFixture(mb, src);
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
    const fix = await bodyFixture(mb, src);
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
    const fix = await bodyFixture(mb, src);
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

  if (op === 'gz-stage-js' || op === 'gz-stage-js-text') {
    // decodeBody fed a JS ReadableStream (fixedSource) — the FAITHFUL input, since the product's
    // source is always a JS stream, never a native body. `cap` (bytes; 0 = Infinity) exercises the
    // maxBytes path; `ick` is the input chunk size. This is the honest before/after for src changes.
    const fix = await bodyFixture(mb, src);
    const ick = Number(params?.get?.('ick') ?? 65536);
    const capRaw = Number(params?.get?.('cap') ?? 0);
    const maxBytes = capRaw > 0 ? capRaw : Infinity;
    // `cap` is the whole point of this op now: a finite cap is what the shipped default sets, and a
    // finite cap is what disqualifies the native IdentityTransformStream relay in decode.js. The
    // two readings differ by more than anything else measured in the body path.
    const out = decodeBody(fixedSource(fix.gz, ick), 'gzip', null, maxBytes);
    if (op === 'gz-stage-js-text') {
      const s = await new Response(out).text();
      assertBytes(s.length, fix.text.byteLength, op);
      return { op, mb, ick, cap: capRaw, bytes: s.length };
    }
    const buf = await new Response(out).arrayBuffer();
    assertBytes(buf.byteLength, fix.text.byteLength, op);
    return { op, mb, ick, cap: capRaw, bytes: buf.byteLength };
  }

  if (op === 'gz-trunc-safety') {
    // Does the runtime's DecompressionStream FAIL CLOSED on a truncated/corrupt gzip when drained
    // natively (pipeThrough + Response), or silently yield a partial body? This is the safety
    // precondition for any "native-collect" decode path: if it fails open here, native collection
    // would deliver a truncated body as if complete — unacceptable — and the JS BYOB drain that
    // wraps errors must stay. Node fails closed (throws); this checks workerd, which need not agree.
    const fix = await bodyFixture(1, src);
    const enc2 = new TextEncoder();
    const cases = {
      truncated: fix.gz.subarray(0, fix.gz.byteLength - 8), // drop CRC32+ISIZE trailer
      garbage: enc2.encode('this is definitely not gzip at all'),
      empty: new Uint8Array(0), // zero-byte body: browsers/decodeBody yield empty, not an error
      full: fix.gz,
    };
    const out = {};
    for (const [name, wire] of Object.entries(cases)) {
      try {
        const got = (await new Response(
          new Response(wire.slice()).body.pipeThrough(new DecompressionStream('gzip')),
        ).arrayBuffer()).byteLength;
        // For `empty`, NO error means native pipe yields empty — the only case where a native
        // collect could skip the head-read; an error means the empty-body check (and its async
        // return, and thus the per-chunk wrapper) is structurally required.
        out[name] = { errored: false, bytes: got,
          complete: name === 'full' ? got === fix.text.byteLength : name === 'empty' ? got === 0 : null,
          verdict: name === 'full' ? 'ok'
            : name === 'empty' ? (got === 0 ? 'yields empty -> native could skip head-read'
                                            : 'unexpected non-empty')
            : 'FAILS OPEN (yielded a partial body silently)' };
      } catch (e) {
        out[name] = { errored: true, error: e?.constructor?.name ?? String(e),
          verdict: name === 'empty' ? 'errors on empty -> head-read + async return REQUIRED'
                                    : 'fails closed' };
      }
    }
    return { op, cases: out };
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

  if (op === 'zstd-freestanding' || op === 'brotli-npm-stream-wrapped' || op === 'brotli-freestanding' || op === 'brotli-wasm' || op === 'brotli-wasm-stream' || op === 'brotli-q11-stream' ||
      op === 'gzip-native' || op === 'inflate-js' || op === 'inflate-pako' || op === 'brotli-js') {
    // Same payload, same decompressed size, one codec each. Differencing two `n` values gives the
    // marginal cost of one decode, which is the number that decides whether `br` can be afforded
    // on a runtime that bills CPU rather than bytes.
    for (let i = 0; i < n; i++) {
      if (op === 'zstd-freestanding') {
        // zstd has no native path either. Same stream shape as the brotli comparison, so the three
        // codecs are measured identically.
        sink += (await new Response(zstdFree(new Response(ZSTD).body)).arrayBuffer()).byteLength;
      } else if (op === 'brotli-npm-stream-wrapped') {
        // The npm package behind the SAME stream->stream shape the freestanding build exposes, so
        // the comparison is decoder against decoder rather than one decoder against the other's
        // wrapper.
        const wrapped = (src) => {
          const dec = new BrotliDecStream();
          return src.pipeThrough(new TransformStream({
            transform(chunk, c) {
              let r = dec.dec(chunk, 1 << 20);
              if (r.buf.length) c.enqueue(r.buf);
              while (r.code === BrotliStreamResultCode.NeedsMoreOutput) {
                r = dec.dec(new Uint8Array(0), 1 << 20);
                if (r.buf.length) c.enqueue(r.buf);
              }
            },
          }));
        };
        sink += (await new Response(wrapped(new Response(BR).body)).arrayBuffer()).byteLength;
      } else if (op === 'brotli-freestanding') {
        // The freestanding decode-only build, measured in the SAME run as the npm package it
        // claims to beat 3x. Cross-run comparisons have been wrong here before.
        sink += (await new Response(brotliFree(new Response(BR).body)).arrayBuffer()).byteLength;
      } else if (op === 'brotli-js') {
        // The controlled comparison the earlier run lacked: the SAME algorithm as brotli-wasm, in
        // pure JavaScript. WASM-brotli beating JS-inflate proved nothing about WASM, because those
        // are different algorithms. This pair differs in one variable only.
        sink += brotliJs(BR).length;
      } else if (op === 'inflate-pako') {
        // A second JS inflate, so "JS inflate is slow" is a property of the approach rather than
        // of one library's code.
        sink += pakoUngzip(GZ).length;
      } else if (op === 'inflate-js') {
        // A NON-NATIVE inflate, same algorithm as the native path. This separates two costs that
        // the brotli-vs-gzip comparison folds together: how much of the gap is Brotli's decoder
        // being heavier per output byte, and how much is simply not being the runtime's own C++.
        sink += gunzipSync(GZ).length;
      } else if (op === 'brotli-q11-stream' || op === 'brotli-wasm-stream') {
        // How a body actually arrives: in chunks, decoded incrementally. The one-shot op above
        // flatters Brotli by comparing it against a gzip path that pays stream overhead, so this
        // is the figure that belongs in any honest comparison.
        // q11 is 16% smaller than q5 for identical output — if harder compression made decoding
        // cheaper, this is where it would show.
        const src = op === 'brotli-q11-stream' ? BR11 : BR;
        const dec = new BrotliDecStream();
        const CHUNK = 16384;
        for (let o = 0; o < src.length; o += CHUNK) {
          const part = src.subarray(o, Math.min(o + CHUNK, src.length));
          let res = dec.dec(part, 1 << 20);
          sink += res.buf.length;
          // NeedsMoreOutput means this chunk produced more than the output budget: pump the same
          // input until it stops asking, or bytes are silently dropped.
          while (res.code === BrotliStreamResultCode.NeedsMoreOutput) {
            res = dec.dec(new Uint8Array(0), 1 << 20);
            sink += res.buf.length;
          }
        }
      } else if (op === 'brotli-wasm') {
        sink += brotliDecompress(BR).length;
      } else {
        const out = await new Response(
          new Response(GZ).body.pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
        sink += out.byteLength;
      }
    }
    // Asserting the output size means a decoder that silently produced nothing cannot look fast.
    if (sink !== RAW_BYTES * n) throw new Error(`decoded ${sink}, expected ${RAW_BYTES * n}`);
    return { op, n, bytes: sink, perDecode: RAW_BYTES };
  }

  if (op === 'aead-wasm-chacha' || op === 'aead-webcrypto-aes') {
    // The AEAD the package actually ships for ChaCha20 — the bundled WASM, not node:crypto — against
    // the WebCrypto AES-256 it would replace. Same 16 KiB records, same run.
    const RECORD = 16384;
    const records = Math.max(1, Math.round((n * 1048576) / RECORD));
    const plain = new Uint8Array(RECORD);
    const key = new Uint8Array(32).fill(7);
    const iv = new Uint8Array(12);
    if (op === 'aead-wasm-chacha') {
      const aad = new Uint8Array(5);
      // `tool=emcc` runs the SAME C, compiled by Emscripten instead of wasi-sdk clang. The two
      // modules are byte-identical in behaviour and neither imports anything, so this is a
      // toolchain comparison on a real crypto primitive rather than on a toy loop — the shape
      // where Emscripten's "layers of mocked dependencies" would show if they were there.
      const impl = params?.get?.('tool') === 'emcc' ? emccChacha : chachaWasm;
      for (let i = 0; i < records; i++) { iv[11] = i & 0xff; sink += impl.seal(key, iv, plain, aad).length; }
    } else {
      const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
      for (let i = 0; i < records; i++) {
        iv[11] = i & 0xff;
        sink += (await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, plain)).byteLength;
      }
    }
    return { op, n, records, bytes: sink };
  }

  if (op === 'aes128' || op === 'aes256') {
    // The default cipher moved from AES-128 to AES-256 when the offer order was matched to curl.
    // Both are WebCrypto; this is the per-byte cost of that change, on 16 KiB TLS records.
    const RECORD = 16384;
    const records = Math.max(1, Math.round((n * 1048576) / RECORD));
    const plain = new Uint8Array(RECORD);
    const iv = new Uint8Array(12);
    const k = await crypto.subtle.importKey(
      'raw', new Uint8Array(op === 'aes256' ? 32 : 16), 'AES-GCM', false, ['encrypt']);
    for (let i = 0; i < records; i++) {
      iv[11] = i & 0xff;
      sink += (await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, k, plain)).byteLength;
    }
    return { op, n, records, bytes: sink };
  }

  if (op === 'pq-caps') {
    // Feature-detection, on the runtime that matters. Whether ChaCha20 or ML-KEM exist natively
    // decides whether these are a wiring job or a userland crypto implementation, and the answer
    // cannot be read off Node's behaviour or anyone's documentation.
    const probe = async (label, fn) => {
      try { return [label, { ok: true, v: await fn() }]; }
      catch (e) { return [label, { ok: false, err: String(e?.message ?? e).slice(0, 90) }]; }
    };
    const nodeCrypto = await import('node:crypto').catch(() => null);
    const results = await Promise.all([
      probe('webcrypto.ChaCha20-Poly1305.importKey', async () => {
        const k = await crypto.subtle.importKey('raw', new Uint8Array(32), 'ChaCha20-Poly1305', false, ['encrypt']);
        return k.algorithm?.name ?? 'imported';
      }),
      probe('webcrypto.AES-GCM.importKey', async () => {
        await crypto.subtle.importKey('raw', new Uint8Array(32), 'AES-GCM', false, ['encrypt']);
        return 'imported';
      }),
      probe('webcrypto.ML-KEM-768.generateKey', async () => {
        const k = await crypto.subtle.generateKey({ name: 'ML-KEM-768' }, true, ['encapsulateBits']);
        return Object.keys(k).join(',');
      }),
      probe('webcrypto.X25519MLKEM768.generateKey', async () => {
        await crypto.subtle.generateKey({ name: 'X25519MLKEM768' }, true, ['deriveBits']);
        return 'generated';
      }),
      probe('node:crypto.getCiphers has chacha20-poly1305', async () =>
        nodeCrypto?.getCiphers?.().includes('chacha20-poly1305') ?? 'no getCiphers'),
      probe('node:crypto.createCipheriv chacha20-poly1305', async () => {
        const c = nodeCrypto.createCipheriv('chacha20-poly1305', new Uint8Array(32), new Uint8Array(12), { authTagLength: 16 });
        c.update(new Uint8Array(16)); c.final();
        return 'works';
      }),
      probe('node:crypto ML-KEM keygen', async () =>
        nodeCrypto.generateKeyPairSync('ml-kem-768') ? 'works' : 'no'),
      probe('node:crypto.getCurves count', async () => nodeCrypto?.getCurves?.().length ?? 'none'),
    ]);
    return { op, caps: Object.fromEntries(results) };
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
        // `n` must be in the mark, not just the query string: differencing two `n` values is how
        // the marginal cost is extracted, and the tail event carries only what was logged.
        n,
        prebuilt: Boolean(prebuilt.plain || prebuilt.chunked),
        fixed: [...BODYFIX.keys()].join('+') || null,
        mb: url.searchParams.get('mb') ?? null,
        ck: url.searchParams.get('ck') ?? null,
        src: url.searchParams.get('src') ?? 'real',
        // variant/view/alg change the answer for gz-stagex, aead-*, sigverify — they MUST reach
        // the mark or two variants land in one cpuTime bucket (the omission the brief names).
        variant: url.searchParams.get('variant') ?? null,
        view: url.searchParams.get('view') ?? null,
        alg: url.searchParams.get('alg') ?? null,
        ick: url.searchParams.get('ick') ?? null,
        cap: url.searchParams.get('cap') ?? null,
        // Which toolchain compiled the module under test. Without this, a Rust reading and an
        // Emscripten reading of the same variant land in one cpuTime bucket and the comparison
        // silently measures their average.
        tool: url.searchParams.get('tool') ?? null,
      });
      return Response.json(await cryptoBench(op, n, url.searchParams));
    }
    if (!env.PROBE_TOKEN || request.headers.get('x-probe-token') !== env.PROBE_TOKEN) {
      return new Response('forbidden', { status: 403 });
    }

    if (url.searchParams.get('h2window')) {
      // Does curl 8.21.0's real SETTINGS_INITIAL_WINDOW_SIZE (64 KiB) cost anything against the
      // 10 MiB this package defaults to? 1.6.2 changed `profiles.curl` to the captured value and
      // said the throughput consequence was NOT measured. This measures it.
      //
      // A smaller stream window is a ROUND-TRIP cost first: the peer stops after a window's worth
      // and waits for a WINDOW_UPDATE. Workers bills CPU, not wall time, so the two can move in
      // opposite directions — both are reported, and conflating them would answer the wrong
      // question. No proxy: this is about h2 flow control, and a direct connection isolates it.
      const win = Number(url.searchParams.get('h2window'));
      const target = url.searchParams.get('target');
      const reps = Number(url.searchParams.get('reps') ?? 1);
      markPath('h2window', { win: String(win), target, reps: String(reps) });
      // `prof=chrome` folds the whole Chromium identity in, which is how a PRIORITY-bearing HEADERS
      // frame gets tested against a server that is not ours.
      const prof = url.searchParams.get('prof');
      const client = new Client({
        connect, forceTunnel: true,
        ...(prof === 'chrome' ? { profile: chromeProfile } : {}),
        http2Settings: [[3, 100], [4, win], [2, 0]],
        maxBodyBytes: Infinity,
        timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 25000, idleMs: 25000 },
      });
      let bytes = 0, status = 0, proto = null;
      const t0 = Date.now();
      try {
        for (let i = 0; i < reps; i++) {
          const r = await client.fetch(`https://${target}${target.includes('?') ? '&' : '?'}i=${i}`);
          status = r.status;
          proto = r.tunnelfetch?.httpVersion ?? null;
          bytes += (await r.arrayBuffer()).byteLength;
        }
      } finally { await client.close(); }
      return Response.json({ win, target, reps, status, proto, bytes, wallMs: Date.now() - t0 });
    }

    if (url.searchParams.get('wire')) {
      // What does a megabyte off a real socket cost, and how much of that is the record layer?
      //
      // Every reading in this repository so far has priced the record layer as one number — 42 ms
      // per 4 MB body, "of which the AEAD is under 2 ms" — without ever separating the socket from
      // the parsing on top of it. Those are different bills with different fixes, and the whole
      // Wasm question turns on which one is bigger: Wasm can replace the parsing, and cannot make
      // the runtime hand bytes over any faster.
      //
      //   wire=http    same origin, no TLS. The socket and nothing else: the floor.
      //   wire=https   the same bytes through the TLS record layer.
      //   wire=h2      the same bytes through Http2Connection on top of that record layer.
      //   wire=client  the same bytes through the real Client (decompress off).
      //
      // Four rungs on one origin with no proxy in the way. The existing `depth` ladder measures
      // the same four, but only through a proxy and against a Cloudflare origin, so it has never
      // been able to say which of those two the cost belongs to.
      //
      // Same host, same file, same byte count, chosen because it serves both schemes off one
      // nginx. Range requests fix the wire volume exactly, so ms/MB needs no estimate of what the
      // origin decided to send. No proxy: a proxy adds a second socket and answers no question
      // being asked here.
      //
      //   pull=        the record layer's BYOB view size (tls.pullBytes), swept here rather than
      //                against a proxy so the U-curve can be attributed
      //   drain=byob   read the raw socket with BYOB views instead of a default reader, which is
      //                what the http rung needs to be a like-for-like floor for the TLS rung
      //
      // Difference two BYTE COUNTS at ONE request (each=1M against each=4M, reps=1), never two
      // request counts: a second request carries a second lot of per-request work — H2 stream
      // setup, HPACK, a HEADERS round trip — and differencing reps folds all of that into what
      // then gets divided by megabytes and called a per-byte cost.
      const scheme = url.searchParams.get('wire');
      const target = url.searchParams.get('target') ?? 'mirror.leaseweb.com';
      const path = url.searchParams.get('path') ?? '/debian/ls-lR.gz';
      const reps = Number(url.searchParams.get('reps') ?? 1);
      const each = Number(url.searchParams.get('each') ?? 1048576);
      const pull = Number(url.searchParams.get('pull') ?? 0);
      const drain = url.searchParams.get('drain') ?? 'default';
      // Optional here, unlike everywhere else in this rig. The ladder's whole point is that it can
      // run WITHOUT a proxy, which is what makes a per-layer answer possible — but the numbers this
      // repository quotes in dollars all come from the proxied path, and those two differ by more
      // than the layers do. Same ladder, same origin, `x-proxy` present or absent, is the one
      // experiment that would say how much of the gap is the proxy.
      const wireSpec = request.headers.get('x-proxy');
      const wireProxy = wireSpec
        ? (([h, pt, u, pw]) => ({ protocol: url.searchParams.get('socks') ? 'socks5' : 'http',
            hostname: h, port: Number(pt), username: u, password: pw }))(wireSpec.split(':'))
        : null;
      // Every knob here changes the answer, so every knob has to reach the tail event or two
      // variants land in one cpuTime bucket. That mistake has been made in this rig before.
      markPath('wire', { scheme, target, reps: String(reps), each: String(each),
                         pull: String(pull), drain, proxied: wireProxy ? '1' : '0' });
      let bytes = 0;
      let pulls = 0;
      let pulled = 0;
      let byobAvailable = true;
      try {
        if (scheme === 'client') {
          // The whole shipped stack, same origin, same byte count. Ranged requests keep the wire
          // volume identical to the rungs below it, so the differences are layers and not payloads.
          const client = new Client({ connect, forceTunnel: true, decompress: false,
            ...(wireProxy ? { proxy: wireProxy } : {}),
            // Without this the `pull` knob silently did not reach this rung, and an A/B of two
            // view sizes compared the default against itself — which showed up as two columns
            // agreeing to the millisecond, the one shape that is never a real result.
            ...(pull > 0 ? { tls: { pullBytes: pull } } : {}),
            maxBodyBytes: Infinity,
            timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 25000, idleMs: 25000 } });
          try {
            for (let i = 0; i < reps; i++) {
              const r = await client.fetch(`https://${target}${path}`,
                { headers: { range: `bytes=${i * each}-${(i + 1) * each - 1}` } });
              bytes += (await r.arrayBuffer()).byteLength;
            }
          } finally { await client.close(); }
          return Response.json({ wire: scheme, target, reps, each, pull, drain,
                                 proxied: Boolean(wireProxy), bytes });
        }
        const conn2 = await openConnection({
          url: `${scheme === 'h2' ? 'https' : scheme}://${target}${path}`,
          connect, proxy: wireProxy, alpn: scheme === 'h2' ? ['h2'] : ['http/1.1'],
          tls: pull > 0 ? { pullBytes: pull } : {},
        });
        if (scheme === 'h2') {
          try {
            const h2 = new Http2Connection(conn2, {});
            for (let i = 0; i < reps; i++) {
              const r = await h2.request({ method: 'GET', scheme: 'https', authority: target,
                path, headers: [['range', `bytes=${i * each}-${(i + 1) * each - 1}`]] });
              const rd = r.body.getReader();
              for (;;) {
                const { done, value } = await rd.read();
                if (done) break;
                bytes += value.byteLength;
                pulls++;
                pulled += value.byteLength;
              }
            }
            await h2.close().catch(() => {});
          } finally { await conn2.close?.(); }
          return Response.json({ wire: scheme, target, reps, each, pull, drain,
                                 proxied: Boolean(wireProxy), bytes,
                                 pulls, avgFill: pulls ? Math.round(pulled / pulls) : 0 });
        }
        try {
          let req = '';
          for (let i = 0; i < reps; i++) {
            req += `GET ${path} HTTP/1.1\r\nHost: ${target}\r\n` +
              `Range: bytes=${i * each}-${(i + 1) * each - 1}\r\n` +
              `Connection: ${i === reps - 1 ? 'close' : 'keep-alive'}\r\n\r\n`;
          }
          const w = conn2.writable.getWriter();
          await w.write(enc.encode(req));
          w.releaseLock();
          if (drain === 'byob') {
            // BYOB straight off the socket, so `avgFill` reports how much the runtime actually
            // hands over per crossing — the number the record layer's view-size sweep turns on.
            //
            // Through a proxy there is no BYOB to be had: openTunnel wraps the socket in a plain
            // ReadableStream so the bytes that arrived alongside the CONNECT reply are delivered
            // first, and a plain ReadableStream is not a byte stream. Falling back rather than
            // failing, and SAYING which one ran, is the point — that difference is a finding, not
            // an inconvenience.
            let rd;
            try {
              rd = conn2.readable.getReader({ mode: 'byob' });
            } catch {
              rd = conn2.readable.getReader();
              byobAvailable = false;
            }
            const size = pull > 0 ? pull : 65536;
            for (;;) {
              const { done, value } = byobAvailable
                ? await rd.read(new Uint8Array(size))
                : await rd.read();
              if (done) break;
              if (!value.byteLength) continue;
              bytes += value.byteLength;
              pulls++;
              pulled += value.byteLength;
            }
          } else {
            const rd = conn2.readable.getReader();
            for (;;) {
              const { done, value } = await rd.read();
              if (done) break;
              bytes += value.byteLength;
              pulls++;
              pulled += value.byteLength;
            }
          }
        } finally { await conn2.close?.(); }
      } catch (e) {
        return Response.json({ wire: scheme, error: String(e?.stack ?? e?.message ?? e).slice(0, 400) },
          { status: 500 });
      }
      return Response.json({ wire: scheme, target, reps, each, pull, drain,
                             proxied: Boolean(wireProxy), byobAvailable, bytes,
                             pulls, avgFill: pulls ? Math.round(pulled / pulls) : 0 });
    }

    const spec = request.headers.get('x-proxy');
    if (!spec) return new Response('need x-proxy: host:port:user:pass', { status: 400 });
    const [host, port, user, pass] = spec.split(':');
    const proxy = { protocol: url.searchParams.get('socks') ? 'socks5' : 'http', hostname: host, port: Number(port), username: user, password: pass };

    // The sweep's size must be in the mark: cpuTime comes from the tail event, and without it
    // every body size lands in one undifferentiated bucket.
    markPath('run', { sizes: url.searchParams.get('sizes') ?? null,
                      reuse: url.searchParams.get('reuse') ?? null,
                      pull: url.searchParams.get('pull') ?? null,
                      cap: url.searchParams.get('cap') ?? null,
                      // dc/ae/h1/sockshape all change the end-to-end cpuTime; they MUST reach the
                      // mark or a decode-on and decode-off run land in one bucket.
                      dc: url.searchParams.get('dc') ?? null,
                      ae: url.searchParams.get('ae') ?? null,
                      h1: url.searchParams.get('h1') ?? null,
                      sockshape: url.searchParams.get('sockshape') ?? null });
    const targets = (url.searchParams.get('targets') || '').split(',').filter(Boolean);
    const results = [];

    for (const t of targets) {
      results.push(await attempt(`https ${t}`, () => httpsThroughProxy({ proxy, url: `https://${t}/` })));
    }
    if (url.searchParams.get('keepalive')) {
      const t = url.searchParams.get('keepalive');
      results.push(await attempt(`keepalive ${t}`, () => keepAlive({ proxy, url: `https://${t}/` })));
    }
    if (url.searchParams.get('br')) {
      // End-to-end proof that the pluggable-decoder design actually works against a server that
      // really serves brotli — mocks prove the wiring, this proves the feature. The decoder is the
      // WASM one whose per-MB cost was measured by /crypto-bench, wrapped as the streaming
      // ReadableStream->ReadableStream the option expects.
      const t = url.searchParams.get('br');
      results.push(await attempt(`br ${t}`, () => brThroughProxy({ proxy, url: `https://${t}/` })));
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
          connect: connectFn, proxy, forceTunnel: true, decompress: dc,
          // The cost table has always been taken at a FINITE cap, which is the default and the
          // shape most callers run. That is also the shape that forces the decode stage through a
          // JS wrapper instead of the native relay, so `cap=inf` prices what the bomb guard costs
          // on a real proxied request rather than on a fixture.
          maxBodyBytes: url.searchParams.get('cap') === 'inf' ? Infinity : 16 << 20,
          http2: h2,
          // Present so the cost table can be re-taken at the OLD socket view size in the same
          // isolate as the new one. Without it the only way to compare the two is across sweeps,
          // where run-to-run variance is larger than the effect.
          ...(Number(url.searchParams.get('pull') ?? 0) > 0
            ? { tls: { pullBytes: Number(url.searchParams.get('pull')) } } : {}),
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


    if (url.searchParams.get('sse')) {
      // The AI-gateway shape, which every other bench in this file gets wrong by construction.
      //
      // Everything else here moves a large body in a few large chunks. An SSE completion moves a
      // SMALL body in hundreds of tiny events, each its own TLS record and h2 DATA frame — so the
      // per-chunk costs this rig has measured as constants (about 0.028 ms fixed per record, about
      // 17 us per stream-boundary crossing) stop being a footnote and become the whole bill. That
      // was an extrapolation; this measures it.
      //
      // Two token budgets, differenced: the connection, the handshake, the request and the
      // response head are in both and cancel, leaving the cost of the extra events alone.
      const which = url.searchParams.get('sse');       // 'pkg' | 'native'
      const maxTok = Number(url.searchParams.get('tok') ?? 128);
      const padTok = Number(url.searchParams.get('inp') ?? 0);
      const model = url.searchParams.get('model') ?? 'gpt-5.6-luna';
      const key = request.headers.get('x-openai-key');
      if (!key) return new Response('need x-openai-key', { status: 400 });
      markPath('sse', { which, tok: String(maxTok), inp: String(padTok), model, h1: url.searchParams.get('h1') ?? null });

      const body = JSON.stringify({
        model, stream: true, max_completion_tokens: maxTok,
        // Ask the API for its own token accounting instead of inferring it from byte counts. Every
        // token figure in this rig until now was an estimate from response size, and one of them
        // was wrong by an order of magnitude.
        stream_options: { include_usage: true },
        // A deterministic prompt that reliably produces a long stream: the point is event COUNT.
        // Ask for far more than the budget allows, so max_completion_tokens is what actually
        // decides the length and every arm streams exactly the same number of tokens.
        // `inp` pads the prompt to a target token count so the WRITE path is exercised too. Every
        // measurement in this rig until now was receive-side; a 20K-token request is ~80 KB of JSON
        // that has to be serialised, buffered, encrypted and framed before anything comes back, and
        // that cost has never been measured.
        // `echo` forces genuinely long output: the model is asked to reproduce a block it was just
        // given, which it will do mechanically for as long as the budget allows. "Count to N" does
        // not work — this model stops on its own at ~1000 tokens regardless of the budget, which is
        // how a whole set of measurements ended up being the same workload three times over.
        messages: url.searchParams.get('mode') === 'echo'
          ? [{ role: 'user', content: 'Repeat the following block back to me VERBATIM, in full, with no commentary:\n\n'
              + Array.from({ length: Math.max(1, Math.round(padTok/8)) },
                  (_, i) => `${i+1}. the quick brown fox jumps over the lazy dog near the river bank`).join('\n') }]
          : [{ role: 'user', content:
          (padTok > 0 ? 'Ignore this reference block.\n' + 'lorem ipsum dolor sit amet '.repeat(Math.round(padTok/5)) + '\n' : '')
          + `Count from 1 to 20000, one number per line.` }],
      });
      const headers = { 'content-type': 'application/json', authorization: `Bearer ${key}` };
      const url2 = 'https://api.openai.com/v1/chat/completions';

      let events = 0, bytes = 0, status = 0, firstChunk = '', firstEvent = '', usage = null;
      let encSeen = null;
      const drain = async (res) => {
        status = res.status;
        encSeen = res.headers.get('content-encoding') ?? 'none';
        const rd = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        for (;;) {
          const { done, value } = await rd.read();
          if (done) break;
          bytes += value.byteLength;
          buf += dec.decode(value, { stream: true });
          if (firstChunk.length < 300) firstChunk += buf.slice(0, 300);
          // Count SSE events the way a consumer would, so the parse cost is in the measurement.
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            events++;
            const ev = buf.slice(0, i);
            if (ev.includes('"usage"')) { try {
              usage = JSON.parse(ev.replace(/^data:\s*/, '')).usage ?? usage;
            } catch {} }
            if (!firstEvent && ev.startsWith('data:')) firstEvent = ev.slice(0, 220);
            buf = buf.slice(i + 2);
          }
        }
      };

      if (which === 'native') {
        await drain(await fetch(url2, { method: 'POST', headers, body }));
      } else {
        // h1 vs h2 is a real question for this shape: an SSE event over h2 is a DATA frame with
        // flow control and a WINDOW_UPDATE behind it, while over h1 it is a chunked-encoding chunk
        // and nothing else. AI APIs do not need multiplexing, so the cheaper framing may just win.
        const client = new Client({ connect, proxy, forceTunnel: true, maxBodyBytes: Infinity,
          ...(url.searchParams.get('h1') ? { http2: false } : {}),
          // `nodec` strips the decode stage. If an SSE stream arrives gzipped, every ~282-byte
          // event goes through the decompressor, and that would be the whole gap to native fetch.
          // Differencing this against the default says whether the cost is decode or transport.
          ...(url.searchParams.get('nodec') ? { decompress: false } : {}),
          timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 60000, idleMs: 60000 } });
        try { await drain(await client.fetch(url2, { method: 'POST', headers, body })); }
        finally { await client.close(); }
      }
      return Response.json({ which, h1: !!url.searchParams.get('h1'), model, tok: maxTok, inp: padTok, reqBytes: body.length, status, events, bytes, usage, firstEvent, enc: encSeen,
        proto: null });
    }

    if (url.searchParams.get('depth')) {
      // The same ladder as the isolated benches, but over a REAL proxied socket.
      //
      // Every bench so far fed its layer from an in-memory stream. The shipped path reads from
      // cloudflare:sockets, where the chunking is decided by the kernel and the network and every
      // read crosses the runtime boundary. That difference is the leading suspect for the two
      // thirds of a 4 MB request that the isolated ladder does not account for, and it cannot be
      // measured by anything that does not open a socket.
      //
      //   tls     openConnection (proxy CONNECT + handshake + record layer), h1 request, drain
      //           the PLAINTEXT. Everything below HTTP framing.
      //   h2      the same connection with ALPN h2 + Http2Connection, body drained, NOT decoded.
      //   client  the real Client with decompress:false — adds client.js plumbing over `h2`.
      //   full    the real Client, decoding, maxBodyBytes Infinity.
      const depth = url.searchParams.get('depth');
      const target = url.searchParams.get('target');
      const reps = Number(url.searchParams.get('reps') ?? 1);
      markPath('depth', { depth, target, reps: String(reps), pull: url.searchParams.get('pull') ?? null });
      const href = `https://${target}`;
      let bytes = 0;
      try {

      if (depth === 'tls' || depth === 'h2') {
        const pb = Number(url.searchParams.get('pull') ?? 0);
        const conn2 = await openConnection({
          url: href, connect, proxy,
          alpn: depth === 'h2' ? ['h2'] : ['http/1.1'],
          ...(pb > 0 ? { tls: { pullBytes: pb } } : {}),
        });
        try {
          if (depth === 'h2') {
            const h2 = new Http2Connection(conn2, {});
            for (let i = 0; i < reps; i++) {
              const u = new URL(href);
              const r = await h2.request({ method: 'GET', scheme: 'https', authority: u.host,
                path: u.pathname + u.search + (u.search ? '&' : '?') + 'i=' + i,
                headers: [['accept-encoding', 'gzip']] });
              const rd = r.body.getReader();
              for (;;) { const { done, value } = await rd.read(); if (done) break; bytes += value.byteLength; }
            }
            await h2.close().catch(() => {});
          } else {
            // No HTTP parsing at all, which is the entire point of this depth: pipeline `reps`
            // requests, mark the last Connection: close, then read to EOF counting bytes. What is
            // being priced is the socket and the TLS record layer and nothing above them.
            //
            // The first version sent one request, ignored `reps`, and made the differenced cost a
            // meaningless ~1 ms. The second parsed Content-Length, which this origin does not send
            // (Cloudflare gzips on the fly and chunks). Reading to EOF needs neither.
            const u = new URL(href);
            const w = conn2.writable.getWriter();
            let req = '';
            for (let i = 0; i < reps; i++) {
              req += `GET ${u.pathname}${u.search}&i=${i} HTTP/1.1\r\nHost: ${u.host}\r\n` +
                `Accept-Encoding: gzip\r\nConnection: ${i === reps - 1 ? 'close' : 'keep-alive'}\r\n\r\n`;
            }
            await w.write(enc.encode(req));
            w.releaseLock();
            const rd = conn2.readable.getReader();
            for (;;) { const { done, value } = await rd.read(); if (done) break; bytes += value.byteLength; }
          }
        } finally { await conn2.close?.(); }
        return Response.json({ depth, target, reps, bytes });
      }

      // depth=passthru: the real Client, still ASKING for gzip, but handing the body back coded.
      // `decompress: false` alone also drops gzip from Accept-Encoding, so the wire grows 2.76x —
      // it loses on both sides. Asking for gzip and passing it through is the combination that does
      // not exist as an option today, and it is the one a proxy actually wants: the caller forwards
      // the bytes with their Content-Encoding intact and never pays to decode them.
      //
      // Subtracting it from `full` gives the decode stage on the real path; subtracting `h2` from
      // it gives what client.js costs below decode. That split HAS now been measured — 16.5 ms of
      // client.js against 35.5 ms of decode on a 4 MB body — so the 41 ms this comment used to call
      // unexamined is accounted for. Left here because the shape of the ladder is what makes it
      // measurable, not because the number is still open.
      const client = new Client({ connect, proxy, forceTunnel: true,
        ...(depth === 'client' ? { decompress: false }
          : depth === 'passthru' ? { decompress: false }
          : { maxBodyBytes: Infinity }),
        timeouts: { connectMs: 15000, handshakeMs: 20000, headersMs: 25000, idleMs: 25000 } });
      try {
        for (let i = 0; i < reps; i++) {
          const r = await client.fetch(`${href}${href.includes('?') ? '&' : '?'}i=${i}`,
            depth === 'passthru' ? { headers: { 'accept-encoding': 'gzip' } } : undefined);
          bytes += (await r.arrayBuffer()).byteLength;
        }
      } finally { await client.close(); }
      return Response.json({ depth, target, reps, bytes });
      } catch (e) {
        return Response.json({ depth, error: String(e?.stack ?? e?.message ?? e).slice(0, 400) }, { status: 500 });
      }
    }

    if (url.searchParams.get('sizecmp')) {
      // Platform fetch against this package, same real origins, same run. A size-controlled origin
      // of our own is unusable here: Cloudflare error 1042 refuses a Worker fetching a Worker on
      // the same account, which once made a 17-byte 404 look like a 100x win.
      const which = url.searchParams.get('sizecmp'); // 'native' | 'pkg'
      const target = url.searchParams.get('target');
      const reps = Number(url.searchParams.get('reps') ?? 1);
      markPath('sizecmp', { which, target, reps, cap: url.searchParams.get('cap') ?? null });
      let bytes = 0, status = 0;
      if (which === 'native') {
        for (let i = 0; i < reps; i++) {
          const r = await fetch(`https://${target}${target.includes('?') ? '&' : '?'}i=${i}`, { cf: { cacheTtl: 0 } });
          status = r.status;
          bytes += (await r.arrayBuffer()).byteLength;
        }
      } else {
        // cap=0 means maxBodyBytes: Infinity, which is what enables the native decode relay added
        // in 1.7.0. Without it the default 32 MiB applies and the counting wrapper is used, so the
        // two are the honest before/after for that change on a real end-to-end path.
        const capRaw = Number(url.searchParams.get('cap') ?? -1);
        const client = new Client({ proxy, connect,
          ...(capRaw === 0 ? { maxBodyBytes: Infinity } : capRaw > 0 ? { maxBodyBytes: capRaw } : {}),
          timeouts: { connectMs: 10000, handshakeMs: 15000, headersMs: 25000, idleMs: 25000 } });
        try {
          for (let i = 0; i < reps; i++) {
            const r = await client.fetch(`https://${target}${target.includes('?') ? '&' : '?'}i=${i}`);
            status = r.status;
            bytes += (await r.arrayBuffer()).byteLength;
          }
        } finally { await client.close(); }
      }
      return Response.json({ which, target, reps, status, bytes });
    }
    if (url.searchParams.get("native")) {
      markPath("native", { sizes: url.searchParams.get("native") ?? null,
                           reuse: url.searchParams.get("reuse") ?? null });
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
