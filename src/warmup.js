// Opt-in JIT warmup: replay a recorded TLS 1.3 handshake, proxy CONNECT exchange and HTTP
// response through this package's REAL drivers — record layer, negotiation, key schedule, AEAD,
// trust and HTTP parsing — so a fresh isolate's first real request runs code V8 has already
// executed and tiered.
//
// Why this exists. On the primary target runtime, per-request CPU is billed (and on the free
// plan, enforced at 10 ms) while module-scope evaluation is a separate startup budget — and V8
// compiles and optimises per function per isolate, ramping over the first ~dozen executions.
// Measured on the edge, a fresh isolate's first proxied request costs ~46 ms of request CPU
// against a ~10 ms tiered floor, with ~60-80 ms of excess spread across the early ramp.
// Executing the hot path at module scope moves that excess into the startup budget.
//
// The trade, stated so a reader can decide rather than cargo-cult:
//   * On plans that do not bill startup CPU (standard Workers), warmup converts billed request
//     milliseconds into unbilled startup milliseconds. It still spends real wall time at isolate
//     start and consumes part of the hard startup CPU limit (1 s), so it is wrong where the
//     startup budget is already tight.
//   * On deployment modes that bill startup CPU as well (Cloudflare's dynamic Worker loading,
//     for example), warmup is the same work still paid for, plus wall time — a pure loss. A
//     library must not make that choice for its consumer, which is why nothing in this package
//     ever calls warmup() itself: it runs only if the consumer imports and calls it, typically
//     at module scope of their worker:
//
//         import { warmup } from 'tunnelfetch';
//         await warmup();
//
// What it deliberately is NOT:
//   * Not caching. Every call decodes the fixture and derives everything afresh and retains
//     nothing; not calling warmup() yields byte-identical behaviour, just slower first
//     executions. Nothing derived from any trust configuration is kept — the replay verifies its
//     own synthetic chain against its own baked root through an explicit anchors-mode config
//     that never touches the bundled store.
//   * Not a network client. No socket, no randomness, no timers. The runtime forbids
//     getRandomValues, key generation, timers and I/O at global scope — which is exactly where
//     this is meant to run — so the replay's nondeterminism was fixed at recording time
//     (scripts/gen-warmup-fixture.mjs) and shipped as bytes, and the "transport" is a hand-made
//     reader/writer pair over those bytes: the platform's stream classes are never touched,
//     because reading them is one of the operations global scope forbids.
//
// Coverage, honestly stated: the proxy CONNECT layer, the whole TLS client (connectTls: record
// layer, both negotiation paths' shared code, transcript, key schedule, AEAD, CertificateVerify
// and chain validation) and HTTP head parsing/serialisation all run for real. What cannot run
// at global scope stays cold: the platform-stream plumbing (plaintextDuplex readers, body
// streams, gzip DecompressionStream, chunked decoding) and the Client facade above
// openConnection (its URL/pool/deadline glue). The measured effect on the ramp lives with the
// bench rig, not here.

import { openHttpConnect } from './proxy/http-connect.js';
import { connectTls } from './tls/connect.js';
import { buildClientHello, generateKeyShare } from './tls/handshake-messages.js';
import { TLS12, TLS13 } from './tls/constants.js';
import { verifyChain } from './trust/index.js';
import { ByteReader, concat, equal, utf8 } from './util/bytes.js';
import { serializeRequestHead } from './http1/request.js';
import { bodyFraming, readResponseHead } from './http1/response.js';
import { charsetFor, decodeText } from './client/decode.js';
import { WARMUP_FIXTURE, WARMUP_HOSTNAME, WARMUP_NOW } from './warmup-fixture.js';

/**
 * A hand-made "readable": satisfies exactly the surface ByteReader uses (getReader().read()),
 * delivering the given chunks then failing loudly. Not a platform ReadableStream on purpose —
 * reading one of those is forbidden in the global scope this module targets.
 * @param {Uint8Array[]} chunks
 */
function cannedReadable(chunks) {
  let i = 0;
  return {
    getReader: () => ({
      read: async () => {
        if (i < chunks.length) return { value: chunks[i++], done: false };
        // Past the recording: the parsers and the fixture disagree. Failing beats hanging the
        // caller's startup on a promise that never settles.
        throw new Error('warmup fixture exhausted: the recording and the replay disagree');
      },
      releaseLock() {},
      cancel: async () => {},
    }),
  };
}

/** The matching "writable": collects what the client sends. Same duck-typing rationale. */
function sinkWritable() {
  const written = [];
  return {
    written,
    getWriter: () => ({
      write: async (chunk) => { written.push(chunk); },
      close: async () => {},
      abort: async () => {},
      releaseLock() {},
    }),
  };
}

/** A ByteReader over already-decrypted bytes; running past them is a loud error. */
function preloadedReader(bytes) {
  const reader = new ByteReader(cannedReadable([]));
  reader.unshift(bytes);
  return reader;
}

const CONNECT_REPLY = 'HTTP/1.1 200 Connection established\r\n\r\n';

/** Tag failures with the replay stage, so `{ ok: false }` names where the runtime said no. */
async function step(name, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e && typeof e === 'object' && e.warmupStage === undefined) e.warmupStage = name;
    throw e;
  }
}

/** One full replay: proxy CONNECT, then the recorded TLS handshake, then the HTTP exchange. */
async function replayOnce() {
  const F = WARMUP_FIXTURE;
  const hostname = WARMUP_HOSTNAME;

  // --- drift detector, before anything tries to decrypt -------------------------------------
  // The recording is only replayable while the ClientHello the package builds is byte-identical
  // to the one recorded. Any change to the offer (ciphers, groups, extensions, ALPN) fails HERE
  // with instructions, rather than three stages later as an opaque AEAD error.
  const { fixedPair } = await step('drift-check', async () => {
    const clientPriv = await crypto.subtle.importKey(
      'pkcs8', F.clientPrivPkcs8(), { name: 'X25519' }, false, ['deriveBits']);
    const clientPub = await crypto.subtle.importKey(
      'raw', F.clientPubRaw(), { name: 'X25519' }, true, []);
    const pair = async () => ({ publicKey: clientPub, privateKey: clientPriv });
    const share = await generateKeyShare(0x001d, { generateKeyPair: pair });
    const probe = buildClientHello({
      hostname,
      keyShares: [share],
      random: F.clientRandom(),
      legacySessionId: F.legacySessionId(),
      versions: [TLS13, TLS12],
    });
    if (!equal(probe.message, F.clientHello())) {
      throw new Error('warmup fixture drift: buildClientHello no longer matches the recording; ' +
        'rerun scripts/gen-warmup-fixture.mjs');
    }
    return { fixedPair: pair };
  });

  // --- proxy CONNECT layer, for real ---------------------------------------------------------
  await step('proxy-connect', async () => {
    const tunnel = await openHttpConnect({
      proxy: { protocol: 'http', hostname, port: 3128, username: 'warm', password: 'up' },
      target: { hostname, port: 443 },
      connect: () => ({
        readable: cannedReadable([utf8(CONNECT_REPLY)]),
        writable: sinkWritable(),
        opened: Promise.resolve({}),
        close: async () => {},
      }),
    });
    if (tunnel.socket == null) throw new Error('warmup: CONNECT replay produced no tunnel');
  });

  // --- the whole TLS client over the recorded bytes ------------------------------------------
  // The transport is hand-made (see cannedReadable): the real record layer, drivers, key
  // schedule, AEAD, trust and negotiation all execute exactly as in production.
  const tlsSink = sinkWritable();
  const session = await step('tls-handshake', () => connectTls({
    transport: { readable: cannedReadable([F.serverBytes()]), writable: tlsSink },
    hostname,
    verifyPeer: (chain, host) => verifyChain({
      chain, hostname: host, trust: { mode: 'anchors', anchors: [F.rootDer()] }, now: WARMUP_NOW,
    }),
    options: { clientRandom: F.clientRandom(), legacySessionId: F.legacySessionId() },
    deps: { generateKeyPair: fixedPair },
  }));

  // --- HTTP over the session's record layer directly -----------------------------------------
  // session.readable/writable are platform streams (forbidden here); session.record is not.
  return step('http-exchange', async () => {
    const request = serializeRequestHead({
      method: 'GET',
      target: '/',
      headers: [
        ['host', hostname], ['accept', '*/*'], ['accept-encoding', 'gzip, deflate'],
        ['connection', 'keep-alive'],
      ],
    });
    await session.record.writeAppData(request);
    const plain = [];
    for (;;) {
      const chunk = await session.record.readAppData();
      if (chunk === null) break; // the recorded close_notify
      plain.push(chunk);
    }
    const reader = preloadedReader(concat(plain));
    const head = await readResponseHead(reader);
    const framing = bodyFraming({ status: head.status, method: 'GET', headers: head.headers });
    if (framing.kind !== 'content-length') {
      throw new Error(`warmup: recorded response framing is ${framing.kind}, expected content-length`);
    }
    const body = await reader.readExactly(framing.length, 'warmup response body');
    const text = decodeText(body, charsetFor(head.headers.get('content-type'), body));
    // Deliberately NO session.close(): shutdown is the one record-layer path that arms a timer,
    // and timers are forbidden where this runs. The session owns no real resources to release.
    return { status: head.status, bodyBytes: text.length, wrote: tlsSink.written.length };
  });
}

/**
 * What one warmup() call reports. `ok` is the only field a caller usually needs; the rest exists
 * so a failure names the exact problem rather than being a silent no-op.
 * @typedef {object} WarmupReport
 * @property {boolean} ok every iteration completed
 * @property {number} iterations how many replays ran to completion
 * @property {string | null} error first failure, if any — warmup() itself never throws
 */

/**
 * Warm the hot path by replaying a recorded proxy + TLS + HTTP exchange through the real code.
 * See the module comment for what this buys, what it costs, and when NOT to call it. Never
 * called by the package itself; call it from module scope of your worker if — and only if —
 * your deployment does not bill startup CPU.
 *
 * Safe by construction: no network, no randomness, no timers, nothing cached, and it never
 * throws — a runtime that forbids more than expected yields `{ ok: false, error }` and the
 * package behaves exactly as if warmup() had never been called.
 *
 * @param {{ iterations?: number }} [opts] replay count, default 5, clamped to 1..10. One pass
 *   moves the hot functions out of the interpreter; more passes push V8's tiering further down
 *   the ramp at proportionally more startup cost. Measured startup cost is roughly 10-20 ms per
 *   iteration on current edge hardware, against the 1 s startup budget.
 * @returns {Promise<WarmupReport>}
 */
export async function warmup({ iterations = 5 } = {}) {
  const n = Math.min(10, Math.max(1, Number.isFinite(iterations) ? Math.floor(iterations) : 5));
  let done = 0;
  try {
    for (let i = 0; i < n; i++) {
      await replayOnce();
      done++;
    }
    return { ok: true, iterations: done, error: null };
  } catch (e) {
    const at = e && typeof e === 'object' && e.warmupStage ? `${e.warmupStage}: ` : '';
    return { ok: false, iterations: done, error: `${at}${e?.message ?? String(e)}` };
  }
}
