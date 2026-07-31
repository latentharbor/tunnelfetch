// Capability probe for workerd on the Cloudflare edge.
//
// Why this exists: every design decision in this package rests on runtime behaviour that is
// either undocumented, documented incorrectly, or divergent from Node. Local workerd does not
// reproduce the edge's network policy or its timer clamping, so conclusions have to be measured
// where the code will actually run. Output is machine-readable so the offline test suite can
// assert against it and capability drift shows up as a test failure rather than a silent bug.
//
// This Worker is token-gated. Without the token it does nothing that touches the network, so a
// deployed probe is not an open relay.

import { connect } from "cloudflare:sockets";
import {
  moduleInventory, nodeCryptoShape, tlsDirect, tlsOptionSupport, tlsOverConnectTunnel,
  tlsOverFreshSocket,
  tlsOverTunnelWrongName,
} from "./nodecompat.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function attempt(fn) {
  try {
    const v = await fn();
    return { ok: true, v: v === undefined ? true : v };
  } catch (e) {
    return { ok: false, err: `${e?.name || "Error"}: ${e?.message || String(e)}` };
  }
}

function deadline(promise, ms, label) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, rej) => {
      t = setTimeout(() => rej(new Error(`timeout after ${ms}ms: ${label}`)), ms);
    }),
  ]);
}

// ---------------------------------------------------------------- capabilities (no egress)

async function capsCrypto() {
  const s = crypto.subtle;
  const out = {};
  const gen = (algo, usages) => s.generateKey(algo, true, usages);

  out.x25519 = await attempt(async () => {
    const a = await gen({ name: "X25519" }, ["deriveBits"]);
    const b = await gen({ name: "X25519" }, ["deriveBits"]);
    const raw = new Uint8Array(await s.exportKey("raw", b.publicKey));
    const imp = await s.importKey("raw", raw, { name: "X25519" }, false, []);
    const bits = await s.deriveBits({ name: "X25519", public: imp }, a.privateKey, 256);
    return { rawPubLen: raw.length, sharedLen: new Uint8Array(bits).length };
  });

  for (const curve of ["P-256", "P-384", "P-521"]) {
    out[`ecdh_${curve}`] = await attempt(async () => {
      const a = await gen({ name: "ECDH", namedCurve: curve }, ["deriveBits"]);
      const b = await gen({ name: "ECDH", namedCurve: curve }, ["deriveBits"]);
      const raw = new Uint8Array(await s.exportKey("raw", b.publicKey));
      const imp = await s.importKey("raw", raw, { name: "ECDH", namedCurve: curve }, false, []);
      const n = curve === "P-521" ? 528 : curve === "P-384" ? 384 : 256;
      const bits = await s.deriveBits({ name: "ECDH", public: imp }, a.privateKey, n);
      return { rawPubLen: raw.length, uncompressed: raw[0] === 0x04, sharedLen: new Uint8Array(bits).length };
    });
  }

  out.ed25519 = await attempt(async () => {
    const k = await gen({ name: "Ed25519" }, ["sign", "verify"]);
    const sig = await s.sign({ name: "Ed25519" }, k.privateKey, enc.encode("x"));
    return s.verify({ name: "Ed25519" }, k.publicKey, sig, enc.encode("x"));
  });

  for (const curve of ["P-256", "P-384", "P-521"]) {
    const h = curve === "P-521" ? "SHA-512" : curve === "P-384" ? "SHA-384" : "SHA-256";
    out[`ecdsa_${curve}`] = await attempt(async () => {
      const k = await gen({ name: "ECDSA", namedCurve: curve }, ["sign", "verify"]);
      const sig = await s.sign({ name: "ECDSA", hash: h }, k.privateKey, enc.encode("x"));
      return s.verify({ name: "ECDSA", hash: h }, k.publicKey, sig, enc.encode("x"));
    });
  }

  for (const [label, name] of [["rsa_pss", "RSA-PSS"], ["rsa_pkcs1", "RSASSA-PKCS1-v1_5"]]) {
    for (const h of ["SHA-256", "SHA-384", "SHA-512", "SHA-1"]) {
      out[`${label}_${h}`] = await attempt(async () => {
        const k = await gen(
          { name, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: h },
          ["sign", "verify"],
        );
        const p = name === "RSA-PSS" ? { name, saltLength: 32 } : { name };
        const sig = await s.sign(p, k.privateKey, enc.encode("x"));
        return s.verify(p, k.publicKey, sig, enc.encode("x"));
      });
    }
  }

  out.spki_import_ec = await attempt(async () => {
    const k = await gen({ name: "ECDSA", namedCurve: "P-256" }, ["sign", "verify"]);
    const spki = await s.exportKey("spki", k.publicKey);
    const re = await s.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return { spkiLen: new Uint8Array(spki).length, reimported: !!re };
  });

  out.spki_import_rsa = await attempt(async () => {
    const k = await gen(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      ["sign", "verify"],
    );
    const spki = await s.exportKey("spki", k.publicKey);
    // The same SPKI must be importable under BOTH PKCS1 and PSS: a cert carries one SPKI but the
    // signature algorithm is chosen by the issuer, so the trust layer imports it twice.
    await s.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    await s.importKey("spki", spki, { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
    return { spkiLen: new Uint8Array(spki).length, bothAlgos: true };
  });

  out.hkdf = await attempt(async () => {
    const k = await s.importKey("raw", enc.encode("ikm"), "HKDF", false, ["deriveBits"]);
    const b = await s.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("i") }, k, 256);
    return new Uint8Array(b).length;
  });

  out.hkdf_zero_salt = await attempt(async () => {
    // TLS 1.3's key schedule starts from HKDF-Extract with a zero-length salt.
    const k = await s.importKey("raw", new Uint8Array(32), "HKDF", false, ["deriveBits"]);
    const b = await s.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new Uint8Array(0) }, k, 256);
    return new Uint8Array(b).length;
  });

  out.hmac = await attempt(async () => {
    const k = await s.importKey("raw", enc.encode("k"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await s.sign("HMAC", k, enc.encode("m"))).length;
  });

  for (const [label, algo] of [
    ["aes_gcm_128", { name: "AES-GCM", length: 128 }],
    ["aes_gcm_256", { name: "AES-GCM", length: 256 }],
    ["aes_ctr", { name: "AES-CTR", length: 128 }],
    ["aes_cbc", { name: "AES-CBC", length: 128 }],
  ]) {
    out[label] = await attempt(async () => {
      const k = await s.generateKey(algo, true, ["encrypt", "decrypt"]);
      const p = algo.name === "AES-GCM"
        ? { name: "AES-GCM", iv: new Uint8Array(12), additionalData: enc.encode("aad"), tagLength: 128 }
        : algo.name === "AES-CTR"
          ? { name: "AES-CTR", counter: new Uint8Array(16), length: 32 }
          : { name: "AES-CBC", iv: new Uint8Array(16) };
      const ct = await s.encrypt(p, k, enc.encode("hello"));
      return new Uint8Array(await s.decrypt(p, k, ct)).length === 5;
    });
  }

  out.aes_gcm_tag_mismatch_throws = await attempt(async () => {
    const k = await s.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
    const p = { name: "AES-GCM", iv: new Uint8Array(12), tagLength: 128 };
    const ct = new Uint8Array(await s.encrypt(p, k, enc.encode("hello")));
    ct[ct.length - 1] ^= 0xff;
    try {
      await s.decrypt(p, k, ct);
      return "NO THROW - AEAD failure is silent, fail-closed impossible";
    } catch {
      return "throws";
    }
  });

  out.chacha20 = await attempt(async () => {
    await s.generateKey({ name: "ChaCha20-Poly1305" }, true, ["encrypt"]);
    return "present";
  });

  for (const d of ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "MD5"]) {
    out[`digest_${d}`] = await attempt(async () => new Uint8Array(await s.digest(d, enc.encode("x"))).length);
  }
  return out;
}

async function capsPlatform() {
  const out = {};
  out.decompression = {};
  for (const f of ["gzip", "deflate", "deflate-raw", "br", "zstd"]) {
    out.decompression[f] = (await attempt(() => { new DecompressionStream(f); })).ok;
  }
  out.text_encodings = {};
  for (const e of ["utf-8", "utf-16le", "utf-16be", "windows-1252", "windows-1251", "gbk",
    "gb18030", "big5", "shift_jis", "euc-jp", "euc-kr", "iso-8859-1", "iso-2022-jp"]) {
    const r = await attempt(() => new TextDecoder(e).encoding);
    out.text_encodings[e] = r.ok ? r.v : false;
  }
  out.byte_stream = (await attempt(() => { new ReadableStream({ type: "bytes" }); })).ok;
  out.abort_timeout = typeof AbortSignal.timeout === "function";
  out.node = {};
  out.node.crypto = await attempt(async () => {
    const m = await import("node:crypto");
    return {
      X509Certificate: typeof m.X509Certificate,
      publicEncrypt: typeof m.publicEncrypt,
      chacha20poly1305: (await attempt(() => {
        m.createCipheriv("chacha20-poly1305", new Uint8Array(32), new Uint8Array(12), { authTagLength: 16 });
      })).ok,
    };
  });
  out.node.x509_proto = await attempt(async () => {
    const { X509Certificate } = await import("node:crypto");
    return Object.getOwnPropertyNames(X509Certificate.prototype);
  });
  out.socket_proto = await attempt(() => {
    const s = connect({ hostname: "127.0.0.1", port: 9 }, { secureTransport: "starttls" });
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(s));
    const byob = (() => { try { s.readable.getReader({ mode: "byob" }).releaseLock(); return true; } catch { return false; } })();
    s.close().catch(() => {});
    return { proto, byob };
  });
  return out;
}

// Timer clamping. Date.now()/performance.now() are expected to be frozen between I/O on the edge
// (Spectre mitigation) but advance under local workerd. Idle-timeout design depends on which.
function capsTiming() {
  const out = {};
  const t0 = Date.now(), p0 = performance.now();
  let acc = 0;
  for (let i = 0; i < 5e6; i++) acc += i % 7;
  out.sync_loop = { dateDelta: Date.now() - t0, perfDelta: performance.now() - p0, acc };
  return out;
}

async function capsTimingAsync() {
  const t0 = Date.now(), p0 = performance.now();
  await sleep(50);
  return { afterSleep50: { dateDelta: Date.now() - t0, perfDelta: performance.now() - p0 } };
}

// ---------------------------------------------------------------- socket helpers

async function readSome(socket, { maxBytes = 4096, ms = 8000 } = {}) {
  const reader = socket.readable.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { value, done } = await deadline(reader.read(), ms, "read");
      if (done) break;
      if (value) { chunks.push(value); total += value.byteLength; }
      if (total > 0) break; // first chunk is enough to prove bytes flowed
    }
  } finally {
    try { reader.releaseLock(); } catch { /* stream already errored */ }
  }
  const buf = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
  return buf;
}

async function writeAll(socket, bytes) {
  const w = socket.writable.getWriter();
  try { await w.write(bytes); } finally { try { w.releaseLock(); } catch { /* already errored */ } }
}

// ---------------------------------------------------------------- network policy

async function netPolicy(url) {
  const targets = (url.searchParams.get("targets") || "").split(",").filter(Boolean);
  const results = {};
  for (const t of targets) {
    const [hostname, portStr] = t.split(/:(?=\d+$)/);
    const port = Number(portStr);
    const started = Date.now();
    results[t] = await attempt(async () => {
      const s = connect({ hostname, port }, { secureTransport: "off", allowHalfOpen: false });
      try {
        const info = await deadline(s.opened, 10000, `opened ${t}`);
        return { opened: true, elapsedMs: Date.now() - started, remoteAddress: info.remoteAddress, localAddress: info.localAddress };
      } finally {
        s.close().catch(() => {});
      }
    });
    if (!results[t].ok) results[t].elapsedMs = Date.now() - started;
  }
  return results;
}

// ---------------------------------------------------------------- the pivotal experiment

// Does workerd enforce certificate identity against expectedServerHostname on startTls()?
//
// The failure mode this guards against: startTls() returns a Socket SYNCHRONOUSLY and the
// handshake runs in the background. Checking only that startTls() did not throw proves nothing.
// So every case here awaits `opened`, then writes a request, then reads bytes back.
async function startTlsCase({ connectHost, port = 443, claimHost, requestHost, byIp = false }) {
  const out = { connectHost, claimHost: claimHost ?? null, requestHost, byIp };
  const s = connect({ hostname: connectHost, port }, { secureTransport: "starttls" });

  const opened1 = await attempt(() => deadline(s.opened, 10000, "plain opened"));
  out.plainOpened = opened1;
  if (!opened1.ok) { s.close().catch(() => {}); return out; }

  let tls;
  out.startTlsCall = await attempt(() => {
    tls = s.startTls(claimHost ? { expectedServerHostname: claimHost } : undefined);
    return { returnedSocket: !!tls, secureTransport: tls.secureTransport };
  });
  if (!out.startTlsCall.ok) { s.close().catch(() => {}); return out; }

  out.tlsOpened = await attempt(() => deadline(tls.opened, 15000, "tls opened"));

  out.wrote = await attempt(() =>
    writeAll(tls, enc.encode(`GET / HTTP/1.1\r\nHost: ${requestHost}\r\nUser-Agent: probe\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n`)));

  out.read = await attempt(async () => {
    const b = await readSome(tls, { ms: 12000 });
    return { bytes: b.byteLength, firstLine: dec.decode(b.subarray(0, 120)).split("\r\n")[0] };
  });

  out.closed = await attempt(() => deadline(tls.closed, 5000, "closed"));
  tls.close().catch(() => {});

  // The verdict: bytes only flow if the runtime accepted the peer's certificate.
  out.verdict = out.read.ok && out.read.v.bytes > 0 ? "DATA_FLOWED" : "NO_DATA";
  return out;
}

async function startTlsSuite(url) {
  const a = url.searchParams.get("hostA");
  const b = url.searchParams.get("hostB");
  const ip = url.searchParams.get("ipA");
  if (!a || !b) throw new Error("need ?hostA=&hostB=");
  const out = {};
  // Control: no option at all. Identity should be the connect() hostname.
  out.c1_no_option = await startTlsCase({ connectHost: a, requestHost: a });
  // Control: claim the truth. Should behave exactly like c1.
  out.c2_claim_truth = await startTlsCase({ connectHost: a, claimHost: a, requestHost: a });
  // THE TEST: connect to A, claim to be B. If data flows, identity is NOT enforced.
  out.c3_claim_lie = await startTlsCase({ connectHost: a, claimHost: b, requestHost: a });
  // Nonexistent name: separates "server rejected our SNI" from "client rejected the cert".
  out.c4_claim_bogus = await startTlsCase({ connectHost: a, claimHost: "probe.invalid", requestHost: a });
  if (ip) {
    // Connect by IP literal, no option: identity becomes the IP, which public certs do not carry.
    out.c5_ip_no_option = await startTlsCase({ connectHost: ip, requestHost: a, byIp: true });
    // Connect by IP, claim the hostname: this is exactly the shape a CONNECT tunnel would need.
    out.c6_ip_claim_host = await startTlsCase({ connectHost: ip, claimHost: a, requestHost: a, byIp: true });
  }
  return out;
}

// ---------------------------------------------------------------- proxy tunnel

function parseProxy(spec) {
  const [host, port, user, pass] = spec.split(":");
  return { host, port: Number(port), user, pass };
}

async function connectTunnel(proxy, targetHost, targetPort, log) {
  const s = connect({ hostname: proxy.host, port: proxy.port }, { secureTransport: "starttls" });
  await deadline(s.opened, 12000, "proxy opened");
  log.proxyOpened = true;

  const auth = btoa(`${proxy.user}:${proxy.pass}`);
  const req =
    `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
    `Host: ${targetHost}:${targetPort}\r\n` +
    `Proxy-Authorization: Basic ${auth}\r\n` +
    `Proxy-Connection: keep-alive\r\n\r\n`;
  await writeAll(s, enc.encode(req));

  // Read the whole status+header block. Proxies inject headers and may answer HTTP/1.0.
  const reader = s.readable.getReader();
  let buf = new Uint8Array(0);
  try {
    while (buf.byteLength < 8192) {
      const { value, done } = await deadline(reader.read(), 12000, "proxy connect reply");
      if (done) break;
      if (value) {
        const n = new Uint8Array(buf.byteLength + value.byteLength);
        n.set(buf); n.set(value, buf.byteLength); buf = n;
      }
      const text = dec.decode(buf);
      if (text.includes("\r\n\r\n")) break;
    }
  } finally { try { reader.releaseLock(); } catch { /* errored */ } }

  const text = dec.decode(buf);
  const statusLine = text.split("\r\n")[0] || "";
  log.connectStatusLine = statusLine;
  log.connectHeaderBytes = buf.byteLength;
  const m = /^HTTP\/(\d\.\d) (\d{3})/.exec(statusLine);
  log.connectVersion = m?.[1] ?? null;
  const code = m ? Number(m[2]) : 0;
  if (code < 200 || code > 299) throw new Error(`CONNECT refused: ${statusLine}`);
  const idx = text.indexOf("\r\n\r\n");
  log.bytesAfterHeaders = buf.byteLength - (idx + 4);
  return s;
}

async function proxySuite(url, proxySpec) {
  const proxy = parseProxy(proxySpec);
  const target = url.searchParams.get("target") || "";
  const [tHost, tPortStr] = target.split(/:(?=\d+$)/);
  const tPort = Number(tPortStr || 443);
  const out = { proxyHost: proxy.host, proxyPort: proxy.port, target: `${tHost}:${tPort}` };

  out.tunnel = await attempt(async () => {
    const log = {};
    const s = await connectTunnel(proxy, tHost, tPort, log);
    s.close().catch(() => {});
    return log;
  });
  if (!out.tunnel.ok) return out;

  // Plaintext HTTP through the tunnel: proves the byte pipe works without any TLS involvement.
  out.plainHttp = await attempt(async () => {
    const log = {};
    const s = await connectTunnel(proxy, tHost, 80, log);
    try {
      await writeAll(s, enc.encode(`GET / HTTP/1.1\r\nHost: ${tHost}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n`));
      const b = await readSome(s, { ms: 12000 });
      return { ...log, bytes: b.byteLength, firstLine: dec.decode(b.subarray(0, 120)).split("\r\n")[0] };
    } finally { s.close().catch(() => {}); }
  });

  // The decisive one: runtime TLS inside the tunnel, with the target's identity asserted.
  out.tunnelStartTls = await attempt(async () => {
    const log = {};
    const s = await connectTunnel(proxy, tHost, tPort, log);
    let tls;
    try {
      tls = s.startTls({ expectedServerHostname: tHost });
    } catch (e) {
      return { ...log, startTlsThrew: `${e?.name}: ${e?.message}` };
    }
    try {
      const openedRes = await attempt(() => deadline(tls.opened, 15000, "tunnel tls opened"));
      await writeAll(tls, enc.encode(`GET / HTTP/1.1\r\nHost: ${tHost}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n`));
      const b = await readSome(tls, { ms: 15000 });
      return { ...log, opened: openedRes, bytes: b.byteLength, firstLine: dec.decode(b.subarray(0, 120)).split("\r\n")[0] };
    } finally { tls?.close?.().catch(() => {}); }
  });

  // Same tunnel, but lie about the identity. If this yields bytes, the tunnel path is MITM-able.
  const lie = url.searchParams.get("hostB");
  if (lie) {
    out.tunnelStartTlsLie = await attempt(async () => {
      const log = {};
      const s = await connectTunnel(proxy, tHost, tPort, log);
      let tls;
      try { tls = s.startTls({ expectedServerHostname: lie }); }
      catch (e) { return { ...log, startTlsThrew: `${e?.name}: ${e?.message}` }; }
      try {
        const openedRes = await attempt(() => deadline(tls.opened, 15000, "lie tls opened"));
        await writeAll(tls, enc.encode(`GET / HTTP/1.1\r\nHost: ${tHost}\r\nConnection: close\r\n\r\n`));
        const b = await readSome(tls, { ms: 15000 });
        return { ...log, opened: openedRes, bytes: b.byteLength, firstLine: dec.decode(b.subarray(0, 120)).split("\r\n")[0] };
      } finally { tls?.close?.().catch(() => {}); }
    });
  }
  return out;
}

// Does this proxy speak SOCKS5 on the same port it speaks HTTP CONNECT on? Webshare-style
// endpoints vary, and the answer decides whether the SOCKS5 path can be live-tested at all.
async function socks5Probe(url, proxySpec) {
  const proxy = parseProxy(proxySpec);
  const target = url.searchParams.get('target') || '';
  const [tHost, tPortStr] = target.split(/:(?=\d+$)/);
  const tPort = Number(tPortStr || 80);
  const out = { proxyPort: proxy.port, target: `${tHost}:${tPort}` };

  out.greeting = await attempt(async () => {
    const s = connect({ hostname: proxy.host, port: proxy.port }, { secureTransport: 'starttls' });
    try {
      await deadline(s.opened, 12000, 'socks open');
      // VER=5, NMETHODS=2, methods = no-auth(0x00), user/pass(0x02)
      await writeAll(s, new Uint8Array([0x05, 0x02, 0x00, 0x02]));
      const reply = await deadline(readSome(s, { maxBytes: 2, ms: 8000 }), 9000, 'socks greeting');
      if (reply.byteLength < 2) return { bytes: reply.byteLength, raw: Array.from(reply), verdict: 'SHORT' };
      const [ver, method] = reply;
      return {
        raw: Array.from(reply.subarray(0, 8)),
        version: ver,
        method,
        verdict:
          ver !== 5 ? 'NOT_SOCKS5'
          : method === 0xff ? 'NO_ACCEPTABLE_METHOD'
          : method === 0x00 ? 'SOCKS5_NO_AUTH'
          : method === 0x02 ? 'SOCKS5_USERPASS'
          : `SOCKS5_METHOD_${method}`,
      };
    } finally {
      s.close().catch(() => {});
    }
  });
  return out;
}

// ---------------------------------------------------------------- router

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const authed = env.PROBE_TOKEN && request.headers.get("x-probe-token") === env.PROBE_TOKEN;
    const json = (o) => Response.json(o, { headers: { "cache-control": "no-store" } });

    if (url.pathname === "/") {
      return json({ probe: "tunnelfetch", authed, routes: ["/caps", "/net", "/starttls", "/proxy", "/socks5", "/nodecompat", "/nodetls"] });
    }
    if (!authed) return new Response("forbidden", { status: 403 });

    const t0 = Date.now();
    let body;
    try {
      if (url.pathname === "/caps") {
        body = {
          crypto: await capsCrypto(),
          platform: await capsPlatform(),
          timing: { ...capsTiming(), ...(await capsTimingAsync()) },
        };
      } else if (url.pathname === "/net") {
        body = await netPolicy(url);
      } else if (url.pathname === "/starttls") {
        body = await startTlsSuite(url);
      } else if (url.pathname === "/proxy") {
        const spec = request.headers.get("x-proxy");
        if (!spec) throw new Error("need x-proxy: host:port:user:pass");
        body = await proxySuite(url, spec);
      } else if (url.pathname === "/nodecompat") {
        body = {
          // Fingerprint of probe/src as it was when this Worker was deployed, injected by
          // scripts/deploy-probe.mjs. The drift test refuses to draw conclusions from a
          // deployment that does not match the probe source in the checkout it is running from.
          srcSha: env.PROBE_SRC_SHA ?? null,
          modules: await moduleInventory(),
          crypto: await nodeCryptoShape(),
        };
      } else if (url.pathname === "/nodetls") {
        // Needs a real proxy and a real origin: the whole question is whether node:tls will run a
        // handshake over a socket it did not dial, and demand the ORIGIN's identity while doing it.
        const spec = request.headers.get("x-proxy");
        if (!spec) throw new Error("need x-proxy: host:port:user:pass");
        const target = url.searchParams.get("target") || "example.com";
        const [ph, pp] = spec.split(':');
        body = {
          options: await tlsOptionSupport(target),
          freshSocket: await tlsOverFreshSocket(ph, pp),
          direct: await tlsDirect(target),
          overTunnel: await tlsOverConnectTunnel(spec, target),
          // If this ALSO succeeds, the identity gate is decorative and the feature is worse than
          // absent — a silent downgrade shaped like a working API.
          overTunnelWrongName: await tlsOverTunnelWrongName(spec, target, "probe.invalid"),
        };
      } else if (url.pathname === "/socks5") {
        const spec = request.headers.get("x-proxy");
        if (!spec) throw new Error("need x-proxy: host:port:user:pass");
        body = await socks5Probe(url, spec);
      } else {
        return new Response("not found", { status: 404 });
      }
    } catch (e) {
      return json({ error: `${e?.name}: ${e?.message}`, stack: e?.stack?.split("\n").slice(0, 4) }, 500);
    }
    return json({ route: url.pathname, wallMs: Date.now() - t0, result: body });
  },
};
