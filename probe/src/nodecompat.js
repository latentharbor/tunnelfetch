// Does workerd's Node compatibility layer make this package unnecessary?
//
// The package exists because TLS inside a proxy tunnel could not be done natively: `startTls()`
// verifies the peer against the hostname passed to `connect()`, which inside a tunnel is the
// PROXY, so the identity check is structurally wrong and cannot be overridden. Node solves the
// same problem with `tls.connect({ socket })` — layering TLS over an already-open socket, with
// `servername` naming the identity to demand. If workerd implements that option, the userland TLS
// stack is obsolete for anyone willing to turn on `nodejs_compat`.
//
// Cloudflare's docs list `node:tls` as "partially supported" and name connect/TLSSocket/
// checkServerIdentity/createSecureContext as available, but say nothing either way about the
// `socket` option. That silence is the whole reason for this file: the last time docs and source
// reading agreed about `startTls`, the edge disagreed with both. Everything here is feature
// detection against observed behaviour — a call that does not throw proves nothing on its own, so
// each probe reads real bytes back before it claims success.
//
// Modules are loaded with dynamic import inside try/catch rather than statically, so a module that
// is entirely absent is a recorded result instead of a Worker that fails to start.

const enc = new TextEncoder();
const dec = new TextDecoder();

async function attempt(fn) {
  try {
    const v = await fn();
    return { ok: true, v: v === undefined ? true : v };
  } catch (e) {
    return { ok: false, err: `${e?.name || 'Error'}: ${e?.message || String(e)}` };
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

const load = (spec) => attempt(async () => {
  const m = await import(/* @vite-ignore */ spec);
  const ns = m.default ?? m;
  // Names only. What matters is which of them are real functions versus present-but-throwing,
  // which the behavioural probes below settle.
  return Object.keys(ns).sort().slice(0, 60);
});

/** What is importable at all, and what each module claims to expose. */
export async function moduleInventory() {
  const specs = ['node:net', 'node:tls', 'node:crypto', 'node:zlib', 'node:stream',
    'node:http', 'node:https', 'node:buffer', 'node:dns'];
  const out = {};
  for (const s of specs) out[s] = await load(s);
  return out;
}

/**
 * The synchronous crypto question, which is separate from the TLS one and matters even if TLS
 * stays in userland: every AEAD operation here is an `await crypto.subtle.decrypt`, one per TLS
 * record. If node:crypto offers working synchronous AES-GCM, the awaits disappear from the record
 * loop. Correctness is checked with a round trip and a known SHA-256 vector, because "the function
 * exists" is not the same claim as "the function works".
 */
export async function nodeCryptoShape() {
  const mod = await attempt(() => import('node:crypto'));
  if (!mod.ok) return { importable: false, err: mod.err };
  const c = mod.v.default ?? mod.v;

  const sha256Empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  return {
    importable: true,
    hasWebcrypto: typeof c.webcrypto === 'object',
    createHash: await attempt(() => {
      const h = c.createHash('sha256').update(new Uint8Array(0)).digest('hex');
      if (h !== sha256Empty) throw new Error(`SHA-256 of empty input is ${h}, not the RFC value`);
      return 'sync, matches vector';
    }),
    createHmac: await attempt(() => typeof c.createHmac('sha256', new Uint8Array(32)).update('x').digest('hex')),
    aesGcmSync: await attempt(() => {
      // A TLS-shaped round trip: 12-byte nonce, AAD, 16-byte tag, all synchronous.
      const key = new Uint8Array(16).fill(7);
      const iv = new Uint8Array(12).fill(9);
      const aad = new Uint8Array([23, 3, 3, 0, 32]);
      const cipher = c.createCipheriv('aes-128-gcm', key, iv);
      cipher.setAAD(aad);
      const ct = Buffer.concat([cipher.update(Buffer.from('hello tls')), cipher.final()]);
      const tag = cipher.getAuthTag();
      const d = c.createDecipheriv('aes-128-gcm', key, iv);
      d.setAAD(aad);
      d.setAuthTag(tag);
      const pt = Buffer.concat([d.update(ct), d.final()]).toString();
      if (pt !== 'hello tls') throw new Error(`round trip produced ${JSON.stringify(pt)}`);
      return 'sync AES-128-GCM round trip with AAD and tag';
    }),
    x25519: await attempt(() => {
      const a = c.generateKeyPairSync('x25519');
      const b = c.generateKeyPairSync('x25519');
      const s1 = c.diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey });
      const s2 = c.diffieHellman({ privateKey: b.privateKey, publicKey: a.publicKey });
      if (!s1.equals(s2)) throw new Error('shared secrets disagree');
      return `sync X25519, ${s1.length}-byte secret`;
    }),
    // A built-in root store would make the bundled 121-anchor snapshot — and its staleness
    // maintenance — unnecessary.
    rootCertificates: await attempt(async () => {
      const tls = (await import('node:tls')).default ?? (await import('node:tls'));
      const r = tls.rootCertificates;
      if (!Array.isArray(r)) throw new Error(`rootCertificates is ${typeof r}`);
      return { count: r.length, first: String(r[0] ?? '').slice(0, 32) };
    }),
  };
}

/**
 * Which option bags does tls.connect() even accept? The runtime rejects some options outright, and
 * a blanket failure hides which. This tries them from bare upward and records the first refusal.
 */
export async function tlsOptionSupport(host, port = 443) {
  const mod = await attempt(() => import('node:tls'));
  if (!mod.ok) return { importable: false, err: mod.err };
  const tls = mod.v.default ?? mod.v;
  const bags = {
    bare: { host, port },
    servername: { host, port, servername: host },
    rejectUnauthorized: { host, port, servername: host, rejectUnauthorized: true },
    alpn: { host, port, servername: host, ALPNProtocols: ['http/1.1'] },
    ca: { host, port, servername: host, ca: [] },
    checkServerIdentity: { host, port, servername: host, checkServerIdentity: () => undefined },
  };
  const out = {};
  for (const [name, opts] of Object.entries(bags)) {
    out[name] = await attempt(() => {
      // Construction alone is the question here; the socket is destroyed immediately.
      const s = tls.connect(opts);
      s.on('error', () => {});
      s.destroy();
      return 'accepted';
    });
  }
  return out;
}

/** Does node:tls reach a real server on its own, without any tunnel? The easy case first. */
export async function tlsDirect(host, port = 443) {
  const mod = await attempt(() => import('node:tls'));
  if (!mod.ok) return { importable: false, err: mod.err };
  const tls = mod.v.default ?? mod.v;

  return attempt(() => deadline(new Promise((resolve, reject) => {
    let sock;
    try {
      sock = tls.connect({ host, port, servername: host }, () => {
        // `authorized` is the only thing that distinguishes "handshake completed" from
        // "handshake completed and the certificate was actually trusted".
        const info = {
          authorized: sock.authorized,
          authorizationError: String(sock.authorizationError ?? ''),
          protocol: sock.getProtocol?.() ?? null,
          cipher: sock.getCipher?.()?.name ?? null,
          alpn: sock.alpnProtocol ?? null,
        };
        sock.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
        let first = '';
        sock.on('data', (d) => {
          // Reading real bytes back is the proof; a connect callback alone proves nothing.
          if (!first) {
            first = String(d).slice(0, 40).replace(/\r\n/g, ' ');
            resolve({ ...info, firstBytes: first });
            sock.destroy();
          }
        });
      });
      sock.on('error', (e) => reject(new Error(`${e?.code ?? e?.name}: ${e?.message}`)));
    } catch (e) {
      reject(e);
    }
  }), 15000, 'tls.connect direct'));
}

/**
 * Control for the tunnel probe: a socket that has NEVER been read from. If TLS cannot take over
 * even this one, then `{socket}` is unusable on this runtime outright and the CONNECT exchange is
 * irrelevant; if it CAN, then the blocker is specifically that reading the proxy's reply — which
 * any tunnel requires — leaves a reader the TLS layer will not wrest away.
 *
 * Success here is a ClientHello leaving the socket, not a completed handshake: the peer is only a
 * TCP endpoint, so bytes written is the signal that the TLS layer engaged at all.
 */
export async function tlsOverFreshSocket(host, port) {
  const net = await attempt(() => import('node:net'));
  const tlsm = await attempt(() => import('node:tls'));
  if (!net.ok || !tlsm.ok) return { err: net.err ?? tlsm.err };
  const NET = net.v.default ?? net.v;
  const TLS = tlsm.v.default ?? tlsm.v;

  return attempt(() => deadline(new Promise((resolve, reject) => {
    const stages = { bytesWritten: 0 };
    const sock = NET.connect({ host, port: Number(port) });
    sock.on('error', (e) => reject(new Error(`net: ${e?.code ?? e?.name}: ${e?.message}`)));
    sock.on('connect', () => {
      stages.netConnect = true;
      const rawWrite = sock.write.bind(sock);
      sock.write = (chunk, ...rest) => {
        stages.bytesWritten += chunk?.length ?? 0;
        return rawWrite(chunk, ...rest);
      };
      let tsock;
      try {
        tsock = TLS.connect({ socket: sock, servername: 'probe.invalid' }, () => {
          // The byte counter can only see writes that go through the JS `write` method, so it
          // cannot by itself prove nothing was sent. These cannot be faked: a connection carrying
          // TLS has a negotiated protocol version and cipher suite, and one that does not, does not.
          resolve({
            ...stages,
            callbackFired: true,
            protocol: tsock.getProtocol?.() ?? null,
            cipher: tsock.getCipher?.()?.name ?? null,
            authorized: tsock.authorized ?? null,
            authorizationError: String(tsock.authorizationError ?? ''),
            peerCert: Object.keys(tsock.getPeerCertificate?.() ?? {}).length,
          });
        });
        tsock.on('error', (e) => resolve({
          ...stages,
          verdict: stages.bytesWritten > 0
            ? 'TLS engaged: a ClientHello was written'
            : 'TLS never wrote anything',
          tlsError: `${e?.code ?? e?.name}: ${e?.message}`,
        }));
      } catch (e) {
        resolve({ ...stages, verdict: 'tls.connect({socket}) threw', err: e?.message });
      }
      setTimeout(() => resolve({ ...stages, verdict: 'no error, no completion' }), 6000);
    });
  }), 12000, 'tls over fresh socket'));
}

/**
 * THE decisive probe. Open a CONNECT tunnel over node:net, then ask node:tls to run the handshake
 * over that already-open socket while demanding the ORIGIN's identity — the thing `startTls()`
 * structurally cannot do. If this returns authorized:true with real response bytes, the reason
 * this package implements TLS in JavaScript no longer holds under `nodejs_compat`.
 */
export async function tlsOverConnectTunnel(proxySpec, target, port = 443, claimName = null) {
  // `claimName` lets the caller demand an identity the origin's certificate does not carry, which
  // is how the negative case below checks that the identity gate is real rather than decorative.
  const servername = claimName ?? target;
  const [phost, pport, puser, ppass] = proxySpec.split(':');
  const net = await attempt(() => import('node:net'));
  const tlsm = await attempt(() => import('node:tls'));
  if (!net.ok) return { stage: 'import node:net', err: net.err };
  if (!tlsm.ok) return { stage: 'import node:tls', err: tlsm.err };
  const NET = net.v.default ?? net.v;
  const TLS = tlsm.v.default ?? tlsm.v;

  return attempt(() => deadline(new Promise((resolve, reject) => {
    const stages = {};
    let sock;
    try {
      sock = NET.connect({ host: phost, port: Number(pport) });
    } catch (e) {
      return reject(new Error(`net.connect threw synchronously: ${e?.message}`));
    }
    sock.on('error', (e) => reject(new Error(`net socket: ${e?.code ?? e?.name}: ${e?.message}`)));

    sock.on('connect', () => {
      stages.netConnect = true;
      const auth = puser
        ? `Proxy-Authorization: Basic ${btoa(`${puser}:${ppass ?? ''}`)}\r\n`
        : '';
      sock.write(`CONNECT ${target}:${port} HTTP/1.1\r\nHost: ${target}:${port}\r\n${auth}\r\n`);
    });

    // Read the CONNECT reply in PAUSED mode, not flowing mode. The runtime's tls.connect({socket})
    // takes ownership of the underlying stream by releasing its reader lock, and it refuses while a
    // read is outstanding — "Cannot call releaseLock() on a reader with outstanding read promises",
    // with zero bytes of ClientHello written. A 'data' listener keeps exactly such a read pending,
    // so the handshake could never start. Paused mode leaves no read in flight between chunks.
    let head = '';
    let handedOver = false;
    const tryHandover = () => {
      if (handedOver) return;
      const i = head.indexOf('\r\n\r\n');
      if (i < 0) return;
      handedOver = true;
      const status = Number(/^HTTP\/\d\.\d (\d{3})/.exec(head)?.[1] ?? 0);
      stages.connectStatus = status;
      if (status < 200 || status > 299) {
        return reject(new Error(`proxy refused CONNECT: ${head.split('\r\n')[0]}`));
      }
      sock.removeAllListeners('readable');
      sock.pause();
      // One turn of the loop for any in-flight read to settle before ownership changes hands.
      setTimeout(() => startTls(), 0);
    };

    const startTls = () => {
      const rawWrite = sock.write.bind(sock);
      stages.bytesWrittenAfterTlsAttach = 0;
      sock.write = (chunk, ...rest) => {
        stages.bytesWrittenAfterTlsAttach += chunk?.length ?? 0;
        return rawWrite(chunk, ...rest);
      };
      setTimeout(() => reject(new Error(`no handshake completed; ${JSON.stringify(stages)}`)), 12000);
      let tsock;
      try {
        tsock = TLS.connect({ socket: sock, servername }, () => {
          stages.tlsHandshake = true;
          const info = {
            ...stages,
            servernameDemanded: servername,
            authorized: tsock.authorized,
            authorizationError: String(tsock.authorizationError ?? ''),
            protocol: tsock.getProtocol?.() ?? null,
            cipher: tsock.getCipher?.()?.name ?? null,
            alpn: tsock.alpnProtocol ?? null,
            peerCN: tsock.getPeerCertificate?.()?.subject?.CN ?? null,
          };
          tsock.write(`GET / HTTP/1.1\r\nHost: ${target}\r\nConnection: close\r\n\r\n`);
          let first = '';
          tsock.on('data', (d2) => {
            if (!first) {
              first = String(d2).slice(0, 48).replace(/\r\n/g, ' ');
              resolve({ ...info, firstBytes: first });
              tsock.destroy();
            }
          });
        });
        tsock.on('error', (e) => reject(new Error(
          `tls over tunnel: ${e?.code ?? e?.name}: ${e?.message} (stages ${JSON.stringify(stages)})`)));
      } catch (e) {
        reject(new Error(`tls.connect({socket}) threw: ${e?.message} (stages ${JSON.stringify(stages)})`));
      }
    };

    sock.on('readable', () => {
      let chunk;
      while ((chunk = sock.read()) !== null) {
        head += String(chunk);
        if (head.includes('\r\n\r\n')) break;
      }
      tryHandover();
    });
  }), 25000, 'tls over CONNECT tunnel'));
}

/**
 * A wrong `servername` must be REFUSED. If the tunnel probe succeeds but this one also succeeds,
 * then node:tls is completing a handshake without checking the identity we asked for, which would
 * be worse than not having it at all — a silent downgrade wearing the shape of a working feature.
 */
export async function tlsOverTunnelWrongName(proxySpec, target, claimed) {
  return tlsOverConnectTunnel(proxySpec, target, 443, claimed);
}
