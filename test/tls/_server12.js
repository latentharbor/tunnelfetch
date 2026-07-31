// A minimal TLS 1.2 (RFC 5246) server for exercising the client handshake driver.
//
// Deliberately built straight on node:crypto rather than on the src/tls primitives: the two ends
// of these tests share no TLS code, so a client bug in the PRF, the AEAD framing, the transcript
// or the signature format cannot be cancelled out by the same bug on this side. In particular the
// ServerKeyExchange is signed with node:crypto, which emits the DER ECDSA form real servers send —
// exactly the shape a WebCrypto-only client gets wrong if it forgets the P1363 conversion.
//
// It genuinely verifies the client's Finished against its own transcript; a server that accepts
// anything would let a broken client pass every "positive" test. Each misbehaviour option makes
// the server wrong in exactly one way, so a negative test pins one failure and nothing else.
// `done` always resolves with a summary (never rejects): failures land in `summary.error` so a
// test can assert on the server's view even when the client aborted first.

import {
  constants as ncon,
  createCipheriv,
  createDecipheriv,
  createECDH,
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
} from 'node:crypto';
import { ByteReader, concat, readU16, readU24, u8, u16, u24 } from '../../src/util/bytes.js';
import { makeCert } from '../trust/_certs.js';

// ------------------------------------------------------------------ fixed tables (independent
// of src/tls/constants.js on purpose: agreeing with the RFC matters, agreeing with src does not)

const SUITES = {
  0xc02b: { hash: 'sha256', keyLen: 16, alg: 'aes-128-gcm', kind: 'ecdsa' }, // ECDHE_ECDSA_AES128
  0xc02f: { hash: 'sha256', keyLen: 16, alg: 'aes-128-gcm', kind: 'rsa' }, // ECDHE_RSA_AES128
  0xc02c: { hash: 'sha384', keyLen: 32, alg: 'aes-256-gcm', kind: 'ecdsa' }, // ECDHE_ECDSA_AES256
  0xc030: { hash: 'sha384', keyLen: 32, alg: 'aes-256-gcm', kind: 'rsa' }, // ECDHE_RSA_AES256
};

const CURVES = {
  0x0017: 'prime256v1',
  0x0018: 'secp384r1',
  0x0019: 'secp521r1',
  0x001d: 'x25519',
};

// SignatureAndHashAlgorithm values (RFC 5246 s7.4.1.4.1 / RFC 8446 s4.2.3 numbering).
const SIGN = {
  0x0403: { hash: 'sha256' }, // ecdsa_secp256r1_sha256 (node emits DER, as the wire wants)
  0x0503: { hash: 'sha384' }, // ecdsa_secp384r1_sha384
  0x0603: { hash: 'sha512' }, // ecdsa_secp521r1_sha512
  0x0401: { hash: 'sha256' }, // rsa_pkcs1_sha256
  0x0501: { hash: 'sha384' }, // rsa_pkcs1_sha384
  0x0601: { hash: 'sha512' }, // rsa_pkcs1_sha512
  0x0804: { hash: 'sha256', pss: true }, // rsa_pss_rsae_sha256
  0x0805: { hash: 'sha384', pss: true }, // rsa_pss_rsae_sha384
  0x0806: { hash: 'sha512', pss: true }, // rsa_pss_rsae_sha512
  0x0809: { hash: 'sha256', pss: true }, // rsa_pss_pss_sha256 (never offered by the client)
  0x0807: { eddsa: true }, // ed25519
};

const DEFAULT_SCHEME = { 'ec-p256': 0x0403, 'ec-p384': 0x0503, rsa: 0x0804, ed25519: 0x0807 };
const DEFAULT_CIPHER = { 'ec-p256': 0xc02b, 'ec-p384': 0xc02b, rsa: 0xc02f, ed25519: 0xc02b };

const ascii = (s) => Uint8Array.from(s, (ch) => ch.charCodeAt(0));
const hs = (type, body) => concat([u8(type), u24(body.byteLength), body]);

// ------------------------------------------------------------------ crypto helpers

const hmac = (hash, key, data) => new Uint8Array(createHmac(hash, key).update(data).digest());

/** PRF(secret, label, seed) per RFC 5246 s5, implemented from the RFC, not from src/tls. */
export function prf12(hash, secret, label, seed, length) {
  const labelSeed = concat([ascii(label), seed]);
  let a = labelSeed;
  const parts = [];
  let have = 0;
  while (have < length) {
    a = hmac(hash, secret, a);
    const t = hmac(hash, secret, concat([a, labelSeed]));
    parts.push(t);
    have += t.byteLength;
  }
  return concat(parts).subarray(0, length);
}

function seq8(seq) {
  const out = new Uint8Array(8);
  let v = seq;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function signSkx(scheme, privateKey, content) {
  const how = SIGN[scheme];
  if (!how) throw new Error(`_server12 has no signer for scheme 0x${scheme.toString(16)}`);
  if (how.eddsa) return new Uint8Array(nodeSign(null, content, privateKey));
  if (how.pss) {
    return new Uint8Array(
      nodeSign(how.hash, content, {
        key: privateKey,
        padding: ncon.RSA_PKCS1_PSS_PADDING,
        saltLength: ncon.RSA_PSS_SALTLEN_DIGEST,
      }),
    );
  }
  return new Uint8Array(nodeSign(how.hash, content, privateKey));
}

/**
 * An ECDHE key for one named group. Exported so a test can create one, keep it, and hand the
 * same key to two server runs (byte-for-byte reproducibility needs both ends deterministic).
 */
export function makeEcdhe(group) {
  const curve = CURVES[group];
  if (!curve) throw new Error(`_server12 has no curve for group 0x${group.toString(16)}`);
  if (curve === 'x25519') {
    const kp = generateKeyPairSync('x25519');
    const point = new Uint8Array(Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url'));
    return {
      group,
      point,
      shared(peerRaw) {
        const publicKey = createPublicKey({
          key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(peerRaw).toString('base64url') },
          format: 'jwk',
        });
        return new Uint8Array(diffieHellman({ privateKey: kp.privateKey, publicKey }));
      },
    };
  }
  const ecdh = createECDH(curve);
  ecdh.generateKeys();
  return {
    group,
    point: new Uint8Array(ecdh.getPublicKey()), // uncompressed by default
    shared: (peerRaw) => new Uint8Array(ecdh.computeSecret(Buffer.from(peerRaw))),
  };
}

// ------------------------------------------------------------------ identities

const identityCache = new Map();

/**
 * A cached server identity: a real self-signed certificate plus its keys, minted once per key
 * type because RSA generation is the slow part. `keys` (a node key pair) overrides the minted
 * pair for exotic curves _certs.js has no keyType for (P-521).
 */
export function serverIdentity(keyType = 'ec-p256', keys) {
  const cacheKey = keys ? null : keyType;
  if (cacheKey && identityCache.has(cacheKey)) return identityCache.get(cacheKey);
  const bundle = makeCert({
    subject: { CN: 'server.test', O: 'tunnelfetch tests' },
    keyType,
    ...(keys ? { keys } : {}),
    san: { dns: ['server.test'] },
  });
  const identity = {
    keyType,
    der: bundle.der,
    spkiDer: bundle.spkiDer,
    privateKey: bundle.privateKey,
  };
  if (cacheKey) identityCache.set(cacheKey, identity);
  return identity;
}

// ------------------------------------------------------------------ ClientHello decoding

function parseClientHello(body) {
  let o = 0;
  const legacyVersion = readU16(body, o);
  o += 2;
  const random = body.subarray(o, o + 32);
  o += 32;
  const sidLen = body[o];
  o += 1;
  const sessionId = body.subarray(o, o + sidLen);
  o += sidLen;
  const csLen = readU16(body, o);
  o += 2;
  const ciphers = [];
  for (let i = 0; i + 1 < csLen; i += 2) ciphers.push(readU16(body, o + i));
  o += csLen;
  const compLen = body[o];
  o += 1;
  const compressions = [...body.subarray(o, o + compLen)];
  o += compLen;
  const extensions = new Map();
  if (o < body.byteLength) {
    const extLen = readU16(body, o);
    o += 2;
    const end = o + extLen;
    while (o + 4 <= end) {
      const type = readU16(body, o);
      const len = readU16(body, o + 2);
      extensions.set(type, body.subarray(o + 4, o + 4 + len));
      o += 4 + len;
    }
  }
  return { legacyVersion, random, sessionId, ciphers, compressions, extensions };
}

const u16List = (data) => {
  const out = [];
  for (let i = 2; i + 1 < data.byteLength; i += 2) out.push(readU16(data, i));
  return out;
};

function decodeSni(data) {
  if (!data || data.byteLength < 5) return null;
  const nameLen = readU16(data, 3);
  return new TextDecoder().decode(data.subarray(5, 5 + nameLen));
}

function decodeAlpnList(data) {
  const out = [];
  if (!data || data.byteLength < 2) return out;
  let o = 2;
  while (o < data.byteLength) {
    const len = data[o];
    out.push(new TextDecoder().decode(data.subarray(o + 1, o + 1 + len)));
    o += 1 + len;
  }
  return out;
}

// ------------------------------------------------------------------ the server

class Bail extends Error {
  constructor(stage, message) {
    super(message);
    this.stage = stage;
  }
}

/**
 * Run one scripted TLS 1.2 server over `{readable, writable}` (one side of a duplexPair).
 *
 * Honest-path options:
 *   identity            from serverIdentity(); default cached ec-p256
 *   cipher              suite to select (default fits the identity's key type)
 *   sigScheme           SignatureAndHashAlgorithm for ServerKeyExchange (default per identity)
 *   group               ECDHE named group (default secp256r1)
 *   ecdhe               injected makeEcdhe() result, for determinism
 *   serverRandom / sessionId   fixed values ('echo' echoes the client's session id)
 *   ems                 echo extended_master_secret when offered (default true)
 *   renegotiationInfo   echo renegotiation_info when offered (default true)
 *   alpn                protocol to select, or null for none (default null)
 *   staple              DER OCSPResponse: echo status_request in the ServerHello and send a
 *                       CertificateStatus message right after Certificate (RFC 6066 s8)
 *   echoStatusRequest   echo status_request but send no CertificateStatus (legal)
 *   requestCertificate  send CertificateRequest (default false)
 *   packing             'per-message' (default) | 'single' | 'split' + splitSize
 *   explicitNonceXor    8 bytes XORed into the explicit GCM nonce (still unique per record)
 *
 * Misbehaviours (one per test): claimVersion, selectCipher, omitServerKeyExchange,
 * explicitCurve, tamperSignature, signWith, emptyCertList, echoSessionId via sessionId:'echo',
 * renegotiationInfoBody, emsBody, includeUnofferedExtension, extraExtensions ([[type, data]]),
 * doneBody, outOfOrder, helloRequest ('before-server-hello' | 'after-handshake'),
 * fatalAlertAfterServerHello, closeAfterServerHello, skipCcs, wrongFinished,
 * stapleWithoutEcho (CertificateStatus with no ServerHello echo), statusEchoBody (non-empty
 * echo), stapleStatusType (CertificateStatus status_type other than ocsp(1)).
 */
export function startServer12({ readable, writable }, opts = {}) {
  const state = {
    clientHello: null,
    clientMessageTypes: [],
    clientCertificateListLength: null,
    clientFinishedVerified: false,
    appDataReceived: new Uint8Array(0),
    sawCloseNotify: false,
    error: null,
  };
  const br = new ByteReader(readable);
  const writer = writable.getWriter();
  const done = run(br, writer, opts, state)
    .then(
      () => state,
      (e) => {
        state.error = { stage: e instanceof Bail ? e.stage : 'crash', message: String(e?.message ?? e) };
        return state;
      },
    )
    .then((s) => {
      // Always tear the transport down, whatever happened above. Cancelling our reader errors
      // the client-to-server pipe, which unblocks a client whose abort-path alert write is
      // parked on our (now absent) reads — without this, a test where the server stops reading
      // deadlocks the client's failure path instead of letting it reject.
      void br.cancel(new Error('_server12: server finished'));
      writer.close().catch(() => {});
      return s;
    });
  return { done };
}

async function run(br, writer, opts, state) {
  const identity = opts.identity ?? serverIdentity('ec-p256');
  const cipher = opts.selectCipher ?? opts.cipher ?? DEFAULT_CIPHER[identity.keyType];
  const suite = SUITES[cipher] ?? null;
  const sigScheme = opts.sigScheme ?? DEFAULT_SCHEME[identity.keyType];
  const group = opts.group ?? 0x0017;
  const serverRandom = opts.serverRandom ?? new Uint8Array(randomBytes(32));
  const packing = opts.packing ?? 'per-message';
  const splitSize = opts.splitSize ?? 7;

  let send = null; // { key, iv, seq, alg }
  let recv = null;
  let hsBuf = new Uint8Array(0);
  const transcript = [];
  const hashTranscript = () => {
    const h = createHash(suite.hash);
    for (const m of transcript) h.update(m);
    return new Uint8Array(h.digest());
  };

  // Writes are enqueued, never awaited: the WritableStream preserves order on its own, and a
  // client that (correctly) stops reading after deciding to abort must not deadlock this server
  // mid-flight — duplexPair's TransformStreams buffer nothing, so an awaited write to a reader
  // that has walked away would pend forever.
  const writeRecord = (type, payload) => {
    writer.write(concat([u8(type), u16(0x0303), u16(payload.byteLength), payload])).catch(() => {});
  };

  function encryptBody(type, plaintext) {
    const counter = seq8(send.seq);
    const explicit = opts.explicitNonceXor
      ? counter.map((b, i) => b ^ opts.explicitNonceXor[i])
      : counter;
    // AAD is seq || type || version || plaintext length (RFC 5246 s6.2.3.3); the nonce is the
    // 4-byte implicit salt plus the explicit part that travels on the wire (RFC 5288).
    const aad = concat([counter, u8(type), u16(0x0303), u16(plaintext.byteLength)]);
    const c = createCipheriv(send.alg, send.key, concat([send.iv, explicit]));
    c.setAAD(aad);
    const body = concat([
      explicit,
      new Uint8Array(c.update(plaintext)),
      new Uint8Array(c.final()),
      new Uint8Array(c.getAuthTag()),
    ]);
    send.seq += 1n;
    return body;
  }

  const sendRecord = (type, plaintext) =>
    send ? writeRecord(type, encryptBody(type, plaintext)) : writeRecord(type, plaintext);

  function decryptBody(header, body) {
    if (body.byteLength < 8 + 16 + 1) throw new Bail('record', 'client record too short for AEAD');
    const explicit = body.subarray(0, 8);
    const tag = body.subarray(body.byteLength - 16);
    const ct = body.subarray(8, body.byteLength - 16);
    const aad = concat([seq8(recv.seq), header.subarray(0, 3), u16(ct.byteLength)]);
    const d = createDecipheriv(recv.alg, recv.key, concat([recv.iv, explicit]));
    d.setAAD(aad);
    d.setAuthTag(tag);
    let out;
    try {
      out = concat([new Uint8Array(d.update(ct)), new Uint8Array(d.final())]);
    } catch {
      throw new Bail('record', `client record ${recv.seq} failed AEAD authentication`);
    }
    recv.seq += 1n;
    return out;
  }

  async function readRecord() {
    const header = (await br.readExactly(5, 'record header')).slice();
    const body = (await br.readExactly(readU16(header, 3), 'record body')).slice();
    if (recv && header[0] !== 20) return { type: header[0], data: decryptBody(header, body) };
    return { type: header[0], data: body };
  }

  /** One protocol event: a complete handshake message, a CCS, an alert, or app data. */
  async function nextEvent() {
    for (;;) {
      if (hsBuf.byteLength >= 4) {
        const need = 4 + readU24(hsBuf, 1);
        if (hsBuf.byteLength >= need) {
          const raw = hsBuf.subarray(0, need);
          hsBuf = hsBuf.subarray(need);
          return { msg: { type: raw[0], body: raw.subarray(4), raw } };
        }
      }
      const rec = await readRecord();
      if (rec.type === 22) hsBuf = concat([hsBuf, rec.data]);
      else if (rec.type === 20) return { ccs: rec.data };
      else if (rec.type === 21) return { alert: { level: rec.data[0], desc: rec.data[1] } };
      else if (rec.type === 23) return { appData: rec.data };
      else throw new Bail('record', `client sent unknown record type ${rec.type}`);
    }
  }

  function bail(stage, message, desc) {
    if (desc !== undefined) {
      try {
        sendRecord(21, Uint8Array.of(2, desc));
      } catch {
        /* client may be gone */
      }
    }
    throw new Bail(stage, message);
  }

  // ---------------------------------------------------------------- ClientHello
  const first = await nextEvent();
  if (first.alert) throw new Bail('client-hello', `client sent alert ${first.alert.desc} before ClientHello`);
  if (!first.msg || first.msg.type !== 1) {
    throw new Bail('client-hello', `expected ClientHello, got ${first.msg?.type ?? 'non-handshake'}`);
  }
  state.clientMessageTypes.push(1);
  const ch = parseClientHello(first.msg.body);
  transcript.push(first.msg.raw);
  state.clientHello = {
    legacyVersion: ch.legacyVersion,
    sessionId: ch.sessionId.slice(),
    ciphers: ch.ciphers,
    compressions: ch.compressions,
    hasSupportedVersions: ch.extensions.has(43),
    hasKeyShare: ch.extensions.has(51),
    hasPskModes: ch.extensions.has(45),
    hasEms: ch.extensions.has(23),
    hasRenegotiationInfo: ch.extensions.has(0xff01),
    hasEcPointFormats: ch.extensions.has(11),
    hasStatusRequest: ch.extensions.has(5),
    sni: decodeSni(ch.extensions.get(0)),
    alpn: decodeAlpnList(ch.extensions.get(16)),
    groups: ch.extensions.has(10) ? u16List(ch.extensions.get(10)) : [],
    sigSchemes: ch.extensions.has(13) ? u16List(ch.extensions.get(13)) : [],
  };

  if (opts.helloRequest === 'before-server-hello') {
    // HelloRequest is never part of the transcript (RFC 5246 s7.4.1.1) — not that the client
    // under test should ever get far enough for that to matter.
    writeRecord(22, hs(0, new Uint8Array(0)));
  }

  // ---------------------------------------------------------------- server flight
  const emsActive = state.clientHello.hasEms && opts.ems !== false;
  const alpnSelected = opts.alpn && state.clientHello.alpn.includes(opts.alpn) ? opts.alpn : null;
  const sessionId =
    opts.sessionId === 'echo'
      ? ch.sessionId
      : opts.sessionId ?? new Uint8Array(randomBytes(32));

  const ext = (type, data) => concat([u16(type), u16(data.byteLength), data]);
  const extensions = [];
  if (state.clientHello.hasRenegotiationInfo && opts.renegotiationInfo !== false) {
    extensions.push(ext(0xff01, opts.renegotiationInfoBody ?? Uint8Array.of(0)));
  }
  if (emsActive) extensions.push(ext(23, opts.emsBody ?? new Uint8Array(0)));
  if (state.clientHello.hasEcPointFormats) extensions.push(ext(11, Uint8Array.of(1, 0)));
  // RFC 6066 s8: the empty status_request echo that licenses a later CertificateStatus message.
  // `staple` implies the echo; `echoStatusRequest` echoes without ever sending the message
  // (legal); `stapleWithoutEcho` sends the message with no echo (illegal, for negative tests).
  if (state.clientHello.hasStatusRequest && (opts.staple || opts.echoStatusRequest)) {
    extensions.push(ext(5, opts.statusEchoBody ?? new Uint8Array(0)));
  }
  if (alpnSelected) {
    const name = ascii(alpnSelected);
    extensions.push(ext(16, concat([u16(name.byteLength + 1), u8(name.byteLength), name])));
  }
  if (opts.includeUnofferedExtension) extensions.push(ext(35, new Uint8Array(0))); // session_ticket
  // Arbitrary extension injection, for misbehaviours the named options above do not cover —
  // e.g. echoing a 1.3-only extension the client DID offer, which "unoffered" checks cannot see.
  for (const [type, data] of opts.extraExtensions ?? []) extensions.push(ext(type, data));
  const extBlock = concat(extensions);
  const shBody = concat([
    u16(opts.claimVersion ?? 0x0303),
    serverRandom,
    u8(sessionId.byteLength),
    sessionId,
    u16(cipher),
    u8(0),
    u16(extBlock.byteLength),
    extBlock,
  ]);
  const serverHello = hs(2, shBody);

  if (opts.closeAfterServerHello) {
    writeRecord(22, serverHello);
    return; // the wrapper closes the writer, giving EOF with no close_notify
  }
  if (opts.fatalAlertAfterServerHello) {
    writeRecord(22, serverHello);
    writeRecord(21, Uint8Array.of(2, opts.fatalAlertAfterServerHello));
    return;
  }

  const chain = opts.emptyCertList ? [] : opts.chain ?? [identity.der];
  const certList = concat(chain.map((der) => concat([u24(der.byteLength), der])));
  const certificate = hs(11, concat([u24(certList.byteLength), certList]));

  const kx = opts.ecdhe ?? makeEcdhe(group);
  const params = opts.explicitCurve
    ? concat([u8(1), Uint8Array.of(0x01, 0x07)]) // ECCurveType explicit_prime + token junk
    : concat([u8(3), u16(group), u8(kx.point.byteLength), kx.point]);
  const signed = concat([ch.random, serverRandom, params]);
  let signature = signSkx(sigScheme, opts.signWith ?? identity.privateKey, signed);
  if (opts.tamperSignature) {
    signature = signature.slice();
    signature[signature.byteLength - 1] ^= 0x01; // flips an s-value bit: still valid DER
  }
  const serverKeyExchange = hs(12, concat([params, u16(sigScheme), u16(signature.byteLength), signature]));

  const certificateRequest = hs(
    13,
    concat([
      Uint8Array.of(2, 1, 64), // certificate_types: rsa_sign, ecdsa_sign
      u16(6),
      u16(0x0403),
      u16(0x0804),
      u16(0x0401), // supported_signature_algorithms
      u16(0), // certificate_authorities: none
    ]),
  );
  const serverHelloDone = hs(14, opts.doneBody ?? new Uint8Array(0));

  const flight = [serverHello, certificate];
  const stapleDer = opts.staple ?? opts.stapleWithoutEcho;
  if (stapleDer) {
    // CertificateStatus (RFC 6066 s8): status_type ocsp(1) + u24-length DER OCSPResponse,
    // immediately after Certificate.
    flight.push(hs(22, concat([u8(opts.stapleStatusType ?? 1), u24(stapleDer.byteLength), stapleDer])));
  }
  if (!opts.omitServerKeyExchange) flight.push(serverKeyExchange);
  if (opts.outOfOrder) {
    // Swap Certificate and ServerKeyExchange: same messages, illegal order.
    [flight[1], flight[2]] = [flight[2], flight[1]];
  }
  if (opts.requestCertificate) flight.push(certificateRequest);
  flight.push(serverHelloDone);
  for (const m of flight) transcript.push(m);

  if (packing === 'single') {
    writeRecord(22, concat(flight));
  } else if (packing === 'split') {
    const all = concat(flight);
    for (let i = 0; i < all.byteLength; i += splitSize) {
      writeRecord(22, all.subarray(i, Math.min(i + splitSize, all.byteLength)));
    }
  } else {
    for (const m of flight) writeRecord(22, m);
  }

  // ---------------------------------------------------------------- client flight
  let clientPoint = null;
  let master = null;
  let sendPending = null;
  for (;;) {
    const ev = await nextEvent();
    if (ev.alert) {
      throw new Bail(
        'client-flight',
        `client sent ${ev.alert.level === 2 ? 'fatal' : 'warning'} alert ${ev.alert.desc} instead of its flight`,
      );
    }
    if (ev.msg) {
      const { type, body, raw } = ev.msg;
      state.clientMessageTypes.push(type);
      if (type === 11) {
        if (!opts.requestCertificate) bail('client-flight', 'unsolicited client Certificate', 10);
        if (clientPoint) bail('client-flight', 'client Certificate after ClientKeyExchange', 10);
        state.clientCertificateListLength = readU24(body, 0);
        transcript.push(raw);
        continue;
      }
      if (type === 16) {
        if (opts.requestCertificate && state.clientCertificateListLength === null) {
          bail('client-flight', 'ClientKeyExchange before the requested Certificate', 10);
        }
        if (body.byteLength !== 1 + body[0]) {
          bail('client-flight', 'malformed ClientKeyExchange ECPoint', 50);
        }
        clientPoint = body.subarray(1).slice();
        transcript.push(raw);
        continue;
      }
      bail('client-flight', `unexpected client handshake type ${type} before ChangeCipherSpec`, 10);
    }
    if (ev.ccs) {
      if (ev.ccs.byteLength !== 1 || ev.ccs[0] !== 1) {
        bail('client-flight', 'malformed ChangeCipherSpec', 10);
      }
      if (!clientPoint) bail('client-flight', 'ChangeCipherSpec before ClientKeyExchange', 10);
      if (!suite) bail('client-flight', `client continued under unknown suite 0x${cipher.toString(16)}`);
      break;
    }
    if (ev.appData) bail('client-flight', 'application data during the handshake', 10);
  }

  // Keys. The session hash for extended master secret is the transcript through
  // ClientKeyExchange — hashed now, before Finished joins it (RFC 7627 s3).
  const preMaster = kx.shared(clientPoint);
  master = emsActive
    ? prf12(suite.hash, preMaster, 'extended master secret', hashTranscript(), 48)
    : prf12(suite.hash, preMaster, 'master secret', concat([ch.random, serverRandom]), 48);
  // key_block: client key, server key, client IV(4), server IV(4). No MAC keys for AEAD.
  const block = prf12(
    suite.hash,
    master,
    'key expansion',
    concat([serverRandom, ch.random]),
    2 * suite.keyLen + 8,
  );
  let o = 0;
  const take = (n) => block.subarray(o, (o += n));
  recv = { key: take(suite.keyLen), iv: null, seq: 0n, alg: suite.alg };
  sendPending = { key: take(suite.keyLen), iv: null, seq: 0n, alg: suite.alg };
  recv.iv = take(4);
  sendPending.iv = take(4);

  // The client Finished, now encrypted. Verify it for real: a server that accepts anything
  // would let a broken client pass every positive test in the suite.
  const finEv = await nextEvent();
  if (!finEv.msg || finEv.msg.type !== 20) {
    bail('client-finished', `expected client Finished, got ${JSON.stringify(finEv.alert ?? finEv.msg?.type)}`, 10);
  }
  state.clientMessageTypes.push(20);
  const expectVerify = prf12(suite.hash, master, 'client finished', hashTranscript(), 12);
  const got = finEv.msg.body;
  let diff = got.byteLength ^ expectVerify.byteLength;
  for (let i = 0; i < Math.min(got.byteLength, expectVerify.byteLength); i++) diff |= got[i] ^ expectVerify[i];
  if (diff !== 0) {
    bail('client-finished', 'client Finished verify_data mismatch', 51);
  }
  state.clientFinishedVerified = true;
  transcript.push(finEv.msg.raw);

  // ---------------------------------------------------------------- server CCS + Finished
  let serverVerify = prf12(suite.hash, master, 'server finished', hashTranscript(), 12);
  if (opts.wrongFinished) {
    serverVerify = serverVerify.slice();
    serverVerify[0] ^= 0xff;
  }
  if (opts.skipCcs) {
    // Finished with no ChangeCipherSpec first — sent in plaintext so the failure the client
    // reports is the missing key change, not an undecryptable record.
    writeRecord(22, hs(20, serverVerify));
  } else {
    writeRecord(20, Uint8Array.of(1));
    send = sendPending;
    sendRecord(22, hs(20, serverVerify));
  }
  if (opts.helloRequest === 'after-handshake') {
    sendRecord(22, hs(0, new Uint8Array(0)));
  }

  // ---------------------------------------------------------------- application data: echo
  const appChunks = [];
  for (;;) {
    let ev;
    try {
      ev = await nextEvent();
    } catch (e) {
      if (e instanceof Bail) throw e;
      throw new Bail('app', `client transport ended without close_notify (${e?.message})`);
    }
    if (ev.appData) {
      appChunks.push(ev.appData);
      sendRecord(23, ev.appData);
      continue;
    }
    if (ev.alert) {
      if (ev.alert.desc === 0) {
        state.sawCloseNotify = true;
        try {
          sendRecord(21, Uint8Array.of(1, 0));
        } catch {
          /* client already gone */
        }
        break; // the wrapper closes the writer after our close_notify
      }
      throw new Bail('app', `client sent alert ${ev.alert.desc} after the handshake`);
    }
    if (ev.msg) throw new Bail('app', `unexpected client handshake type ${ev.msg.type} after the handshake`);
    if (ev.ccs) throw new Bail('app', 'unexpected ChangeCipherSpec after the handshake');
  }
  state.appDataReceived = concat(appChunks);
}
