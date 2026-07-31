// HTTP CONNECT tunnelling against a scripted in-memory proxy.
//
// The single most important case in this file: tunnel payload arriving in the SAME chunk as the
// CONNECT reply's terminating CRLFCRLF. Those bytes belong to the peer; losing them truncates the
// first TLS record and surfaces much later as an inexplicable handshake failure. Everything else
// is exact wire bytes (requests are asserted byte-for-byte, not by substring) and failure taxonomy
// (every failure has a stable err.code and a message naming the concrete value the proxy sent).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openHttpConnect } from '../../src/proxy/http-connect.js';
import { codes } from '../../src/errors.js';
import { concat, latin1, utf8 } from '../../src/util/bytes.js';
import { collect, rejectsWithCode } from '../_harness.js';
import { fakeProxy } from './_fakeproxy.js';

const PROXY = Object.freeze({ protocol: 'http', hostname: 'proxy.example', port: 3128 });
const TARGET = Object.freeze({ hostname: 'example.com', port: 443 });
const CRLFCRLF = '\r\n\r\n';
const OK_REPLY = 'HTTP/1.1 200 Connection established\r\n\r\n';

// btoa('user:pass') — computed independently of the implementation's own encoder.
const USERPASS_B64 = 'dXNlcjpwYXNz';
// RFC 7617: credentials are UTF-8 encoded before base64. This is the base64 of the UTF-8 bytes of
// 'aladdin:öpen sésame' (21 bytes: ö and é are two bytes each), NOT of any latin-1/UCS-2 mangling.
const UTF8_CREDS_B64 = 'YWxhZGRpbjrDtnBlbiBzw6lzYW1l';

const EXPECT_PLAIN_REQUEST =
  'CONNECT example.com:443 HTTP/1.1\r\n' +
  'Host: example.com:443\r\n' +
  'Proxy-Connection: keep-alive\r\n' +
  '\r\n';

/** A proxy that reads the CONNECT request, replies, optionally echoes, then hangs up. */
function proxyReplying(reply, { chunking, echo = 0 } = {}) {
  const captured = { request: null };
  const fake = fakeProxy(async (peer) => {
    captured.request = await peer.readUntil(CRLFCRLF);
    peer.send(reply, chunking);
    if (echo > 0) peer.send(await peer.readExactly(echo));
    peer.end();
  });
  return { fake, captured };
}

const open = (fake, { proxy = PROXY, target = TARGET, ...rest } = {}) =>
  openHttpConnect({ proxy, target, connect: fake.connect, ...rest });

// ---------------------------------------------------------------------------- happy paths

test('CONNECT: HTTP/1.1 200 opens a transparent tunnel; request bytes are exact', async () => {
  const { fake, captured } = proxyReplying(OK_REPLY, { echo: 4 });
  const tunnel = await open(fake);
  // The request must be exactly these bytes: an extra header, a reordered line or a stray space
  // is a real-world interop break, so substring checks are not good enough.
  assert.equal(latin1(captured.request), EXPECT_PLAIN_REQUEST);

  const w = tunnel.writable.getWriter();
  await w.write(utf8('ping'));
  w.releaseLock();
  // The write went to the raw socket and came back: the tunnel is a transparent byte pipe.
  assert.equal(latin1(await collect(tunnel.readable)), 'ping');
  await tunnel.close();
  assert.equal(fake.call.closeCalls, 1, 'tunnel.close() must close the underlying socket');
});

test('CONNECT: HTTP/1.0 200 OK works — real proxies answer 1.1 requests with 1.0', async () => {
  const { fake } = proxyReplying('HTTP/1.0 200 OK\r\n\r\n', { echo: 2 });
  const tunnel = await open(fake);
  const w = tunnel.writable.getWriter();
  await w.write(utf8('hi'));
  w.releaseLock();
  assert.equal(latin1(await collect(tunnel.readable)), 'hi');
  await tunnel.close();
});

test('CONNECT: any 2xx opens the tunnel (204 observed from filtering appliances)', async () => {
  const { fake } = proxyReplying('HTTP/1.1 204 No Content\r\n\r\n');
  const tunnel = await open(fake);
  assert.equal((await collect(tunnel.readable)).byteLength, 0);
  await tunnel.close();
});

test('CONNECT: extra reply headers (Via, X-Cache, Proxy-Agent) are tolerated', async () => {
  const reply =
    'HTTP/1.1 200 Connection established\r\n' +
    'Via: 1.1 corp-egress-7\r\n' +
    'X-Cache: MISS from corp-egress-7\r\n' +
    'Proxy-Agent: FakeProxy/1.0\r\n' +
    '\r\n';
  const { fake } = proxyReplying(reply, { echo: 2 });
  const tunnel = await open(fake);
  const w = tunnel.writable.getWriter();
  await w.write(utf8('ok'));
  w.releaseLock();
  assert.equal(latin1(await collect(tunnel.readable)), 'ok');
  await tunnel.close();
});

// TLS-record-shaped payload: exactly what a proxy racing the server's first flight would send,
// and exactly the bytes whose loss produces the delayed handshake failure described up top.
const EARLY = Uint8Array.from([0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0xff, 0x00, 0xfe]);

test('CONNECT: payload in the SAME chunk as CRLFCRLF is the FIRST tunnel bytes, none lost', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readUntil(CRLFCRLF);
    // One write: reply and payload arrive in a single read on the client side.
    peer.send(concat([utf8(OK_REPLY), EARLY]));
    peer.send(utf8('later'));
    peer.end();
  });
  const tunnel = await open(fake);
  const got = await collect(tunnel.readable);
  assert.deepEqual(got, concat([EARLY, utf8('later')]));
  await tunnel.close();
});

test('CONNECT: reply plus payload fed one byte at a time delivers the identical stream', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readUntil(CRLFCRLF);
    peer.send(concat([utf8(OK_REPLY), EARLY, utf8('later')]), 'bytes');
    peer.end();
  });
  const tunnel = await open(fake);
  assert.deepEqual(await collect(tunnel.readable), concat([EARLY, utf8('later')]));
  await tunnel.close();
});

test('CONNECT: a chunk boundary inside the CRLFCRLF itself does not desync the payload', async () => {
  const wire = concat([utf8(OK_REPLY), EARLY]);
  const fake = fakeProxy(async (peer) => {
    await peer.readUntil(CRLFCRLF);
    // 37 splits the terminating CRLFCRLF in half (header block is 39 bytes): the delimiter
    // spans two chunks, which is the case naive indexOf-per-chunk scanners get wrong.
    peer.send(wire, [37, 4]);
    peer.end();
  });
  const tunnel = await open(fake);
  assert.deepEqual(await collect(tunnel.readable), EARLY);
  await tunnel.close();
});

// ---------------------------------------------------------------------------- request bytes

test('CONNECT: credentials become Proxy-Authorization: Basic btoa(user:pass), exactly', async () => {
  const { fake, captured } = proxyReplying(OK_REPLY);
  const tunnel = await open(fake, {
    proxy: { ...PROXY, username: 'user', password: 'pass' },
  });
  assert.equal(
    latin1(captured.request),
    'CONNECT example.com:443 HTTP/1.1\r\n' +
      'Host: example.com:443\r\n' +
      `Proxy-Authorization: Basic ${USERPASS_B64}\r\n` +
      'Proxy-Connection: keep-alive\r\n' +
      '\r\n',
  );
  await tunnel.close();
});

test('CONNECT: non-ASCII password is UTF-8 encoded before base64 (RFC 7617)', async () => {
  const { fake, captured } = proxyReplying(OK_REPLY);
  const tunnel = await open(fake, {
    proxy: { ...PROXY, username: 'aladdin', password: 'öpen sésame' },
  });
  const auth = latin1(captured.request)
    .split('\r\n')
    .find((l) => l.startsWith('Proxy-Authorization:'));
  assert.equal(auth, `Proxy-Authorization: Basic ${UTF8_CREDS_B64}`);
  await tunnel.close();
});

test('CONNECT: an IPv6 target is bracketed in both the request line and Host', async () => {
  const { fake, captured } = proxyReplying(OK_REPLY);
  const tunnel = await open(fake, { target: { hostname: '2001:db8::1', port: 443 } });
  // Unbracketed, the last colon of the address is indistinguishable from the port separator.
  assert.equal(
    latin1(captured.request),
    'CONNECT [2001:db8::1]:443 HTTP/1.1\r\n' +
      'Host: [2001:db8::1]:443\r\n' +
      'Proxy-Connection: keep-alive\r\n' +
      '\r\n',
  );
  await tunnel.close();
});

test('CONNECT: an https proxy is dialled with secureTransport on, a plain one with starttls', async () => {
  const plain = proxyReplying(OK_REPLY);
  await (await open(plain.fake)).close();
  assert.deepEqual(plain.fake.call.addr, { hostname: 'proxy.example', port: 3128 });
  assert.deepEqual(plain.fake.call.opts, { secureTransport: 'starttls', allowHalfOpen: false });

  const tls = proxyReplying(OK_REPLY);
  const tunnel = await open(tls.fake, {
    proxy: { protocol: 'https', hostname: 'secure-proxy.example', port: 8443 },
  });
  assert.deepEqual(tls.fake.call.addr, { hostname: 'secure-proxy.example', port: 8443 });
  // 'on' means the runtime itself does TLS to the proxy — the one hop where the platform's
  // certificate check verifies the right name.
  assert.deepEqual(tls.fake.call.opts, { secureTransport: 'on', allowHalfOpen: false });
  await tunnel.close();
});

// ---------------------------------------------------------------------------- failures

test('CONNECT: 407 with no credentials -> PROXY_AUTH_REQUIRED, challenge quoted verbatim', async () => {
  const { fake } = proxyReplying(
    'HTTP/1.1 407 Proxy Authentication Required\r\n' +
      'Proxy-Authenticate: Basic realm="corp-egress", charset="UTF-8"\r\n' +
      '\r\n',
  );
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_AUTH_REQUIRED);
  // The challenge is the actionable part: it says whether to configure a password or give up
  // because the proxy wants Digest/NTLM. It must survive into the message verbatim.
  assert.ok(err.message.includes('Basic realm="corp-egress", charset="UTF-8"'), err.message);
  assert.ok(fake.call.closed, 'failed handshake must close the socket');
});

test('CONNECT: 407 with credentials -> PROXY_AUTH_FAILED naming user and challenge', async () => {
  const { fake } = proxyReplying(
    // Header name deliberately upper-cased: field names are case-insensitive on the wire.
    'HTTP/1.1 407 Proxy Authentication Required\r\nPROXY-AUTHENTICATE: Negotiate\r\n\r\n',
  );
  const err = await rejectsWithCode(
    () => open(fake, { proxy: { ...PROXY, username: 'user', password: 'wrong' } }),
    codes.PROXY_AUTH_FAILED,
  );
  assert.match(err.message, /user "user"/);
  assert.match(err.message, /Negotiate/);
  assert.ok(fake.call.closed);
});

test('CONNECT: 403/502/500 -> PROXY_CONNECT_REFUSED with status and reason in the message', async () => {
  for (const [status, reason] of [
    [403, 'Forbidden'],
    [502, 'Bad Gateway'],
    [500, 'Internal Server Error'],
  ]) {
    const { fake } = proxyReplying(`HTTP/1.1 ${status} ${reason}\r\n\r\n`);
    const err = await rejectsWithCode(() => open(fake), codes.PROXY_CONNECT_REFUSED);
    assert.ok(err.message.includes(`${status} ${reason}`), `${status}: ${err.message}`);
    assert.ok(err.message.includes('example.com:443'), 'must name the refused target');
    assert.ok(fake.call.closed, `${status} must close the socket`);
  }
});

test('CONNECT: error reply followed by an HTML body and close fails cleanly, no hang', { timeout: 5000 }, async () => {
  const { fake } = proxyReplying(
    'HTTP/1.1 403 Forbidden\r\n' +
      'Content-Type: text/html\r\n' +
      'Content-Length: 58\r\n' +
      '\r\n' +
      '<html><body><h1>Access denied by corporate policy</h1></body>',
    // Body dribbles in after the header block; a parser that keeps reading "until done" hangs
    // or misparses. The timeout above turns a hang into a failure instead of a stuck run.
    { chunking: [80, 20, 30] },
  );
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_CONNECT_REFUSED);
  assert.match(err.message, /403 Forbidden/);
  assert.ok(fake.call.closed);
});

test('CONNECT: proxy closes mid-header-block -> PROXY_PROTOCOL', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readUntil(CRLFCRLF);
    peer.send('HTTP/1.1 200 Connection established\r\nVia: 1.1 corp');
    peer.end(); // EOF before the terminating blank line
  });
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_PROTOCOL);
  assert.match(err.message, /proxy\.example:3128/);
  assert.ok(fake.call.closed);
});

test('CONNECT: stream error mid-reply -> PROXY_PROTOCOL quoting the cause', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readUntil(CRLFCRLF);
    peer.send('HTTP/1.1 2');
    peer.abort(new Error('connection reset by peer'));
  });
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_PROTOCOL);
  assert.match(err.message, /connection reset by peer/);
  assert.ok(fake.call.closed);
});

test('CONNECT: reply with no CRLFCRLF past maxProxyReplyBytes -> LIMIT_HEADER', { timeout: 5000 }, async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readUntil(CRLFCRLF);
    // No delimiter, and no end(): only the byte limit can stop the read. 100 > 64.
    peer.send('X'.repeat(100));
  });
  const err = await rejectsWithCode(
    () => open(fake, { limits: { maxProxyReplyBytes: 64 } }),
    codes.LIMIT_HEADER,
  );
  assert.match(err.message, /64/);
  assert.ok(fake.call.closed);
});

test('CONNECT: garbage first line -> PROXY_PROTOCOL with the offending line quoted', async () => {
  const cases = [
    ['ICY 200 OK\r\n\r\n', /ICY 200 OK/],       // SHOUTcast: HTTP-shaped but not HTTP
    ['\r\n\r\n', /got ""/],                      // empty status line
    ['\x01\x02\x7fjunk\r\n\r\n', /junk/], // binary noise (bytes below 0x80: latin1 == utf8)
    ['http/1.1 200 ok\r\n\r\n', /http\/1\.1 200 ok/], // HTTP-name is case-sensitive per RFC 9112
  ];
  for (const [reply, quoted] of cases) {
    const { fake } = proxyReplying(reply);
    const err = await rejectsWithCode(() => open(fake), codes.PROXY_PROTOCOL);
    assert.match(err.message, quoted);
    assert.ok(fake.call.closed, `${JSON.stringify(reply)} must close the socket`);
  }
});

test('CONNECT: a rejecting opened surfaces as-is and the socket is still closed', async () => {
  const boom = Object.assign(new Error('TLS to proxy failed: certificate expired'), {
    code: 'FAKE_OPEN_FAILURE',
  });
  const fake = fakeProxy(null, { openError: boom });
  let err;
  try {
    await open(fake);
  } catch (e) {
    err = e;
  }
  // Documented actual contract: unlike openDirect, openHttpConnect rethrows the runtime's own
  // open-failure unwrapped, so the caller sees the runtime's message and code untranslated.
  assert.equal(err, boom, 'the opened rejection must propagate as the same error instance');
  assert.ok(fake.call.closed, 'a socket whose opened rejected must still be closed');
});

test('CONNECT: connect() throwing synchronously -> PROXY_UNREACHABLE naming proxy and cause', async () => {
  const fake = fakeProxy(null, { connectError: new Error('no route to host') });
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_UNREACHABLE);
  assert.match(err.message, /proxy\.example:3128/);
  assert.match(err.message, /no route to host/);
});
