// Transport assembly: URL parsing, tunnel selection, and the capability rule that decides whether
// the platform's own fetch is allowed to serve a request.
//
// That rule is the security-relevant part. Delegating a request that asked for a pinned
// certificate to an implementation using a different trust store would answer a question the
// caller never asked, so the tests below are written as "these configurations must NOT delegate".

import test from 'node:test';
import assert from 'node:assert/strict';
import { nativeFetchCanServe, openConnection, targetFromUrl } from '../src/transport.js';
import { fakeNetwork, readRequestHead, response, sequenceServer } from './_fakenet.js';
import { ByteReader, latin1, utf8 } from '../src/util/bytes.js';
import { rejectsWithCode } from './_harness.js';

// ------------------------------------------------------------------ targetFromUrl

test('targetFromUrl fills in default ports and flags the secure scheme', () => {
  assert.deepEqual(pick(targetFromUrl('http://h.example/p')), {
    hostname: 'h.example',
    port: 80,
    secure: false,
  });
  assert.deepEqual(pick(targetFromUrl('https://h.example/p')), {
    hostname: 'h.example',
    port: 443,
    secure: true,
  });
  assert.equal(targetFromUrl('https://h.example:8443/').port, 8443);
});

const pick = ({ hostname, port, secure }) => ({ hostname, port, secure });

test('an IPv6 host is unbracketed for the socket layer', () => {
  const t = targetFromUrl('https://[2001:db8::1]:8443/x');
  assert.equal(t.hostname, '2001:db8::1', 'the socket API and SOCKS5 both want the bare address');
  assert.equal(t.port, 8443);
});

test('targetFromUrl accepts a URL instance as well as a string', () => {
  assert.equal(targetFromUrl(new URL('http://h.example/')).port, 80);
});

test('a non-http scheme is refused by name', async () => {
  const err = await rejectsWithCode(async () => targetFromUrl('ftp://h.example/'), 'CONFIG_INVALID');
  assert.match(err.message, /ftp:/);
});

// ------------------------------------------------------------------ delegation rule

test('a plain request with default trust may use the platform fetch', () => {
  assert.deepEqual(nativeFetchCanServe({}), { ok: true, reason: null });
  assert.equal(nativeFetchCanServe({ trust: { mode: 'system' } }).ok, true);
});

test('a proxy disqualifies delegation, because fetch has no proxy option', () => {
  const v = nativeFetchCanServe({ proxy: { protocol: 'http', hostname: 'p', port: 8080 } });
  assert.equal(v.ok, false);
  assert.match(v.reason, /proxy/);
});

test('any non-default trust policy disqualifies delegation', () => {
  for (const mode of ['pinned', 'anchors', 'none', 'custom']) {
    const v = nativeFetchCanServe({ trust: { mode } });
    assert.equal(v.ok, false, `trust mode ${mode} must not be delegated`);
    assert.match(v.reason, new RegExp(mode));
    assert.match(v.reason, /certificate hooks/);
  }
});

test('TLS options disqualify delegation', () => {
  assert.equal(nativeFetchCanServe({ tls: { alpn: ['http/1.1'] } }).ok, false);
  assert.equal(nativeFetchCanServe({ tls: {} }).ok, true, 'an empty options object asks for nothing');
});

test('forceTunnel disqualifies delegation even when nothing else does', () => {
  const v = nativeFetchCanServe({ forceTunnel: true });
  assert.equal(v.ok, false);
  assert.match(v.reason, /forceTunnel/);
});

// ------------------------------------------------------------------ openConnection, cleartext

test('openConnection dials the origin directly when no proxy is configured', async () => {
  const server = sequenceServer([response({ body: 'direct' })]);
  const net = fakeNetwork(server.handler);
  const conn = await openConnection({ url: 'http://origin.example/x', connect: net.connect });

  assert.deepEqual(net.calls[0].addr, { hostname: 'origin.example', port: 80 });
  assert.equal(net.calls[0].opts.secureTransport, 'off');
  assert.equal(conn.info.proxied, false);
  assert.equal(conn.info.proxy, null);
  assert.equal(conn.info.tls, null, 'a cleartext connection has no TLS session to report');
  await conn.close();
});

test('openConnection dials the proxy, not the origin, and reports it', async () => {
  const handler = async ({ reader, write }) => {
    const head = await readRequestHead(reader);
    assert.equal(head.method, 'CONNECT');
    assert.equal(head.target, 'origin.example:80');
    await write('HTTP/1.0 200 Connection established\r\n\r\n');
    await write(response({ body: 'through the tunnel' }));
  };
  const net = fakeNetwork(handler);
  const conn = await openConnection({
    url: 'http://origin.example/x',
    connect: net.connect,
    proxy: 'http://p.example:8080',
  });

  assert.deepEqual(net.calls[0].addr, { hostname: 'p.example', port: 8080 });
  assert.equal(conn.info.proxied, true);
  assert.equal(conn.info.proxy, 'http://p.example:8080');
  await conn.close();
});

test('an https proxy is dialled with runtime TLS, which is the one correct use of it', async () => {
  // The identity the platform verifies is the hostname passed to connect(). For this hop that IS
  // the proxy, so the platform's check asks exactly the right question here — and only here.
  const handler = async ({ reader, write }) => {
    await readRequestHead(reader);
    await write('HTTP/1.1 200 OK\r\n\r\n');
  };
  const net = fakeNetwork(handler);
  const conn = await openConnection({
    url: 'http://origin.example/',
    connect: net.connect,
    proxy: 'https://secure-proxy.example:443',
  });
  assert.equal(net.calls[0].opts.secureTransport, 'on');
  await conn.close();
});

test('bytes the proxy sent alongside its reply are not lost', async () => {
  // The reply and the first payload bytes arrive in ONE write. Dropping the tail here would
  // truncate a TLS ClientHello and surface much later as an inexplicable handshake failure.
  const handler = async ({ reader, write }) => {
    await readRequestHead(reader);
    await write(utf8('HTTP/1.0 200 OK\r\n\r\nEARLY-PAYLOAD'));
  };
  const net = fakeNetwork(handler);
  const conn = await openConnection({
    url: 'http://origin.example/',
    connect: net.connect,
    proxy: 'http://p.example:8080',
  });
  const reader = new ByteReader(conn.readable);
  assert.equal(latin1(await reader.readExactly(13)), 'EARLY-PAYLOAD');
  await conn.close();
});

test('a proxy refusing CONNECT surfaces the status and closes the socket', async () => {
  const handler = async ({ reader, write, close }) => {
    await readRequestHead(reader);
    await write('HTTP/1.1 403 Forbidden\r\ncontent-length: 9\r\n\r\nno entry.');
    await close();
  };
  const net = fakeNetwork(handler);
  const err = await rejectsWithCode(
    () =>
      openConnection({
        url: 'http://origin.example/',
        connect: net.connect,
        proxy: 'http://p.example:8080',
      }),
    'PROXY_CONNECT_REFUSED',
  );
  assert.match(err.message, /403/);
  assert.match(err.message, /Forbidden/);
  assert.match(err.message, /origin\.example:80/);
});

test('a SOCKS5 proxy is spoken to in SOCKS5, not HTTP', async () => {
  const handler = async ({ reader, write }) => {
    const greeting = await reader.readExactly(3, 'greeting');
    assert.deepEqual([...greeting], [0x05, 0x01, 0x00], 'no credentials means one method offered');
    await write(new Uint8Array([0x05, 0x00]));

    const head = await reader.readExactly(4, 'request head');
    assert.deepEqual([...head], [0x05, 0x01, 0x00, 0x03], 'domain ATYP so the proxy resolves');
    const len = (await reader.readExactly(1, 'name length'))[0];
    const name = latin1(await reader.readExactly(len, 'name'));
    const port = await reader.readExactly(2, 'port');
    assert.equal(name, 'origin.example');
    assert.equal((port[0] << 8) | port[1], 80);
    await write(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  };
  const net = fakeNetwork(handler);
  const conn = await openConnection({
    url: 'http://origin.example/',
    connect: net.connect,
    proxy: 'socks5://p.example:1080',
  });
  assert.deepEqual(net.calls[0].addr, { hostname: 'p.example', port: 1080 });
  assert.equal(conn.info.proxy, 'socks5://p.example:1080');
  await conn.close();
});

test('socks5h normalises to socks5 in the reported configuration', async () => {
  const handler = async ({ reader, write }) => {
    await reader.readExactly(3, 'greeting');
    await write(new Uint8Array([0x05, 0x00]));
    await reader.readExactly(4, 'head');
    const len = (await reader.readExactly(1, 'len'))[0];
    await reader.readExactly(len + 2, 'rest');
    await write(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  };
  const net = fakeNetwork(handler);
  const conn = await openConnection({
    url: 'http://origin.example/',
    connect: net.connect,
    proxy: 'socks5h://p.example:1080',
  });
  assert.match(conn.info.proxy, /^socks5:\/\//);
  await conn.close();
});

test('a connect deadline aborts rather than hanging', async () => {
  const { DeadlineController } = await import('../src/util/deadline.js');
  // A socket whose `opened` never settles is exactly what a blackholed route looks like.
  const connect = () => ({
    readable: new ReadableStream({ pull() {} }),
    writable: new WritableStream(),
    opened: new Promise(() => {}),
    close: async () => {},
  });
  const deadlines = new DeadlineController({ connectMs: 20 });
  await rejectsWithCode(
    () => openConnection({ url: 'http://origin.example/', connect, deadlines }),
    'TIMEOUT_CONNECT',
  );
  deadlines.dispose();
});

test('a target hostname carrying CRLF is rejected before anything is written', async () => {
  // `URL` already refuses control characters in an authority, so a request URL cannot carry one.
  // The guard that matters is the one inside openTunnel, because that is the layer a caller can
  // reach directly and it is the layer that composes the CONNECT request line.
  const { openTunnel } = await import('../src/proxy/index.js');
  const net = fakeNetwork(async () => {
    throw new Error('the handler must never run for a rejected target');
  });

  for (const hostname of [
    'evil.example\r\nGET /admin HTTP/1.1',
    'evil.example\nX: 1',
    'evil.example\0',
    'evil example',
  ]) {
    await rejectsWithCode(
      () =>
        openTunnel({
          target: { hostname, port: 80 },
          connect: net.connect,
          proxy: 'http://p.example:8080',
        }),
      'CONFIG_INVALID',
    );
  }
  assert.equal(net.calls.length, 0, 'no socket may be opened for a target we refuse to name');
});

test('an out-of-range target port is refused', async () => {
  const { openTunnel } = await import('../src/proxy/index.js');
  const net = fakeNetwork(async () => {});
  for (const port of [0, -1, 65536, 1.5, NaN, undefined]) {
    await rejectsWithCode(
      () => openTunnel({ target: { hostname: 'h.example', port }, connect: net.connect }),
      'CONFIG_INVALID',
    );
  }
  assert.equal(net.calls.length, 0);
});
