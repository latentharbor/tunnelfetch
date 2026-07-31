// The proxy layer's front door: parseProxy normalisation, openTunnel dispatch and target
// validation, and the direct (no-proxy) path.
//
// Target validation is tested with a real CRLF payload because it is a request-injection guard:
// a hostname like 'evil\r\nGET /' would otherwise be spliced verbatim into the CONNECT request
// line, letting a caller-controlled string smuggle a second request to the proxy.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as proxyIndex from '../../src/proxy/index.js';
import { parseProxy, openTunnel, closeQuietly } from '../../src/proxy/index.js';
import { openDirect } from '../../src/proxy/direct.js';
import { codes } from '../../src/errors.js';
import { latin1, utf8 } from '../../src/util/bytes.js';
import { collect, rejectsWithCode } from '../_harness.js';
import { fakeProxy } from './_fakeproxy.js';

const TARGET = Object.freeze({ hostname: 'example.com', port: 443 });

/** Fake proxies speaking just enough of each protocol for dispatch tests. */
const connectScript = async (peer, record) => {
  record.request = await peer.readUntil('\r\n\r\n');
  peer.send('HTTP/1.1 200 Connection established\r\n\r\n');
  peer.end();
};
const socksScript = async (peer, record) => {
  record.greeting = await peer.read();
  peer.send(Uint8Array.from([0x05, 0x00]));
  await peer.read();
  peer.send(Uint8Array.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  peer.end();
};
const echoScript = async (peer) => {
  peer.send(await peer.readExactly(4));
  peer.end();
};

// ---------------------------------------------------------------------------- parseProxy

test('parseProxy: URL strings with default ports 8080/443/1080/1080', () => {
  assert.deepEqual(parseProxy('http://proxy.example'), {
    protocol: 'http',
    hostname: 'proxy.example',
    port: 8080,
    username: undefined,
    password: undefined,
  });
  assert.equal(parseProxy('https://proxy.example').port, 443);
  assert.equal(parseProxy('socks5://proxy.example').port, 1080);
  assert.equal(parseProxy('socks5h://proxy.example').port, 1080);
  // Explicit ports win over defaults.
  assert.equal(parseProxy('http://proxy.example:3128').port, 3128);
  assert.equal(parseProxy('socks5://proxy.example:9050').port, 9050);
});

test('parseProxy: socks5h is an alias of socks5 (remote resolution is the only mode)', () => {
  assert.equal(parseProxy('socks5h://proxy.example:1080').protocol, 'socks5');
  assert.equal(parseProxy({ protocol: 'socks5h', hostname: 'h' }).protocol, 'socks5');
});

test('BUG: parseProxy must honour an explicit :80 on an http proxy URL', () => {
  // WHATWG URL elides a port equal to the scheme default, so url.port is '' for http://h:80 and
  // the code substitutes ITS default of 8080. A user pointing at a proxy on port 80 — a common
  // place for corporate proxies to listen — silently gets dialled on 8080 instead. The https
  // variant only escapes this because 443 happens to coincide with the scheme default.
  assert.equal(parseProxy('http://proxy.example:80').port, 80);
});

test('parseProxy: percent-encoded credentials with @ and : round-trip', () => {
  const cfg = parseProxy('http://al%40dd%3Ain:p%40ss%3Aword@proxy.example:3128');
  // If these came through still encoded, Basic auth would send the wrong password and the
  // failure would look like a proxy-side credential problem.
  assert.equal(cfg.username, 'al@dd:in');
  assert.equal(cfg.password, 'p@ss:word');
});

test('BUG: parseProxy must reject a malformed percent-escape as CONFIG_INVALID', async () => {
  // The URL parser accepts a lone % in userinfo, then decodeURIComponent throws a bare URIError.
  // Every other invalid spec is a ConfigError with CONFIG_INVALID; a caller filtering on the
  // documented code would let this one crash through untyped.
  await rejectsWithCode(() => parseProxy('socks5://user:p%zz@proxy.example'), codes.CONFIG_INVALID);
});

test('parseProxy: object form is normalised, defaulted and frozen', () => {
  const cfg = parseProxy({ protocol: 'SOCKS5:', hostname: 'h' }); // case and colon tolerated
  assert.deepEqual(cfg, {
    protocol: 'socks5',
    hostname: 'h',
    port: 1080,
    username: undefined,
    password: undefined,
  });
  // Frozen matters beyond hygiene: openTunnel uses Object.isFrozen to tell an already-parsed
  // config from a raw caller object that still needs validation.
  assert.ok(Object.isFrozen(cfg));
  // An empty password is treated as absent, not as a zero-byte secret.
  assert.equal(parseProxy({ protocol: 'http', hostname: 'h', username: 'u', password: '' }).password, undefined);
});

test('parseProxy: null, undefined and empty string mean "no proxy"', () => {
  assert.equal(parseProxy(null), null);
  assert.equal(parseProxy(undefined), null);
  assert.equal(parseProxy(''), null);
});

test('parseProxy: an IPv6 proxy host loses its brackets', () => {
  const cfg = parseProxy('http://[::1]:3128');
  // connect() takes a bare hostname; leaving the brackets on would dial a name that does not
  // resolve anywhere.
  assert.equal(cfg.hostname, '::1');
  assert.equal(cfg.port, 3128);
});

test('parseProxy: invalid specs -> CONFIG_INVALID', async () => {
  const cases = [
    ['not a url at all', /is not a URL/],
    ['ftp://proxy.example', /not supported/],
    // Parses as a URL with scheme "proxy.example:" — a classic paste of host:port without scheme.
    ['proxy.example:8080', /not supported/],
    ['http://:pw@proxy.example', /password given without a username/],
  ];
  for (const [spec, match] of cases) {
    await rejectsWithCode(() => parseProxy(spec), codes.CONFIG_INVALID, match);
  }
  const objects = [
    [{ protocol: 'http' }, /no hostname/],
    [{ protocol: 'wss', hostname: 'h' }, /not supported/],
    [{ protocol: 'http', hostname: 'h', port: 0 }, /out of range/],
    [{ protocol: 'http', hostname: 'h', port: 65536 }, /out of range/],
    [{ protocol: 'http', hostname: 'h', port: 443.5 }, /out of range/],
    [{ protocol: 'http', hostname: 'h', port: '8080' }, /out of range/], // strings are not ports
    [{ protocol: 'http', hostname: 'h', password: 'pw' }, /without a username/],
    [{}, /not supported/],
  ];
  for (const [spec, match] of objects) {
    await rejectsWithCode(() => parseProxy(spec), codes.CONFIG_INVALID, match);
  }
});

// ---------------------------------------------------------------------------- openTunnel dispatch

test('openTunnel: null proxy goes direct — secureTransport off, dialled at the target', async () => {
  const fake = fakeProxy(echoScript);
  const tunnel = await openTunnel({ proxy: null, target: TARGET, connect: fake.connect });
  assert.equal(tunnel.proxied, false);
  assert.deepEqual(fake.call.addr, { hostname: 'example.com', port: 443 });
  assert.deepEqual(fake.call.opts, { secureTransport: 'off', allowHalfOpen: false });

  const w = tunnel.writable.getWriter();
  await w.write(utf8('ping'));
  w.releaseLock();
  assert.equal(latin1(await collect(tunnel.readable)), 'ping');
  await tunnel.close();
  assert.ok(fake.call.closed, 'close must reach the underlying socket through the spread');
});

test('openTunnel: http and https configs dispatch to CONNECT', async () => {
  for (const proxy of [
    { protocol: 'http', hostname: 'proxy.example', port: 3128 },
    'https://proxy.example:8443', // string form must be parsed, not treated as an object
  ]) {
    const fake = fakeProxy(connectScript);
    const tunnel = await openTunnel({ proxy, target: TARGET, connect: fake.connect });
    assert.equal(tunnel.proxied, true);
    assert.match(latin1(fake.call.request), /^CONNECT example\.com:443 HTTP\/1\.1\r\n/);
    assert.equal(
      fake.call.opts.secureTransport,
      typeof proxy === 'string' ? 'on' : 'starttls',
      'https proxy must be dialled over TLS, plain http must not',
    );
    await tunnel.close();
  }
});

test('openTunnel: socks5 and socks5h dispatch to SOCKS5', async () => {
  for (const proxy of ['socks5://socks.example', 'socks5h://socks.example:9050']) {
    const fake = fakeProxy(socksScript);
    const tunnel = await openTunnel({ proxy, target: TARGET, connect: fake.connect });
    assert.equal(tunnel.proxied, true);
    assert.deepEqual([...fake.call.greeting], [0x05, 0x01, 0x00], proxy);
    assert.equal(fake.call.addr.port, proxy.includes('9050') ? 9050 : 1080);
    await tunnel.close();
  }
});

test('openTunnel: an unfrozen proxy object is validated and defaulted like a fresh spec', async () => {
  const fake = fakeProxy(connectScript);
  const tunnel = await openTunnel({
    proxy: { protocol: 'http', hostname: 'proxy.example' }, // no port: must gain 8080
    target: TARGET,
    connect: fake.connect,
  });
  assert.equal(fake.call.addr.port, 8080);
  await tunnel.close();
  // And an unfrozen INVALID object must be rejected, not passed through unchecked.
  await rejectsWithCode(
    () => openTunnel({ proxy: { protocol: 'gopher', hostname: 'h' }, target: TARGET, connect: fake.connect }),
    codes.CONFIG_INVALID,
  );
});

test('openTunnel: missing connect function -> CONFIG_INVALID', async () => {
  await rejectsWithCode(() => openTunnel({ proxy: null, target: TARGET }), codes.CONFIG_INVALID);
  await rejectsWithCode(
    () => openTunnel({ proxy: null, target: TARGET, connect: 'not a function' }),
    codes.CONFIG_INVALID,
  );
});

// ---------------------------------------------------------------------------- target validation

test('openTunnel: hostname with CRLF/NUL/whitespace -> CONFIG_INVALID and no socket opened', async () => {
  const hostnames = [
    'evil\r\nGET / HTTP/1.1', // the actual injection: a second request line inside CONNECT
    'evil\rx',
    'evil\nx',
    'evil' + String.fromCharCode(0) + 'x',
    'two words',
    'tab\there',
  ];
  for (const hostname of hostnames) {
    const fake = fakeProxy(connectScript);
    await rejectsWithCode(
      () =>
        openTunnel({
          proxy: { protocol: 'http', hostname: 'proxy.example', port: 3128 },
          target: { hostname, port: 443 },
          connect: fake.connect,
        }),
      codes.CONFIG_INVALID,
      /whitespace or a control character/,
    );
    // The guard must fire BEFORE any bytes exist to inject into: no dial may have happened.
    assert.equal(fake.calls.length, 0, JSON.stringify(hostname));
  }
});

test('openTunnel: missing or out-of-range target port -> CONFIG_INVALID and no socket', async () => {
  const cases = [
    { hostname: 'example.com', port: 0 },
    { hostname: 'example.com', port: -1 },
    { hostname: 'example.com', port: 65536 },
    { hostname: 'example.com', port: 443.5 },
    { hostname: 'example.com', port: '443' },
    { hostname: 'example.com' },
    { hostname: '', port: 443 },
    null,
  ];
  for (const target of cases) {
    const fake = fakeProxy(connectScript);
    await rejectsWithCode(
      () => openTunnel({ proxy: null, target, connect: fake.connect }),
      codes.CONFIG_INVALID,
    );
    assert.equal(fake.calls.length, 0, JSON.stringify(target));
  }
});

// ---------------------------------------------------------------------------- abort and failures

test('openTunnel: an already-aborted signal rejects before any socket is opened', async () => {
  for (const proxy of [null, 'http://proxy.example:3128', 'socks5://socks.example']) {
    const fake = fakeProxy(connectScript);
    const ac = new AbortController();
    ac.abort();
    await assert.rejects(
      () => openTunnel({ proxy, target: TARGET, connect: fake.connect, signal: ac.signal }),
      { name: 'AbortError' },
    );
    assert.equal(fake.calls.length, 0, `proxy=${proxy}: aborted call must not dial`);
  }
  // A custom abort reason must surface as itself, not be replaced by a generic AbortError.
  const fake = fakeProxy(connectScript);
  const ac = new AbortController();
  ac.abort(new Error('operator cancelled'));
  await assert.rejects(
    () => openTunnel({ proxy: null, target: TARGET, connect: fake.connect, signal: ac.signal }),
    { message: 'operator cancelled' },
  );
  assert.equal(fake.calls.length, 0);
});

test('direct: connect() throwing -> PROXY_UNREACHABLE naming target and cause', async () => {
  const fake = fakeProxy(null, { connectError: new Error('network is unreachable') });
  const err = await rejectsWithCode(
    () => openDirect({ target: TARGET, connect: fake.connect }),
    codes.PROXY_UNREACHABLE,
  );
  assert.match(err.message, /example\.com:443/);
  assert.match(err.message, /network is unreachable/);
});

test('direct: a rejecting opened -> PROXY_UNREACHABLE quoting the runtime message', async () => {
  const fake = fakeProxy(null, { openError: new Error('connection refused by platform') });
  const err = await rejectsWithCode(
    () => openTunnel({ proxy: null, target: TARGET, connect: fake.connect }),
    codes.PROXY_UNREACHABLE,
  );
  // The runtime's refusal text is the best diagnostic the caller will ever get; it must survive.
  assert.match(err.message, /connection refused by platform/);
  assert.match(err.message, /example\.com:443/);
});

test('BUG: direct must close the socket when opened rejects', async () => {
  // Both proxied paths close the socket on every handshake failure; the direct path does not
  // close after a failed opened. On the target runtime a connect() that returned a socket object
  // holds a resource until close() — leaking one per failed dial is a real Worker resource bug.
  const fake = fakeProxy(null, { openError: new Error('timed out') });
  await assert.rejects(() => openTunnel({ proxy: null, target: TARGET, connect: fake.connect }));
  assert.ok(fake.call.closed, 'failed direct dial must close() the socket it was handed');
});

// ---------------------------------------------------------------------------- small surface

test('closeQuietly: tolerates absent duplex, absent close, and a throwing close', async () => {
  await closeQuietly(undefined);
  await closeQuietly(null);
  await closeQuietly({});
  await closeQuietly({ close: () => Promise.reject(new Error('already gone')) });
  await closeQuietly({
    close() {
      throw new Error('sync throw');
    },
  });
  // Reaching here IS the assertion: none of the above may throw.
  assert.ok(true);
});

test('proxy index exports exactly the documented surface', () => {
  assert.deepEqual(Object.keys(proxyIndex).sort(), [
    'closeQuietly',
    'openDirect',
    'openHttpConnect',
    'openSocks5',
    'openTunnel',
    'parseProxy',
  ]);
});
