// SOCKS5 (RFC 1928 / RFC 1929) against a scripted in-memory proxy.
//
// The two classic implementation bugs this file pins:
//   * the username/password sub-negotiation must carry VER = 0x01, not 0x05 — asserted on the
//     exact wire bytes, because a server-side reject is maddening to diagnose from outside;
//   * the reply's BND.ADDR is variable length, and consuming the wrong number of bytes leaves the
//     tunnel misaligned by a few octets — which fails LATER, as a garbled first TLS record. Every
//     ATYP is therefore tested with payload packed directly against the reply.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openSocks5, encodeAddress, parseIpv6 } from '../../src/proxy/socks5.js';
import { codes } from '../../src/errors.js';
import { concat, latin1, utf8, toHex } from '../../src/util/bytes.js';
import { collect, rejectsWithCode } from '../_harness.js';
import { fakeProxy } from './_fakeproxy.js';

const PROXY = Object.freeze({ protocol: 'socks5', hostname: 'socks.example', port: 1080 });
const AUTH_PROXY = Object.freeze({ ...PROXY, username: 'user', password: 'secret' });
const TARGET = Object.freeze({ hostname: 'example.com', port: 443 });

const bytes = (...a) => Uint8Array.from(a);
// A minimal successful reply: VER REP RSV ATYP=IPv4, BND.ADDR 192.0.2.1, BND.PORT 8080.
const OK_REPLY_V4 = bytes(0x05, 0x00, 0x00, 0x01, 192, 0, 2, 1, 0x1f, 0x90);
// The CONNECT request for example.com:443 — ATYP 0x03 so the PROXY resolves the name.
const EXPECT_REQUEST = concat([
  bytes(0x05, 0x01, 0x00, 0x03, 11),
  utf8('example.com'),
  bytes(0x01, 0xbb),
]);

const open = (fake, { proxy = PROXY, target = TARGET, ...rest } = {}) =>
  openSocks5({ proxy, target, connect: fake.connect, ...rest });

// ---------------------------------------------------------------------------- happy paths

test('SOCKS5 no-auth: greeting, request and reply are byte-exact; tunnel is transparent', async () => {
  let greeting, request;
  const fake = fakeProxy(async (peer) => {
    greeting = await peer.readExactly(3);
    peer.send(bytes(0x05, 0x00));
    request = await peer.readExactly(18);
    peer.send(concat([OK_REPLY_V4, utf8('early')]));
    peer.send(await peer.readExactly(4)); // echo, proving the write side is the raw socket
    peer.end();
  });
  const tunnel = await open(fake);
  assert.equal(toHex(greeting), '050100', 'VER=5, NMETHODS=1, METHODS=[no-auth]');
  assert.equal(toHex(request), toHex(EXPECT_REQUEST));
  assert.deepEqual(fake.call.addr, { hostname: 'socks.example', port: 1080 });
  assert.deepEqual(fake.call.opts, { secureTransport: 'starttls', allowHalfOpen: false });

  const w = tunnel.writable.getWriter();
  await w.write(utf8('ping'));
  w.releaseLock();
  assert.equal(latin1(await collect(tunnel.readable)), 'earlyping');
  await tunnel.close();
  assert.equal(fake.call.closeCalls, 1);
});

test('SOCKS5 username/password: sub-negotiation uses VER 0x01 and exact length prefixes', async () => {
  let greeting, auth;
  const fake = fakeProxy(async (peer) => {
    greeting = await peer.readExactly(4);
    peer.send(bytes(0x05, 0x02)); // server selects username/password
    auth = await peer.readExactly(13); // 1 ver + 1 ulen + 4 user + 1 plen + 6 pass
    peer.send(bytes(0x01, 0x00)); // RFC 1929 success
    await peer.readExactly(18);
    peer.send(OK_REPLY_V4);
    peer.end();
  });
  const tunnel = await open(fake, { proxy: AUTH_PROXY });
  assert.equal(toHex(greeting), '05020002', 'must offer both no-auth and username/password');
  // THE bug this test exists for: the sub-negotiation version is 0x01. Sending 0x05 here fails
  // against every conforming server.
  assert.equal(auth[0], 0x01, 'auth VER must be 0x01, not the SOCKS version 0x05');
  assert.equal(
    toHex(auth),
    '01' + '04' + toHex(utf8('user')) + '06' + toHex(utf8('secret')),
  );
  await tunnel.close();
});

test('SOCKS5: server may select no-auth despite offered credentials; no auth message is sent', async () => {
  let afterGreeting;
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(4);
    peer.send(bytes(0x05, 0x00)); // no-auth, even though 0x02 was offered
    // The very next client bytes must be the CONNECT request. If an auth message were sent
    // anyway, these 18 bytes would start 0x01 and the equality below would fail.
    afterGreeting = await peer.readExactly(18);
    peer.send(OK_REPLY_V4);
    peer.end();
  });
  const tunnel = await open(fake, { proxy: AUTH_PROXY });
  assert.equal(toHex(afterGreeting), toHex(EXPECT_REQUEST));
  await tunnel.close();
});

// Payload packed against the reply, for every BND.ADDR shape and every delivery framing. A
// BND.ADDR length bug does not fail here as a parse error — it surfaces as payload bytes being
// eaten or invented, which is exactly what the deepEqual catches.
const PAYLOAD = bytes(0x16, 0x03, 0x03, 0x00, 0x02, 0xff, 0x00); // TLS-record-shaped, has a NUL
const BND_REPLIES = {
  ipv4: bytes(0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x50),
  ipv6: bytes(0x05, 0x00, 0x00, 0x04, ...Array.from({ length: 16 }, (_, i) => i + 1), 0x01, 0xbb),
  domain: concat([bytes(0x05, 0x00, 0x00, 0x03, 9), utf8('localhost'), bytes(0x1f, 0x90)]),
};

for (const [atyp, reply] of Object.entries(BND_REPLIES)) {
  test(`SOCKS5 reply ATYP ${atyp}: trailing payload is delivered intact, in order`, async () => {
    for (const mode of ['same-chunk', 'split', 'byte-by-byte']) {
      const fake = fakeProxy(async (peer) => {
        await peer.readExactly(3);
        peer.send(bytes(0x05, 0x00), mode === 'byte-by-byte' ? 'bytes' : 'whole');
        await peer.readExactly(18);
        if (mode === 'same-chunk') {
          peer.send(concat([reply, PAYLOAD]));
        } else if (mode === 'split') {
          peer.send(reply);
          peer.send(PAYLOAD);
        } else {
          peer.send(concat([reply, PAYLOAD]), 'bytes');
        }
        peer.send(utf8('tail'));
        peer.end();
      });
      const tunnel = await open(fake);
      assert.deepEqual(
        await collect(tunnel.readable),
        concat([PAYLOAD, utf8('tail')]),
        `${atyp} / ${mode}: BND.ADDR misframing ate or invented payload bytes`,
      );
      await tunnel.close();
    }
  });
}

test('SOCKS5 target forms: IPv4 literal -> ATYP 0x01, IPv6 literal -> 0x04, name -> 0x03', async () => {
  const cases = [
    // [target, expected request hex]
    [{ hostname: '192.0.2.7', port: 80 }, '05010001' + 'c0000207' + '0050'],
    [
      { hostname: '2001:db8::1', port: 443 },
      '05010004' + '20010db8' + '00000000' + '00000000' + '00000001' + '01bb',
    ],
    // Not an IP literal, so the name goes to the proxy for remote resolution — the only mode
    // that works on a runtime with no resolver, and the one that keeps names off local DNS.
    [{ hostname: 'intranet.corp', port: 8443 }, '05010003' + '0d' + toHex(utf8('intranet.corp')) + '20fb'],
  ];
  for (const [target, expected] of cases) {
    let request;
    const fake = fakeProxy(async (peer) => {
      await peer.readExactly(3);
      peer.send(bytes(0x05, 0x00));
      request = await peer.readExactly(expected.length / 2);
      peer.send(OK_REPLY_V4);
      peer.end();
    });
    const tunnel = await open(fake, { target });
    assert.equal(toHex(request), expected, target.hostname);
    await tunnel.close();
  }
});

// ---------------------------------------------------------------------------- failures

test('SOCKS5: greeting answered 05 FF -> SOCKS5_NO_ACCEPTABLE_AUTH listing what was offered', async () => {
  const noCreds = fakeProxy(async (peer) => {
    await peer.readExactly(3);
    peer.send(bytes(0x05, 0xff));
    peer.end();
  });
  const err1 = await rejectsWithCode(() => open(noCreds), codes.SOCKS5_NO_ACCEPTABLE_AUTH);
  assert.match(err1.message, /0x00/, 'must list the offered methods');
  assert.match(err1.message, /no credentials were configured/);
  assert.ok(noCreds.call.closed);

  const withCreds = fakeProxy(async (peer) => {
    await peer.readExactly(4);
    peer.send(bytes(0x05, 0xff));
    peer.end();
  });
  const err2 = await rejectsWithCode(
    () => open(withCreds, { proxy: AUTH_PROXY }),
    codes.SOCKS5_NO_ACCEPTABLE_AUTH,
  );
  assert.match(err2.message, /0x00, 0x02/, 'must list both offered methods');
  assert.match(err2.message, /does not implement/);
  assert.ok(withCreds.call.closed);
});

test('SOCKS5: greeting answered with version != 5 -> PROXY_PROTOCOL', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(3);
    peer.send(bytes(0x04, 0x00)); // a SOCKS4 server, the realistic misconfiguration
    peer.end();
  });
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_PROTOCOL);
  assert.match(err.message, /0x04/);
  assert.ok(fake.call.closed);
});

test('SOCKS5: server selecting unoffered GSSAPI (05 01) -> SOCKS5_NO_ACCEPTABLE_AUTH', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(4);
    peer.send(bytes(0x05, 0x01)); // GSSAPI was never in our METHODS
    peer.end();
  });
  const err = await rejectsWithCode(
    () => open(fake, { proxy: AUTH_PROXY }),
    codes.SOCKS5_NO_ACCEPTABLE_AUTH,
  );
  assert.match(err.message, /0x01/);
  assert.match(err.message, /not offered/);
  assert.ok(fake.call.closed);
});

test('BUG: server selecting userpass when only no-auth was offered must be rejected', async () => {
  // RFC 1928: the server "selects from one of the methods given in METHODS". With no credentials
  // configured we offer only 0x00, so a server answering 0x02 violated the protocol and there is
  // nothing valid to send — proceeding means emitting an empty-credential RFC 1929 message.
  // Pinned as SOCKS5_NO_ACCEPTABLE_AUTH: greet() checks the method against the implementable
  // set, not the offered set, so today this leaks into authenticate() with no username.
  let afterSelect = null;
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(3); // greeting offered [0x00] only
    peer.send(bytes(0x05, 0x02));
    afterSelect = await peer.read(); // null if the client (correctly) hangs up instead
    peer.end();
  });
  const err = await rejectsWithCode(() => open(fake), codes.SOCKS5_NO_ACCEPTABLE_AUTH);
  assert.match(err.message, /not offered/);
  assert.ok(fake.call.closed);
  assert.equal(afterSelect, null, 'no auth message may be sent for an unoffered method');
});

test('SOCKS5: auth reply status != 0 -> PROXY_AUTH_FAILED naming the username', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(4);
    peer.send(bytes(0x05, 0x02));
    await peer.readExactly(13);
    peer.send(bytes(0x01, 0x5f)); // any non-zero status is failure
    peer.end();
  });
  const err = await rejectsWithCode(() => open(fake, { proxy: AUTH_PROXY }), codes.PROXY_AUTH_FAILED);
  assert.match(err.message, /user "user"/);
  assert.match(err.message, /0x5f/);
  assert.ok(fake.call.closed);
});

test('SOCKS5: auth reply with version != 1 -> PROXY_PROTOCOL', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(4);
    peer.send(bytes(0x05, 0x02));
    await peer.readExactly(13);
    peer.send(bytes(0x05, 0x00)); // server wrongly echoes the SOCKS version in the auth reply
    peer.end();
  });
  const err = await rejectsWithCode(() => open(fake, { proxy: AUTH_PROXY }), codes.PROXY_PROTOCOL);
  assert.match(err.message, /0x05/);
  assert.match(err.message, /expected 0x01/);
  assert.ok(fake.call.closed);
});

test('SOCKS5: every REP code 0x01..0x08 -> SOCKS5_REPLY with its own phrase; 0x09 unassigned', async () => {
  // Phrases transcribed from RFC 1928 s6 independently of the implementation's table.
  const expected = {
    0x01: /general SOCKS server failure/,
    0x02: /connection not allowed by ruleset/,
    0x03: /network unreachable/,
    0x04: /host unreachable/,
    0x05: /connection refused/,
    0x06: /TTL expired/,
    0x07: /command not supported/,
    0x08: /address type not supported/,
    0x09: /unassigned reply code/,
  };
  const seen = new Set();
  for (const [rep, phrase] of Object.entries(expected).map(([k, v]) => [Number(k), v])) {
    const fake = fakeProxy(async (peer) => {
      await peer.readExactly(3);
      peer.send(bytes(0x05, 0x00));
      await peer.readExactly(18);
      // Full reply including BND.ADDR/PORT: the client must drain it even on failure.
      peer.send(bytes(0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0));
      peer.end();
    });
    const err = await rejectsWithCode(() => open(fake), codes.SOCKS5_REPLY);
    assert.match(err.message, phrase, `REP ${rep}`);
    assert.match(err.message, new RegExp(`0x0${rep.toString(16)}`), 'must name the wire value');
    assert.match(err.message, /example\.com:443/, 'must name the refused target');
    assert.ok(fake.call.closed, `REP ${rep} must close the socket`);
    // Distinct phrases: an operator reading one log line must be able to tell them apart.
    const m = err.message.match(/refused CONNECT to [^:]+:\d+: (.+) \(0x/);
    assert.ok(m, err.message);
    assert.ok(!seen.has(m[1]), `phrase "${m[1]}" reused across REP codes`);
    seen.add(m[1]);
  }
});

test('SOCKS5: reply with unknown ATYP -> SOCKS5_ADDR_TYPE (stream position unknowable)', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(3);
    peer.send(bytes(0x05, 0x00));
    await peer.readExactly(18);
    peer.send(bytes(0x05, 0x00, 0x00, 0x02, 0xde, 0xad)); // ATYP 0x02 is unassigned
    peer.end();
  });
  const err = await rejectsWithCode(() => open(fake), codes.SOCKS5_ADDR_TYPE);
  assert.match(err.message, /0x02/);
  assert.ok(fake.call.closed);
});

test('SOCKS5: connection closed mid-reply -> PROXY_PROTOCOL', async () => {
  const head = fakeProxy(async (peer) => {
    await peer.readExactly(3);
    peer.send(bytes(0x05, 0x00));
    await peer.readExactly(18);
    peer.send(bytes(0x05, 0x00, 0x00)); // dies one byte short of the fixed head
    peer.end();
  });
  const err1 = await rejectsWithCode(() => open(head), codes.PROXY_PROTOCOL);
  assert.match(err1.message, /SOCKS5 reply/);
  assert.ok(head.call.closed);

  const bnd = fakeProxy(async (peer) => {
    await peer.readExactly(3);
    peer.send(bytes(0x05, 0x00));
    await peer.readExactly(18);
    peer.send(bytes(0x05, 0x00, 0x00, 0x01, 10, 0)); // dies inside BND.ADDR
    peer.end();
  });
  const err2 = await rejectsWithCode(() => open(bnd), codes.PROXY_PROTOCOL);
  assert.match(err2.message, /BND\.ADDR/);
  assert.ok(bnd.call.closed);
});

test('SOCKS5: username or password over 255 bytes -> CONFIG_INVALID before any auth bytes', async () => {
  for (const creds of [
    { username: 'u'.repeat(256), password: 'p' },
    { username: 'u', password: 'p'.repeat(256) },
  ]) {
    let afterSelect = null;
    const fake = fakeProxy(async (peer) => {
      await peer.readExactly(4);
      peer.send(bytes(0x05, 0x02)); // force the userpass path, where the length field lives
      afterSelect = await peer.read();
      peer.end();
    });
    const err = await rejectsWithCode(
      () => open(fake, { proxy: { ...PROXY, ...creds } }),
      codes.CONFIG_INVALID,
    );
    assert.match(err.message, /255/);
    assert.ok(fake.call.closed);
    // The length field is one byte; an overlong value must never be truncated onto the wire.
    assert.equal(afterSelect, null, 'no auth bytes may be written for oversized credentials');
  }
});

test('SOCKS5: domain target over 255 bytes -> CONFIG_INVALID (length field is one byte)', async () => {
  const fake = fakeProxy(async (peer) => {
    await peer.readExactly(3);
    peer.send(bytes(0x05, 0x00));
    await peer.read(); // null once the client hangs up without sending a request
    peer.end();
  });
  const err = await rejectsWithCode(
    () => open(fake, { target: { hostname: 'a'.repeat(256), port: 443 } }),
    codes.CONFIG_INVALID,
  );
  assert.match(err.message, /255/);
  assert.ok(fake.call.closed);
});

test('SOCKS5: a rejecting opened surfaces as-is and the socket is still closed', async () => {
  // Same documented contract as openHttpConnect: the runtime's own dial failure is not wrapped.
  const boom = new Error('connection timed out');
  const fake = fakeProxy(null, { openError: boom });
  let err;
  try {
    await open(fake);
  } catch (e) {
    err = e;
  }
  assert.equal(err, boom);
  assert.ok(fake.call.closed);
});

test('SOCKS5: connect() throwing synchronously -> PROXY_UNREACHABLE', async () => {
  const fake = fakeProxy(null, { connectError: new Error('no route to host') });
  const err = await rejectsWithCode(() => open(fake), codes.PROXY_UNREACHABLE);
  assert.match(err.message, /socks\.example:1080/);
  assert.match(err.message, /no route to host/);
});

// ---------------------------------------------------------------------------- exported helpers

test('encodeAddress: domain, IPv4 and IPv6 targets, byte for byte', () => {
  assert.equal(
    toHex(encodeAddress({ hostname: 'example.com', port: 443 })),
    '03' + '0b' + toHex(utf8('example.com')) + '01bb',
  );
  assert.equal(toHex(encodeAddress({ hostname: '192.0.2.7', port: 80 })), '01c00002070050');
  assert.equal(
    toHex(encodeAddress({ hostname: '::1', port: 8443 })),
    '04' + '0'.repeat(31) + '1' + '20fb',
  );
  // Port is big-endian; a swapped port connects somewhere real and wrong, not nowhere.
  assert.equal(toHex(encodeAddress({ hostname: 'x', port: 0x1234 }).slice(-2)), '1234');
});

test('encodeAddress: rejects empty and over-255-byte domain names', async () => {
  await rejectsWithCode(
    () => encodeAddress({ hostname: 'a'.repeat(256), port: 443 }),
    codes.CONFIG_INVALID,
  );
  await rejectsWithCode(() => encodeAddress({ hostname: '', port: 443 }), codes.CONFIG_INVALID);
});

test('parseIpv6: accepts the real-world spellings', () => {
  const cases = [
    ['::1', '00000000000000000000000000000001'],
    ['2001:db8::1', '20010db8000000000000000000000001'],
    // Full 8-group form with distinct groups, so a transposition cannot cancel out.
    ['0102:0304:0506:0708:090a:0b0c:0d0e:0f10', '0102030405060708090a0b0c0d0e0f10'],
    ['::ffff:192.0.2.1', '00000000000000000000ffffc0000201'], // embedded IPv4 tail
    ['fe80::1%eth0', 'fe800000000000000000000000000001'], // zone id stripped, not sent
    ['[2001:db8::2]', '20010db8000000000000000000000002'], // URL-style brackets tolerated
    ['1:2:3:4:5:6:1.2.3.4', '00010002000300040005000601020304'], // v4 tail without ::
  ];
  for (const [text, hex] of cases) {
    assert.equal(toHex(parseIpv6(text)), hex, text);
  }
});

test('parseIpv6: rejects malformed addresses with CONFIG_INVALID', async () => {
  const cases = [
    ['1::2::3', /more than one "::"/],
    ['1:2:3:4:5:6:7:8:9', /9 groups/], // uncompressed, one group too many
    ['1:2:3:4:5::6:7:8:9', /too many groups/], // compressed but already over 8
    ['2001:xyz::1', /invalid group "xyz"/],
    ['12345::1', /invalid group/], // a group is at most 4 hex digits
    ['::ffff:1.2.3.999', /not a valid IPv6 address/], // embedded IPv4 octet out of range
  ];
  for (const [text, match] of cases) {
    const err = await rejectsWithCode(() => parseIpv6(text), codes.CONFIG_INVALID, match);
    assert.ok(err.message.includes(text), `message must quote the rejected input: ${err.message}`);
  }
});
