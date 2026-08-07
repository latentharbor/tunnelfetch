// SOCKS5 (RFC 1928) with username/password authentication (RFC 1929).
//
// Two things here are classic implementation bugs, and both are guarded deliberately:
//
//   * The username/password sub-negotiation carries VER = 0x01, not 0x05. Reusing 0x05 produces a
//     handshake that fails against every conforming server and is maddening to diagnose.
//   * The reply's BND.ADDR is variable length. Consuming the wrong number of bytes leaves the
//     stream misaligned by a few octets, which does not fail here — it fails later, as a garbled
//     first TLS record. The length is therefore derived from ATYP and an unknown ATYP is fatal.
//
// Addresses are sent as ATYP=0x03 (domain name) whenever the target is not already an IP literal,
// so the proxy resolves. That is not a preference: this runtime exposes no resolver, and remote
// resolution also keeps the target name off the local DNS path.

import { ProxyError, ConfigError, codes, hex8 } from '../errors.js';
import { ByteReader, ByteWriter, concat, utf8 } from '../util/bytes.js';
import { tunnelReadable } from './tunnel.js';

const VERSION = 0x05;
const AUTH_VERSION = 0x01;
const METHOD_NONE = 0x00;
const METHOD_USERPASS = 0x02;
const METHOD_UNACCEPTABLE = 0xff;
const CMD_CONNECT = 0x01;

const ATYP = { ipv4: 0x01, domain: 0x03, ipv6: 0x04 };

const REPLY = {
  0x00: 'succeeded',
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported',
};

const isIpv4 = (h) => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(h) &&
  h.split('.').every((o) => Number(o) <= 255);

/**
 * @typedef {object} Socks5Options
 * @property {import('./index.js').ProxyConfig} proxy credentials trigger RFC 1929 user/pass auth
 * @property {{ hostname: string, port: number }} target
 * @property {import('./index.js').ConnectFn} connect injected socket factory
 * @property {AbortSignal} [signal]
 */

/**
 * Establish a SOCKS5 tunnel. Resolves with the tunnel duplex; every refusal (no acceptable
 * auth method, rejected credentials, non-zero reply code, unframeable reply) throws a
 * ProxyError naming the exact wire value the proxy sent.
 *
 * @param {Socks5Options} args
 * @returns {Promise<import('./http-connect.js').ProxyTunnel>}
 */
export async function openSocks5({ proxy, target, connect, signal }) {
  signal?.throwIfAborted?.();
  const where = `${proxy.hostname}:${proxy.port}`;

  let socket;
  try {
    socket = connect({ hostname: proxy.hostname, port: proxy.port }, {
      secureTransport: 'starttls',
      allowHalfOpen: false,
    });
  } catch (cause) {
    throw new ProxyError(
      codes.PROXY_UNREACHABLE,
      `could not open a socket to SOCKS5 proxy ${where}: ${cause?.message ?? cause}`,
      { proxy: where },
    );
  }

  let reader;
  let writer;
  try {
    if (socket.opened) await socket.opened;
    reader = new ByteReader(socket.readable);
    writer = new ByteWriter(socket.writable);

    const method = await greet(reader, writer, proxy, where);
    if (method === METHOD_USERPASS) await authenticate(reader, writer, proxy, where);

    await request(reader, writer, target, where);
    writer.releaseLock();
    return tunnelFrom(socket, reader);
  } catch (err) {
    try {
      writer?.releaseLock();
      await reader?.cancel(err);
      await socket.close?.();
    } catch {
      /* socket already unusable */
    }
    throw err;
  }
}

async function greet(reader, writer, proxy, where) {
  const methods = proxy.username ? [METHOD_NONE, METHOD_USERPASS] : [METHOD_NONE];
  await writer.write(Uint8Array.from([VERSION, methods.length, ...methods]));

  const reply = await readExactly(reader, 2, 'SOCKS5 method selection', where);
  if (reply[0] !== VERSION) {
    throw new ProxyError(
      codes.PROXY_PROTOCOL,
      `SOCKS5 proxy ${where} answered the greeting with version ${hex8(reply[0])}, expected 0x05`,
      { proxy: where, version: reply[0] },
    );
  }
  const method = reply[1];
  if (method === METHOD_UNACCEPTABLE) {
    throw new ProxyError(
      codes.SOCKS5_NO_ACCEPTABLE_AUTH,
      `SOCKS5 proxy ${where} accepted none of the methods offered ` +
        `(${methods.map(hex8).join(', ')}); ` +
        (proxy.username
          ? 'it wants an authentication method this package does not implement (only ' +
            'username/password, RFC 1929, is supported)'
          : 'it requires authentication but no credentials were configured'),
      { proxy: where, offered: methods },
    );
  }
  // Checked against what we actually OFFERED, not against what we could in principle implement.
  // Testing the wider set let a server that answered 0x02 to a no-credentials greeting fall into
  // the authentication step, where the client would put an empty-credential RFC 1929 message on
  // the wire before failing — bytes that should never have been sent.
  if (!methods.includes(method)) {
    throw new ProxyError(
      codes.SOCKS5_NO_ACCEPTABLE_AUTH,
      `SOCKS5 proxy ${where} selected authentication method ${hex8(method)}, which was not ` +
        `offered (offered: ${methods.map(hex8).join(', ')})`,
      { proxy: where, method, offered: methods },
    );
  }
  // A server may legitimately select no-auth even when we offered credentials; that is not an
  // error, it simply means the credentials go unused.
  return method;
}

async function authenticate(reader, writer, proxy, where) {
  const user = utf8(proxy.username);
  const pass = utf8(proxy.password ?? '');
  if (user.byteLength > 255 || pass.byteLength > 255) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `SOCKS5 username (${user.byteLength} bytes) and password (${pass.byteLength} bytes) ` +
        'must each be at most 255 bytes',
    );
  }
  await writer.write(
    concat([
      Uint8Array.from([AUTH_VERSION, user.byteLength]),
      user,
      Uint8Array.from([pass.byteLength]),
      pass,
    ]),
  );

  const reply = await readExactly(reader, 2, 'SOCKS5 authentication reply', where);
  if (reply[0] !== AUTH_VERSION) {
    throw new ProxyError(
      codes.PROXY_PROTOCOL,
      `SOCKS5 proxy ${where} answered authentication with version ${hex8(reply[0])}, expected 0x01`,
      { proxy: where, version: reply[0] },
    );
  }
  if (reply[1] !== 0x00) {
    throw new ProxyError(
      codes.PROXY_AUTH_FAILED,
      `SOCKS5 proxy ${where} rejected the credentials for user "${proxy.username}" ` +
        `(status ${hex8(reply[1])})`,
      { proxy: where, status: reply[1] },
    );
  }
}

async function request(reader, writer, target, where) {
  await writer.write(
    concat([Uint8Array.from([VERSION, CMD_CONNECT, 0x00]), encodeAddress(target)]),
  );

  const head = await readExactly(reader, 4, 'SOCKS5 reply', where);
  if (head[0] !== VERSION) {
    throw new ProxyError(
      codes.PROXY_PROTOCOL,
      `SOCKS5 proxy ${where} answered CONNECT with version ${hex8(head[0])}, expected 0x05`,
      { proxy: where, version: head[0] },
    );
  }
  const rep = head[1];
  const atyp = head[3];

  // The bound address must be drained even on failure, or a caller that retries on the same
  // socket would read it as the next reply. Unknown ATYP means we cannot know how much to drain,
  // which is exactly why it is fatal rather than ignorable.
  const addrLen = await boundAddressLength(reader, atyp, where);
  await readExactly(reader, addrLen + 2, 'SOCKS5 BND.ADDR and BND.PORT', where);

  if (rep !== 0x00) {
    throw new ProxyError(
      codes.SOCKS5_REPLY,
      `SOCKS5 proxy ${where} refused CONNECT to ${target.hostname}:${target.port}: ` +
        `${REPLY[rep] ?? 'unassigned reply code'} (${hex8(rep)})`,
      { proxy: where, reply: rep, target: `${target.hostname}:${target.port}` },
    );
  }
}

async function boundAddressLength(reader, atyp, where) {
  if (atyp === ATYP.ipv4) return 4;
  if (atyp === ATYP.ipv6) return 16;
  if (atyp === ATYP.domain) {
    const len = await readExactly(reader, 1, 'SOCKS5 BND.ADDR length', where);
    return len[0];
  }
  throw new ProxyError(
    codes.SOCKS5_ADDR_TYPE,
    `SOCKS5 proxy ${where} replied with address type ${hex8(atyp)}; the reply cannot be framed ` +
      'and the stream position is unknown, so the tunnel is unusable',
    { proxy: where, atyp },
  );
}

/**
 * Encode DST.ADDR + DST.PORT. Prefers the domain form so the proxy resolves.
 * @param {{ hostname: string, port: number }} target
 * @returns {Uint8Array}
 */
export function encodeAddress(target) {
  const { hostname, port } = target;
  const portBytes = Uint8Array.from([(port >> 8) & 0xff, port & 0xff]);

  if (isIpv4(hostname)) {
    const octets = hostname.split('.').map(Number);
    return concat([Uint8Array.from([ATYP.ipv4, ...octets]), portBytes]);
  }
  if (hostname.includes(':')) {
    return concat([Uint8Array.from([ATYP.ipv6]), parseIpv6(hostname), portBytes]);
  }
  const name = utf8(hostname);
  if (name.byteLength === 0 || name.byteLength > 255) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `SOCKS5 domain name must be 1..255 bytes, got ${name.byteLength}`,
      { hostname },
    );
  }
  return concat([Uint8Array.from([ATYP.domain, name.byteLength]), name, portBytes]);
}

/**
 * Minimal IPv6 text parser: `::` compression and a trailing embedded IPv4 are both real.
 * Throws ConfigError on anything that does not expand to exactly 8 groups.
 * @param {string} text
 * @returns {Uint8Array} the 16 address bytes
 */
export function parseIpv6(text) {
  let s = text.replace(/^\[|\]$/g, '');
  const zone = s.indexOf('%');
  if (zone !== -1) s = s.slice(0, zone);

  let tail = [];
  const lastColon = s.lastIndexOf(':');
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    if (!isIpv4(maybeV4)) {
      throw new ConfigError(codes.CONFIG_INVALID, `"${text}" is not a valid IPv6 address`);
    }
    const o = maybeV4.split('.').map(Number);
    tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    s = s.slice(0, lastColon + 1) + '0:0';
  }

  const halves = s.split('::');
  if (halves.length > 2) {
    throw new ConfigError(codes.CONFIG_INVALID, `"${text}" has more than one "::"`);
  }
  const parse = (part) =>
    part === '' ? [] : part.split(':').map((g) => {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
        throw new ConfigError(codes.CONFIG_INVALID, `"${text}" has an invalid group "${g}"`);
      }
      return parseInt(g, 16);
    });

  let groups;
  if (halves.length === 2) {
    const head = parse(halves[0]);
    const rest = parse(halves[1]);
    const fill = 8 - head.length - rest.length;
    if (fill < 0) throw new ConfigError(codes.CONFIG_INVALID, `"${text}" has too many groups`);
    groups = [...head, ...new Array(fill).fill(0), ...rest];
  } else {
    groups = parse(halves[0]);
  }
  if (tail.length) groups = [...groups.slice(0, 6), ...tail].slice(0, 8);
  if (groups.length !== 8) {
    throw new ConfigError(
      codes.CONFIG_INVALID,
      `"${text}" expands to ${groups.length} groups, not 8`,
    );
  }
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    out[i * 2] = (g >> 8) & 0xff;
    out[i * 2 + 1] = g & 0xff;
  });
  return out;
}

async function readExactly(reader, n, what, where) {
  try {
    return await reader.readExactly(n, what);
  } catch (cause) {
    throw new ProxyError(
      codes.PROXY_PROTOCOL,
      `SOCKS5 proxy ${where} closed or stalled during ${what}: ${cause?.message ?? cause}`,
      { proxy: where, what },
    );
  }
}

/** Bytes that arrived alongside the reply are tunnel payload; the buffered reader carries them. */
function tunnelFrom(socket, reader) {
  return {
    readable: tunnelReadable(socket, reader),
    writable: socket.writable,
    opened: socket.opened,
    close: () => socket.close?.(),
    socket,
  };
}
