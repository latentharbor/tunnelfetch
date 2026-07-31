// A `connect` factory over node:net, so the live suite can run on a developer machine.
//
// This file is the one place in the repo that talks to a real network, and it lives under
// test/live/ with a *.live.js sibling naming convention precisely so it can never be picked up by
// the offline glob. `node:net` is fine here: the live rig is not shipped, and on the target
// runtime the equivalent factory is the platform's own socket module.

import net from 'node:net';

/**
 * @returns {(addr: {hostname: string, port: number}, opts?: object) => {
 *   readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>,
 *   opened: Promise<{remoteAddress: string|null, localAddress: string|null}>,
 *   close: () => Promise<void> }}
 */
export function nodeConnect() {
  return (addr, opts = {}) => {
    if (opts.secureTransport === 'on') {
      // The `https` proxy scheme needs TLS to the proxy itself, which on the target runtime the
      // platform provides. Reproducing that here would mean node:tls and a second trust store,
      // which is not what the live suite is for.
      throw new Error('the node live rig does not implement TLS to the proxy; use an http proxy');
    }
    const socket = net.connect({ host: addr.hostname, port: addr.port });
    socket.setNoDelay(true);

    const opened = new Promise((resolve, reject) => {
      socket.once('connect', () =>
        resolve({
          remoteAddress: `${socket.remoteAddress}:${socket.remotePort}`,
          localAddress: `${socket.localAddress}:${socket.localPort}`,
        }),
      );
      socket.once('error', reject);
    });
    opened.catch(() => {});

    const readable = new ReadableStream({
      start(controller) {
        socket.on('data', (chunk) => controller.enqueue(new Uint8Array(chunk)));
        socket.on('end', () => {
          try {
            controller.close();
          } catch {
            /* already closed */
          }
        });
        socket.on('error', (err) => {
          try {
            controller.error(err);
          } catch {
            /* already errored */
          }
        });
      },
      cancel() {
        socket.destroy();
      },
    });

    const writable = new WritableStream({
      write(chunk) {
        return new Promise((resolve, reject) => {
          socket.write(chunk, (err) => (err ? reject(err) : resolve()));
        });
      },
      close() {
        return new Promise((resolve) => socket.end(resolve));
      },
      abort() {
        socket.destroy();
      },
    });

    return {
      readable,
      writable,
      opened,
      close: async () => {
        socket.destroy();
      },
    };
  };
}

/**
 * Read a proxy from the environment. Accepts either a URL (`http://user:pass@host:port`) or the
 * `host:port:user:pass` shape many providers hand out.
 *
 * Fails loudly when unset. A live suite that goes green because it silently skipped is worse than
 * no live suite at all, so this throws rather than returning null.
 */
export function proxyFromEnv(name = 'TUNNELFETCH_PROXY') {
  const raw = process.env[name];
  if (!raw) {
    throw new Error(
      `${name} is not set. The live suite needs a proxy you control; it never uses a public one. ` +
        `Set ${name} to http://user:pass@host:port, socks5://user:pass@host:port, or ` +
        'host:port:user:pass, then run `npm run test:live`.',
    );
  }
  if (raw.includes('://')) return raw;
  const [host, port, user, pass] = raw.split(':');
  if (!host || !port) throw new Error(`${name}="${raw}" is not host:port[:user:pass]`);
  const auth = user ? `${encodeURIComponent(user)}:${encodeURIComponent(pass ?? '')}@` : '';
  return `http://${auth}${host}:${port}`;
}

export function socksFromEnv(name = 'TUNNELFETCH_SOCKS5') {
  const raw = process.env[name] ?? process.env.TUNNELFETCH_PROXY;
  if (!raw) {
    throw new Error(
      `${name} (or TUNNELFETCH_PROXY) is not set; the SOCKS5 live tests need a proxy you control.`,
    );
  }
  if (raw.startsWith('socks5://')) return raw;
  const stripped = raw.replace(/^https?:\/\//, '');
  if (stripped.includes('@')) return `socks5://${stripped}`;
  const [host, port, user, pass] = stripped.split(':');
  const auth = user ? `${encodeURIComponent(user)}:${encodeURIComponent(pass ?? '')}@` : '';
  return `socks5://${auth}${host}:${port}`;
}

/** Hosts the live suite dials. Kept here so a run against a different set is one edit. */
export const LIVE_TARGETS = (process.env.TUNNELFETCH_LIVE_TARGETS ?? 'www.google.com,github.com')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
