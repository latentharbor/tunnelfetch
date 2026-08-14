// Resolving the host runtime's socket factory.
//
// The interesting cases are the failures. A socket factory that cannot be found is a deployment
// mistake, and the whole point of this module is that the mistake names itself here rather than
// surfacing later as "connect is not a function" from somewhere inside the TLS layer.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isConnectFn,
  normaliseSocket,
  normalisingConnect,
  resolveConnect,
} from '../src/connect.js';
import { rejectsWithCode } from './_harness.js';

const duplex = () => ({
  readable: new ReadableStream({ start: (c) => c.close() }),
  writable: new WritableStream(),
});

// ------------------------------------------------------------------ resolveConnect

test('an injected connect is returned as-is, without importing anything', async () => {
  const connect = () => duplex();
  let imported = false;
  const got = await resolveConnect({
    connect,
    specifiers: ['never:imported'],
    importModule: () => {
      imported = true;
      return Promise.resolve({});
    },
  });
  assert.equal(got, connect);
  assert.equal(imported, false, 'the injected path must short-circuit before any import');
});

test('the first specifier exporting a callable connect wins', async () => {
  const wanted = () => duplex();
  const tried = [];
  const got = await resolveConnect({
    specifiers: ['a:missing', 'b:no-export', 'c:good', 'd:never'],
    importModule: (spec) => {
      tried.push(spec);
      if (spec === 'a:missing') return Promise.reject(new Error('nope'));
      if (spec === 'b:no-export') return Promise.resolve({ notConnect: 1 });
      if (spec === 'c:good') return Promise.resolve({ connect: wanted });
      return Promise.resolve({ connect: () => duplex() });
    },
  });
  assert.equal(got, wanted);
  assert.deepEqual(tried, ['a:missing', 'b:no-export', 'c:good'], 'must stop at the first hit');
});

test('a default export carrying connect is accepted, as CommonJS interop produces', async () => {
  const wanted = () => duplex();
  const got = await resolveConnect({
    specifiers: ['x:cjs'],
    importModule: () => Promise.resolve({ default: { connect: wanted } }),
  });
  assert.equal(got, wanted);
});

test('exportName selects a differently-named factory', async () => {
  const wanted = () => duplex();
  const got = await resolveConnect({
    specifiers: ['x:other'],
    exportName: 'createSocket',
    importModule: () => Promise.resolve({ createSocket: wanted }),
  });
  assert.equal(got, wanted);
});

test('nothing resolvable fails with CONFIG_UNSATISFIABLE naming every specifier tried', async () => {
  const err = await rejectsWithCode(
    () =>
      resolveConnect({
        specifiers: ['a:missing', 'b:no-export'],
        importModule: (spec) =>
          spec === 'a:missing' ? Promise.reject(new Error('not found')) : Promise.resolve({}),
      }),
    'CONFIG_UNSATISFIABLE',
  );
  // The message has to be actionable on its own: it is what a deployment sees.
  assert.match(err.message, /a:missing/);
  assert.match(err.message, /not found/);
  assert.match(err.message, /b:no-export/);
  assert.match(err.message, /no callable "connect" export/);
  assert.deepEqual(err.detail.tried.length, 2);
});

test('no specifiers and no connect says so rather than listing an empty attempt', async () => {
  const err = await rejectsWithCode(() => resolveConnect(), 'CONFIG_UNSATISFIABLE');
  assert.match(err.message, /No specifiers were given/);
});

test('a non-callable connect is refused rather than deferred', async () => {
  // A specifier STRING where a function belongs is the likely mistake, so it is the one tested.
  await rejectsWithCode(() => resolveConnect({ connect: 'some:sockets' }), 'CONFIG_INVALID');
  await rejectsWithCode(() => resolveConnect({ connect: {} }), 'CONFIG_INVALID');
});

test('malformed specifier lists are refused', async () => {
  await rejectsWithCode(() => resolveConnect({ specifiers: 'not-an-array' }), 'CONFIG_INVALID');
  await rejectsWithCode(() => resolveConnect({ specifiers: [''] }), 'CONFIG_INVALID');
  await rejectsWithCode(() => resolveConnect({ specifiers: [42] }), 'CONFIG_INVALID');
  await rejectsWithCode(
    () => resolveConnect({ specifiers: ['a:b'], importModule: 'nope' }),
    'CONFIG_INVALID',
  );
});

test('isConnectFn accepts only callables', () => {
  assert.equal(isConnectFn(() => {}), true);
  assert.equal(isConnectFn(null), false);
  assert.equal(isConnectFn({}), false);
});

// ------------------------------------------------------------------ normaliseSocket

test('normaliseSocket reads the duplex off the prototype, so the result survives a spread', () => {
  // The exact shape the edge runtime hands back: readable/writable are ACCESSORS ON THE PROTOTYPE,
  // which is why `{ ...socket }` loses them and why this function exists at all.
  const d = duplex();
  class HostSocket {
    get readable() {
      return d.readable;
    }
    get writable() {
      return d.writable;
    }
    close() {
      this.closed = true;
    }
  }
  const socket = new HostSocket();

  assert.equal({ ...socket }.readable, undefined, 'precondition: a spread loses the accessors');

  const flat = normaliseSocket(socket);
  const spread = { ...flat };
  assert.equal(spread.readable, d.readable);
  assert.equal(spread.writable, d.writable);

  flat.close();
  assert.equal(socket.closed, true, 'close must still reach the host socket');
});

test('normaliseSocket refuses a socket missing either half', () => {
  assert.throws(() => normaliseSocket(null), { code: 'CONFIG_INVALID' });
  assert.throws(() => normaliseSocket('socket'), { code: 'CONFIG_INVALID' });
  assert.throws(() => normaliseSocket({ writable: new WritableStream() }), {
    code: 'CONFIG_INVALID',
  });
  assert.throws(() => normaliseSocket({ readable: new ReadableStream() }), {
    code: 'CONFIG_INVALID',
  });
});

test('normaliseSocket tolerates a socket with no close, and preserves opened', async () => {
  const opened = Promise.resolve({ remoteAddress: null, localAddress: null });
  const flat = normaliseSocket({ ...duplex(), opened });
  assert.equal(flat.opened, opened);
  await flat.close(); // must not throw
});

// ------------------------------------------------------------------ normalisingConnect

test('normalisingConnect flattens every socket the factory returns, passing args through', () => {
  const seen = [];
  const d = duplex();
  const wrapped = normalisingConnect((addr, opts) => {
    seen.push([addr, opts]);
    return Object.create({ readable: d.readable, writable: d.writable });
  });
  const sock = wrapped({ hostname: 'h.example', port: 443 }, { secureTransport: 'off' });
  assert.equal({ ...sock }.readable, d.readable);
  assert.deepEqual(seen, [[{ hostname: 'h.example', port: 443 }, { secureTransport: 'off' }]]);
});

test('normalisingConnect refuses a non-callable factory', () => {
  assert.throws(() => normalisingConnect(null), { code: 'CONFIG_INVALID' });
});
