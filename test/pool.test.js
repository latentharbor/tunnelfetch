// The pool's job is small and its failure mode is severe: hand back a socket with unread bytes on
// it and the next request reads the previous response. Every test here is about the conditions
// under which a connection may be retained.

import test from 'node:test';
import assert from 'node:assert/strict';
import { ConnectionPool, poolKey } from '../src/pool.js';
import { rejectsWithCode } from './_harness.js';

const conn = (id) => {
  const c = { id, closed: 0 };
  c.close = async () => {
    c.closed++;
  };
  return c;
};

const base = { scheme: 'https:', hostname: 'h.example', port: 443, proxy: null, trust: undefined, tls: undefined };

test('a key separates origin, proxy, trust and tls options', () => {
  const k = poolKey(base);
  assert.notEqual(k, poolKey({ ...base, port: 8443 }));
  assert.notEqual(k, poolKey({ ...base, hostname: 'other.example' }));
  assert.notEqual(k, poolKey({ ...base, scheme: 'http:' }));
  assert.notEqual(
    k,
    poolKey({ ...base, proxy: { protocol: 'http', hostname: 'p.example', port: 8080 } }),
  );
  assert.equal(k, poolKey({ ...base, trust: { mode: 'system' } }), 'default trust is system');
});

test('different trust policies never share a connection', () => {
  // A peer validated under one policy must not silently satisfy another: reusing the socket would
  // mean the second policy was never actually applied to anything.
  const system = poolKey({ ...base, trust: { mode: 'system' } });
  const none = poolKey({ ...base, trust: { mode: 'none', insecureAcceptAnyCertificate: true } });
  const pinnedA = poolKey({ ...base, trust: { mode: 'pinned', pins: ['sha256/AAA='] } });
  const pinnedB = poolKey({ ...base, trust: { mode: 'pinned', pins: ['sha256/BBB='] } });
  assert.equal(new Set([system, none, pinnedA, pinnedB]).size, 4);
  // Pin order must not matter; the same set is the same policy.
  assert.equal(
    poolKey({ ...base, trust: { mode: 'pinned', pins: ['sha256/A=', 'sha256/B='] } }),
    poolKey({ ...base, trust: { mode: 'pinned', pins: ['sha256/B=', 'sha256/A='] } }),
  );
});

test('two different custom verifiers are two different policies', () => {
  const f = async () => {};
  const g = async () => {};
  assert.equal(
    poolKey({ ...base, trust: { mode: 'custom', verify: f } }),
    poolKey({ ...base, trust: { mode: 'custom', verify: f } }),
  );
  assert.notEqual(
    poolKey({ ...base, trust: { mode: 'custom', verify: f } }),
    poolKey({ ...base, trust: { mode: 'custom', verify: g } }),
  );
});

test('anchor sets are distinguished, and identical sets collide', () => {
  const a = poolKey({ ...base, trust: { mode: 'anchors', anchors: ['-----BEGIN A-----'] } });
  const b = poolKey({ ...base, trust: { mode: 'anchors', anchors: ['-----BEGIN B-----'] } });
  const a2 = poolKey({ ...base, trust: { mode: 'anchors', anchors: ['-----BEGIN A-----'] } });
  assert.notEqual(a, b);
  assert.equal(a, a2);
});

test('tls options are part of the key', () => {
  assert.notEqual(poolKey(base), poolKey({ ...base, tls: { alpn: ['http/1.1'] } }));
  // Option order must not create a spurious mismatch.
  assert.equal(
    poolKey({ ...base, tls: { a: 1, b: 2 } }),
    poolKey({ ...base, tls: { b: 2, a: 1 } }),
  );
});

test('take returns null on a cold pool and counts the miss', () => {
  const p = new ConnectionPool();
  assert.equal(p.take('k'), null);
  assert.equal(p.stats.misses, 1);
  assert.equal(p.stats.hits, 0);
});

test('an eligible connection round-trips and is reused most-recently-first', () => {
  const p = new ConnectionPool();
  const a = conn('a');
  const b = conn('b');
  assert.equal(p.release('k', a, true), true);
  assert.equal(p.release('k', b, true), true);
  assert.equal(p.idleCount, 2);
  // The newest is the one just proven alive, so it is handed out first.
  assert.equal(p.take('k'), b);
  assert.equal(p.take('k'), a);
  assert.equal(p.take('k'), null);
  assert.equal(p.idleCount, 0);
});

test('an ineligible connection is closed, never retained', async () => {
  const p = new ConnectionPool();
  const c = conn('c');
  assert.equal(p.release('k', c, false), false);
  assert.equal(p.idleCount, 0);
  await Promise.resolve();
  assert.equal(c.closed, 1, 'a connection that cannot be reused must be closed, not leaked');
  assert.equal(p.take('k'), null);
});

test('per-key capacity evicts the oldest rather than refusing the newest', async () => {
  const p = new ConnectionPool({ maxPerKey: 2 });
  const a = conn('a');
  const b = conn('b');
  const c = conn('c');
  p.release('k', a, true);
  p.release('k', b, true);
  p.release('k', c, true);
  assert.equal(p.idleCount, 2);
  assert.equal(p.stats.evicted, 1);
  await Promise.resolve();
  assert.equal(a.closed, 1, 'the evicted connection must be closed');
  assert.equal(p.take('k'), c);
  assert.equal(p.take('k'), b);
});

test('total capacity is enforced across keys', () => {
  const p = new ConnectionPool({ maxPerKey: 10, maxTotal: 2 });
  p.release('k1', conn(1), true);
  p.release('k2', conn(2), true);
  p.release('k3', conn(3), true);
  assert.ok(p.idleCount <= 2, `expected at most 2 idle, got ${p.idleCount}`);
});

test('keys do not leak into one another', () => {
  const p = new ConnectionPool();
  const a = conn('a');
  p.release('k1', a, true);
  assert.equal(p.take('k2'), null);
  assert.equal(p.take('k1'), a);
});

test('closeAll closes everything and the pool refuses further use', async () => {
  const p = new ConnectionPool();
  const a = conn('a');
  const b = conn('b');
  p.release('k1', a, true);
  p.release('k2', b, true);
  await p.closeAll();
  assert.equal(a.closed, 1);
  assert.equal(b.closed, 1);
  assert.equal(p.idleCount, 0);
  await rejectsWithCode(async () => p.take('k1'), 'POOL_CLOSED');
});

test('release after close discards rather than resurrecting the pool', async () => {
  const p = new ConnectionPool();
  await p.closeAll();
  const c = conn('c');
  assert.equal(p.release('k', c, true), false);
  await Promise.resolve();
  assert.equal(c.closed, 1);
});

test('a connection whose close() throws does not break the pool', async () => {
  const p = new ConnectionPool();
  const bad = {
    close: async () => {
      throw new Error('socket already reset');
    },
  };
  assert.equal(p.release('k', bad, false), false);
  await p.closeAll();
  await new Promise((r) => setTimeout(r, 0));
});

test('discard closes and counts', async () => {
  const p = new ConnectionPool();
  const c = conn('c');
  await p.discard(c);
  assert.equal(c.closed, 1);
  assert.equal(p.stats.discarded, 1);
});

test('stats track hits and misses honestly', () => {
  const p = new ConnectionPool();
  p.take('k');
  p.release('k', conn(1), true);
  p.take('k');
  p.take('k');
  assert.deepEqual(
    { hits: p.stats.hits, misses: p.stats.misses, released: p.stats.released },
    { hits: 1, misses: 2, released: 1 },
  );
});
