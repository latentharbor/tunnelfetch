// End-to-end redirect behaviour over the in-memory network, ported from httpx's
// tests/client/test_redirects.py. redirect.test.js already covers the pure nextRequest() engine;
// this file exercises the FULL client loop (performFetch), where the hop budget, the cookie jar,
// and the body replay all interact — and where an off-by-a-factor-of-two in the hop counter hid.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { fakeNetwork, readRequestHead, response } from '../_fakenet.js';
import { rejectsWithCode } from '../_harness.js';

/** A server that always 302s to a fresh, never-before-seen path (so no loop, only depth). */
function alwaysRedirects() {
  const targets = [];
  let n = 0;
  const handler = async ({ reader, write }) => {
    for (;;) {
      let head;
      try {
        head = await readRequestHead(reader);
      } catch {
        return;
      }
      targets.push(head.target);
      const declared = Number(head.headers.get('content-length') ?? 0);
      if (declared > 0) {
        try {
          await reader.readExactly(declared, 'body');
        } catch {
          /* gone */
        }
      }
      await write(response({ status: 302, headers: { location: `/hop${++n}` }, body: '' }));
    }
  };
  return { handler, targets };
}

/**
 * The number of redirects the client actually follows before giving up, for a given maxRedirects.
 * The server 302s forever, so this measures the hop budget directly.
 */
async function redirectsFollowed(maxRedirects) {
  const server = alwaysRedirects();
  const net = fakeNetwork(server.handler);
  const client = new Client({ connect: net.connect, forceTunnel: true, maxRedirects });
  let code = null;
  try {
    await client.fetch('http://origin.example/start');
  } catch (e) {
    code = e.code;
  }
  await client.close();
  // Requests sent = redirects followed + the final one that tripped the limit.
  return { followed: server.targets.length - 1, code };
}

test('maxRedirects is the exact number of redirects followed, not half of it', async () => {
  // BUG (found by this port, fixed): performFetch pushed to the same `history` array that
  // nextRequest already appends to, so every hop counted twice and the client stopped at
  // maxRedirects/2. With the default of 20 this silently followed only 10.
  for (const max of [1, 2, 4, 20]) {
    const { followed, code } = await redirectsFollowed(max);
    assert.equal(code, 'LIMIT_REDIRECTS', `max=${max} must end in LIMIT_REDIRECTS`);
    assert.equal(followed, max, `max=${max}: expected exactly ${max} redirects followed, got ${followed}`);
  }
});

test('a chain shorter than the limit completes and reports redirected + final url', async () => {
  // Exactly `count` redirects, then a 200. With a generous budget this must succeed.
  function chainThenOk(count) {
    let n = 0;
    const targets = [];
    const handler = async ({ reader, write }) => {
      for (;;) {
        let head;
        try {
          head = await readRequestHead(reader);
        } catch {
          return;
        }
        targets.push(head.target);
        if (n < count) {
          await write(response({ status: 302, headers: { location: `/step${++n}` }, body: '' }));
        } else {
          await write(response({ body: 'arrived' }));
        }
      }
    };
    return { handler, targets };
  }
  const server = chainThenOk(19); // 19 hops fits inside the default 20
  const net = fakeNetwork(server.handler);
  const client = new Client({ connect: net.connect, forceTunnel: true });
  const res = await client.fetch('http://origin.example/start');
  assert.equal(await res.text(), 'arrived');
  assert.equal(res.redirected, true);
  assert.equal(res.url, 'http://origin.example/step19');
  assert.equal(server.targets.length, 20, 'start + 19 redirect targets');
  await client.close();
});

test('a request that is never redirected reports redirected:false', async () => {
  const handler = async ({ reader, write }) => {
    for (;;) {
      try {
        await readRequestHead(reader);
      } catch {
        return;
      }
      await write(response({ body: 'direct' }));
    }
  };
  const net = fakeNetwork(handler);
  const client = new Client({ connect: net.connect, forceTunnel: true });
  const res = await client.fetch('http://origin.example/');
  assert.equal(await res.text(), 'direct');
  assert.equal(res.redirected, false);
  await client.close();
});

test('307 replays the body every hop with a correct Content-Length and no stale framing', async () => {
  // Two 307s then a 200. The body must be re-sent verbatim on all three requests, each framed by
  // its true length and never accompanied by a Transfer-Encoding.
  let n = 0;
  const heads = [];
  const handler = async ({ reader, write }) => {
    for (;;) {
      let head;
      try {
        head = await readRequestHead(reader);
      } catch {
        return;
      }
      const declared = Number(head.headers.get('content-length') ?? 0);
      let body = '';
      if (declared > 0) body = new TextDecoder().decode(await reader.readExactly(declared, 'body'));
      heads.push({ method: head.method, cl: head.headers.get('content-length'),
        te: head.headers.get('transfer-encoding'), body });
      if (n < 2) {
        await write(response({ status: 307, headers: { location: `/again${++n}` }, body: '' }));
      } else {
        await write(response({ body: 'done' }));
      }
    }
  };
  const net = fakeNetwork(handler);
  const client = new Client({ connect: net.connect, forceTunnel: true });
  await (await client.fetch('http://origin.example/p', { method: 'POST', body: 'payload' })).text();
  await client.close();
  assert.equal(heads.length, 3);
  for (const h of heads) {
    assert.equal(h.method, 'POST', 'method preserved across 307');
    assert.equal(h.body, 'payload', 'body replayed verbatim');
    assert.equal(h.cl, '7', 'Content-Length matches the replayed body');
    assert.equal(h.te, undefined, 'no phantom Transfer-Encoding on the replay');
  }
});

test('too-many-redirects is reported even when every Location is a fresh valid URL', async () => {
  const server = alwaysRedirects();
  const net = fakeNetwork(server.handler);
  const client = new Client({ connect: net.connect, forceTunnel: true, maxRedirects: 5 });
  await rejectsWithCode(() => client.fetch('http://origin.example/start'), 'LIMIT_REDIRECTS');
  await client.close();
});
