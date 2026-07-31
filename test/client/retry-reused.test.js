// When may a request be re-sent on a fresh connection?
//
// Reusing a pooled keep-alive socket races the peer's own idle reaper, so a client that never
// retries fails intermittently for reasons the caller cannot act on. But retrying is re-applying
// the request, and that is only defensible when the peer provably never saw it. The line lives in
// serverNeverSawIt() in src/client.js, and these tests pin both sides of it: the reap is retried,
// and a timeout — a request that may be executing on the server right now — is not.

import test from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '../../src/client.js';
import { fakeNetwork, readRequestHead, response } from '../_fakenet.js';
import { rejectsWithCode } from '../_harness.js';

/**
 * A server whose first socket answers exactly one request and then behaves as `thenWhat` says,
 * while every later socket answers normally. That is the shape of an idle connection the peer
 * reaped between our two requests.
 *
 * @param {(io: { write: (b: string) => Promise<void>, close: () => Promise<void> }) => Promise<void>} thenWhat
 */
function reapsAfterFirstRequest(thenWhat) {
  let socketIndex = 0;
  const handler = async ({ reader, write, close }) => {
    const mine = socketIndex++;
    let answered = 0;
    for (;;) {
      let head;
      try {
        head = await readRequestHead(reader);
      } catch {
        return; // client hung up
      }
      const declared = Number(head.headers.get('content-length') ?? 0);
      if (declared > 0) await reader.readExactly(declared, 'request body');

      if (mine === 0 && answered === 1) return thenWhat({ write, close });
      answered++;
      await write(response({ status: 200, body: `socket${mine}` }));
    }
  };
  return { handler };
}

/** Two sequential requests on one Client; the second lands on the pooled socket. */
async function twoRequests(net, opts = {}) {
  const client = new Client({ connect: net.connect, forceTunnel: true, ...opts });
  try {
    const first = await client.fetch('http://origin.example/one');
    assert.equal(await first.text(), 'socket0', 'the first request must be answered normally');
    assert.equal(client.pool.stats.released, 1, 'the first socket must go back to the pool');
    const second = await client.fetch('http://origin.example/two');
    return { body: await second.text(), client };
  } finally {
    await client.close();
  }
}

test('a pooled socket the peer reaped is retried once on a fresh connection', async () => {
  // The peer closes without writing anything: the record layer drains and the head reader hits EOF
  // with nothing buffered, which is the one state that proves the request was never seen.
  const net = fakeNetwork(reapsAfterFirstRequest(async ({ close }) => close()).handler);
  const { body } = await twoRequests(net);
  assert.equal(body, 'socket1', 'the retry must be answered by a second, fresh socket');
  assert.equal(net.calls.length, 2, 'exactly one extra connection may be opened');
});

test('a retry happens at most once: a second reap surfaces the error', async () => {
  // Socket 0 reaps after one answer, and the socket opened for the retry reaps immediately — so
  // the retry hits the identical "peer never saw it" state. The client must still stop there
  // rather than opening a third connection, because that attempt was not itself a reuse.
  let socketIndex = 0;
  const handler = async ({ reader, write, close }) => {
    const mine = socketIndex++;
    let answered = 0;
    for (;;) {
      let head;
      try {
        head = await readRequestHead(reader);
      } catch {
        return;
      }
      const declared = Number(head.headers.get('content-length') ?? 0);
      if (declared > 0) await reader.readExactly(declared, 'request body');
      if (mine > 0 || answered === 1) return close();
      answered++;
      await write(response({ status: 200, body: `socket${mine}` }));
    }
  };
  const net = fakeNetwork(handler);
  const client = new Client({ connect: net.connect, forceTunnel: true });
  try {
    await (await client.fetch('http://origin.example/one')).text();
    await assert.rejects(() => client.fetch('http://origin.example/two'));
    assert.equal(net.calls.length, 2, 'one retry, not a retry loop');
  } finally {
    await client.close();
  }
});

test('a malformed response head on a pooled socket is NOT retried', async () => {
  // The sharpest case, because nothing else stops it. A timeout is incidentally protected — the
  // deadline has already aborted, so a retry would die on the spot — but a peer that answers with
  // garbage fails while the deadline is still live, so only the predicate stands between a POST
  // and being applied twice. The peer clearly received the request: it replied.
  const net = fakeNetwork(
    reapsAfterFirstRequest(async ({ write, close }) => {
      await write('HTTP/1.1 banana\r\n\r\n'); // complete head block, unparseable status line
      await close();
    }).handler,
  );
  const client = new Client({ connect: net.connect, forceTunnel: true });
  try {
    await (await client.fetch('http://origin.example/one')).text();
    await assert.rejects(() =>
      client.fetch('http://origin.example/two', { method: 'POST', body: 'charge me once' }));
    assert.equal(net.calls.length, 1, 'a peer that answered must never be re-POSTed to');
  } finally {
    await client.close();
  }
});

test('a headers timeout on a pooled socket is NOT retried', async () => {
  // The decisive case. A timeout says nothing about whether the server saw the request — it may be
  // executing it right now — so re-sending could apply a non-idempotent operation twice. The
  // client must report the timeout and open no second connection.
  const net = fakeNetwork(
    reapsAfterFirstRequest(() => new Promise(() => {})).handler, // accept, then never answer
  );
  const client = new Client({
    connect: net.connect,
    forceTunnel: true,
    timeouts: { headersMs: 150 },
  });
  try {
    await (await client.fetch('http://origin.example/one')).text();
    await rejectsWithCode(
      () => client.fetch('http://origin.example/two', { method: 'POST', body: 'charge me once' }),
      'TIMEOUT_HEADERS',
    );
    assert.equal(net.calls.length, 1, 'a timed-out request must not be re-sent');
  } finally {
    await client.close();
  }
});

test('a peer that began answering and then died is NOT retried', async () => {
  // Partial bytes prove the peer had the request, so re-sending it is the same double-apply
  // hazard as the timeout, even though this failure is also an EOF.
  const net = fakeNetwork(
    reapsAfterFirstRequest(async ({ write, close }) => {
      await write('HTTP/1.1 200 OK\r\nContent-Len'); // dies mid-header-block
      await close();
    }).handler,
  );
  const client = new Client({ connect: net.connect, forceTunnel: true });
  try {
    await (await client.fetch('http://origin.example/one')).text();
    await assert.rejects(() => client.fetch('http://origin.example/two'));
    assert.equal(net.calls.length, 1, 'a half-answered request must not be re-sent');
  } finally {
    await client.close();
  }
});
