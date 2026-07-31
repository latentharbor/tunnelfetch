// The mirror of must-fail.ts: every line here MUST type-check. A union tight enough to reject
// bad input is only useful if it still accepts every legitimate shape, and it is easy to write
// one that does the first without the second.

import { Client, createFetch, install, verifyChain } from '../../types/index.js';

new Client({ trust: { mode: 'system' } });
new Client({}); // trust is optional and defaults to the bundled roots
new Client({ trust: { mode: 'pinned', pins: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] } });
new Client({ trust: { mode: 'none', insecureAcceptAnyCertificate: true } });
new Client({ trust: { mode: 'anchors', anchors: ['-----BEGIN CERTIFICATE-----'] } });
new Client({ trust: { mode: 'anchors', anchors: [new Uint8Array([0x30])] } });
new Client({ trust: { mode: 'custom', verify: async () => {} } });
new Client({ maxRedirects: 10, maxBodyBytes: 1024, cookies: true, forceTunnel: true });
new Client({ timeouts: { connectMs: 1000, idleMs: 5000 } });
new Client({ proxy: 'http://user:pass@proxy.example:8080' });
new Client({ proxy: null });

// The facade must be assignable to the platform's own fetch, since being droppable into an SDK
// that only accepts `typeof fetch` is the entire point of the package's shape.
const asGlobalFetch: typeof fetch = createFetch({});
void asGlobalFetch;

const undo: () => void = install({});
void undo;

// A Client instance must be usable as a bare fetch function too.
const bound: typeof fetch = new Client({}).fetch;
void bound;

void verifyChain({ chain: [new Uint8Array()], hostname: 'host.example' });
void verifyChain({ chain: [new Uint8Array()], hostname: 'host.example', trust: { mode: 'system' } });
