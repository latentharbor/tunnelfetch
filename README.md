# tunnelfetch

[English](README.md) · [简体中文](README.zh-CN.md)

A `fetch`-shaped HTTP client that can route through an HTTP CONNECT, HTTPS, or SOCKS5 proxy on
runtimes that expose only raw TCP — principally Cloudflare Workers (`workerd`).

Zero dependencies. ESM. No build step. No `node:` imports anywhere in `src/`.

```js
import { Client } from 'tunnelfetch';
import { connect } from 'cloudflare:sockets';

const client = new Client({ connect, proxy: 'http://user:pass@proxy.example:8080' });
const res = await client.fetch('https://api.example.com/v1/things');
const data = await res.json();
await client.close();
```

## Why this exists

On Cloudflare Workers there is no supported way to send an HTTPS request through a third-party
proxy. The reasons are structural, and each was measured on the edge rather than inferred:

1. **`fetch()` has no proxy option.** No `proxy`, no `agent`, no `dispatcher`. The runtime's
   outbound routing controls (`fetcher`, `globalOutbound`) point at other Workers, not at proxies.
2. **`node:net` / `node:tls` do not help.** They are real, but they are implemented on top of the
   same `cloudflare:sockets` API and inherit every one of its limits.
3. **`cloudflare:sockets` `connect()` gives raw TCP**, so a CONNECT or SOCKS5 handshake is
   perfectly possible — but the TLS *inside* that tunnel is not.

That third point is the whole problem. `startTls()` verifies the peer certificate against the
hostname passed to `connect()`. Inside a tunnel that hostname is **the proxy**, not the origin, so
the runtime checks the wrong identity. The `expectedServerHostname` option looks like the fix and
is not: workerd's own source calls it "not currently supported", logs every use, and carries an
autogate to start rejecting it outright. Measured on the edge on 2026-07-31:

| Experiment | Result |
| --- | --- |
| `connect(A)` → `startTls()` | handshake completes, data flows |
| `connect(A)` → `startTls({expectedServerHostname: B})` | handshake **still** completes — the option moves SNI, not the identity gate |
| `connect(A)` → `startTls({expectedServerHostname: "probe.invalid"})` | still completes |
| CONNECT tunnel to origin → `startTls({expectedServerHostname: origin})` | **`TLS Handshake Failed`** |

The tunnel case fails closed, which is the right failure — but it leaves no route. And
`getPeerCertificate()` throws `not implemented`, `SocketInfo` carries only addresses, and
`rejectUnauthorized: false` throws, so the certificate can be neither inspected nor re-checked
afterwards.

So the only way to make a proxied HTTPS request from a Worker, and the only way to offer
httpx-style `verify=` at all, is to implement TLS in userland. That is what this package does.

**Verified end to end on the Cloudflare edge**, through five different third-party proxies:
TLS 1.3 (`0x0304`), `TLS_AES_128_GCM_SHA256`, X25519, ALPN `http/1.1`, chunked and
content-length framing, gzip decoded, chains validated against 121 bundled CCADB roots.

## Install

```bash
npm install tunnelfetch
```

The package ships plain ESM under `src/`. There is no build output and no `nodejs_compat`
requirement — the live rig deploys with no compatibility flags at all.

TypeScript declarations ship in `types/`, generated from the JSDoc in the source and committed, so
nothing needs building on install. They are not decoration: `trust` is a discriminated union, which
makes several ways of getting security configuration wrong into compile errors rather than runtime
ones.

```ts
new Client({ trust: { mode: 'pinned' } });
//                   ^ Property 'pins' is missing but required in type 'PinnedTrust'

new Client({ trust: { mode: 'none' } });
//                   ^ Property 'insecureAcceptAnyCertificate' is missing but required
```

## Usage

### As a custom `fetch`

The OpenAI and Anthropic SDKs, and most libraries worth proxying, accept a `fetch` function. That
shape is the primary deliverable.

```js
import { Client } from 'tunnelfetch';
import { connect } from 'cloudflare:sockets';
import Anthropic from '@anthropic-ai/sdk';

const transport = new Client({ connect, proxy: env.PROXY_URL });

const client = new Anthropic({
  apiKey: env.ANTHROPIC_API_KEY,
  fetch: transport.fetch,          // already bound; the pool survives across calls
});
```

`client.fetch` is bound in the constructor precisely so it can be handed to an SDK by reference.
Prefer it over `createFetch` here: `createFetch` opens and closes a connection per call, which on a
CPU-metered runtime costs a full TLS handshake every time — measured at roughly 10 ms against
0.9 ms for a request on an already-open connection. `createFetch` is for one-off calls, matching
httpx's module-level helpers.

### With connection reuse and a cookie jar

```js
const client = new Client({
  connect,
  proxy: 'socks5://user:pass@proxy.example:1080',
  cookies: true,
});

for (const url of urls) {
  const res = await client.fetch(url);
  await handle(await res.text());
}
await client.close();          // required: releases pooled sockets
```

Measured on the edge: first request 678 ms, second to the same origin 135 ms.

### Replacing the global

For libraries that only ever call the bare global:

```js
import { install } from 'tunnelfetch';
const uninstall = install({ connect, proxy: env.PROXY_URL });
try { await thirdPartyLibrary(); } finally { uninstall(); }
```

This never happens on import. Silently replacing a global makes every unrelated failure in the
process look like a bug in this package.

### Warming a fresh isolate

V8 compiles and optimises per function per isolate, so the first request through a fresh isolate
runs the TLS and HTTP paths interpreted — 46 ms against a warm floor of about 10 ms, with the
excess decaying over roughly six requests. `warmup()` replays a recorded handshake through the real
drivers at module scope, so the first real request meets code the engine has already tiered.

```js
import { warmup } from 'tunnelfetch';

await warmup();                       // module scope, once per isolate
export default { async fetch(req, env) { /* ... */ } };
```

It is opt-in and nothing in this package ever calls it, because the trade is not the same for
everyone. Standard Workers do not bill startup CPU, so this converts billed request milliseconds
into unbilled startup ones; deployment modes that *do* bill startup — Cloudflare's dynamic Worker
loading, for instance — pay for the same work twice over, plus the wall time. A library should not
make that choice for its consumer.

It caches nothing and holds no state: the replay validates its own synthetic chain against its own
baked root through an explicit anchors-mode configuration, never consulting the bundled store, and
not calling `warmup()` leaves behaviour byte-identical, only slower at first. A Worker that imports
but never calls it is measurably unaffected. See the cost table for what each iteration count buys.

### Server-sent events

SSE has no code of its own here: it is a `text/event-stream` body like any other. What matters is
that bodies genuinely stream, and they do — measured on the edge through a proxy, a 592 KB
response arrives as 442 separate chunks, the first at the same instant as the headers.

```js
const client = new Client({
  connect,
  proxy: env.PROXY_URL,
  timeouts: { idleMs: 60_000, totalMs: 0 },
});
const res = await client.fetch(url, { headers: { accept: 'text/event-stream' } });
for await (const chunk of res.body) {
  // events arrive as they are written, not when the response ends
}
```

Two settings are worth choosing deliberately. `idleMs` is the gap between chunks, not the total
duration — raise it above your feed's heartbeat interval, or a quiet-but-alive stream will be cut.
`totalMs` defaults to off, which is what a long-lived stream wants; turn it on only as a backstop.

Abandoning a stream part-way never returns the connection to the pool: its position is unknown,
and reusing it would splice the remains of one response onto the next request.

## API

### `new Client(options)`

| Option | Default | Meaning |
| --- | --- | --- |
| `connect` | — | Socket factory. On Workers, the `connect` export of `cloudflare:sockets`. Required for anything the platform's `fetch` cannot serve. |
| `proxy` | `null` | URL string or object. `http:`, `https:`, `socks5:`, `socks5h:`. |
| `trust` | `{mode:'system'}` | Certificate policy; see below. |
| `tls` | `{}` | Handshake options (`alpn`, `groups`, `ciphers`, `offerGroups`). |
| `timeouts` | see below | `connectMs`, `handshakeMs`, `headersMs`, `idleMs`, `totalMs`. |
| `cookies` | `false` | Enable a per-Client cookie jar. |
| `maxRedirects` | `20` | |
| `maxBodyBytes` | `Infinity` | Enforced from `Content-Length` before a byte is read. |
| `decompress` | `true` | gzip/deflate. Never `br` — see limits. |
| `keepAlive` | `true` | |
| `forceTunnel` | `false` | Never delegate to the platform's `fetch`. |
| `nativeFetch` | `globalThis.fetch` | Delegation target. |

`client.fetch(input, init)` takes and returns the platform's `Request`/`Response`. The response
carries a non-standard `tunnelfetch` property with `{proxied, proxy, tls, httpVersion, framing}`.

`client.close()` releases every pooled socket. A `Client` that is not closed leaks sockets for the
lifetime of the isolate.

### Trust — the `verify=` knob

```js
{ mode: 'system' }                                  // bundled CCADB roots (default)
{ mode: 'anchors', anchors: [pemOrDer, ...] }       // exactly these, nothing else
{ mode: 'pinned', pins: ['sha256/BASE64...'] }      // full validation plus an SPKI pin set
{ mode: 'custom', verify: async (chain, host) => {} } // your policy; throw to reject
{ mode: 'none', insecureAcceptAnyCertificate: true } // no verification at all
```

`mode: 'none'` requires the second flag; it cannot be reached by a typo. A pin mismatch reports
the pins it actually saw, so the right one can be copied out of a log:

```
CertificateError [CERT_PIN_MISMATCH]: no certificate in the chain matches any configured pin
(observed: sha256/uOmwqBIvMM6bY2khsu8Tmp+ltdXst3nxA6Z3ZuKeAWA=, sha256/ZSagvDzj…)
```

### When the platform's `fetch` is used instead

A request is delegated to the platform's own `fetch` only when it can be satisfied **identically**:
no proxy, default trust, no TLS options, no `forceTunnel`. Anything else runs through this stack.
Handing a request that asked for a pinned certificate to an implementation using a different trust
store would answer a question the caller never asked.

Delegation is usually what you want when it applies: it is faster, costs no metered CPU, speaks
HTTP/2 and /3, and reaches origins raw sockets are forbidden from dialling.

### Timeouts

| Deadline | Default | |
| --- | --- | --- |
| `connectMs` | 10 000 | TCP connect and proxy handshake |
| `handshakeMs` | 15 000 | TLS handshake |
| `headersMs` | 30 000 | status line and headers |
| `idleMs` | 60 000 | **gap between body chunks** |
| `totalMs` | `0` (off) | whole-request ceiling |

The idle deadline is the control, not the total: for a streaming response "how long since the last
byte" is the signal that something is wrong, while "how long in total" is not. Every timer is
driven by stream events rather than by reading a clock, because on this runtime `Date.now()` is
frozen for the whole of a synchronous slice and only advances across I/O — a deadline implemented
by polling the clock would either never fire or fire at an unrelated moment.

These are liveness controls, not cost controls. The runtime bills CPU, not wall clock, so a
connection waiting on a slow peer is free; and after the response head arrives it stops occupying
one of the six slots an invocation may have simultaneously awaiting headers. That asymmetry is why
`idleMs` defaults long: too long merely holds an unbilled connection, too short kills a request
that would have succeeded. Do not try to tune it to a peer's keep-alive interval — streaming APIs
that send keep-alive events generally do not commit to one, and a peer that is computing a long
answer before its first byte is legitimately silent for as long as that takes.

`headersMs` is the one phase that does hold a header-wait slot, so it is tighter. Raise it for a
peer that buffers an entire slow response before sending its head; a peer that streams sends its
head immediately and never needs it.

## What this cannot do, and why

This section is the important one. Each limit is deliberate.

**Direct (unproxied) connections reach very little of the web.** `connect()` refuses Cloudflare's
own address ranges, and a large share of the internet sits behind them — including, today,
`example.com`. Refusal takes 0–6 ms with `proxy request failed, cannot connect to the specified
address`. The practical consequence: **certificate pinning and custom anchors are only available
through a proxy**, because direct mode cannot reach most origins at all.

**TLS 1.3 and 1.2 only, AEAD only.** Negotiable: TLS 1.3 with AES-128/256-GCM, and TLS 1.2 with
ECDHE + AES-GCM. Key exchange X25519, P-256, P-384, P-521. Signatures ECDSA, RSA-PSS,
RSA-PKCS#1 (SHA-256 and up), Ed25519.

Not implemented, and not planned:

- **CBC cipher suites, in any TLS version.** They are MAC-then-encrypt, and resisting Lucky13
  requires constant-time padding validation. JavaScript cannot promise constant time — JIT tiering
  and GC see to that — so shipping CBC would mean shipping a padding oracle in the name of
  compatibility. This applies to TLS 1.2's CBC suites exactly as it does to TLS 1.0/1.1.
- **TLS 1.0 / 1.1.** RC4 is broken and everything else there is CBC. Browsers have refused these
  since 2020. Note the distinction: a server that *also* supports 1.0/1.1 is fine, because we will
  negotiate 1.2 or 1.3 with it. Only a server that supports *nothing else* is out of reach.
- **RSA key transport.** No forward secrecy.
- **ChaCha20-Poly1305.** It buys nothing: a server can only pick a suite we offered, TLS 1.3
  mandates AES-128-GCM, and AES-GCM is universal in TLS 1.2 deployments. WebCrypto has no
  ChaCha20, so offering it would mean a `node:crypto` dependency for zero compatibility gain.
- **Client certificates (mTLS), session resumption, 0-RTT, renegotiation.** A `HelloRequest` is
  refused rather than honoured.
- **Certificate revocation (CRL / OCSP).** Checking revocation needs a network fetch mid-handshake;
  that is not implemented, and pretending otherwise would be worse than saying so.
- **Certificate policy processing** (`policyConstraints`, `inhibitAnyPolicy`). Because they are
  always critical, their presence causes a rejection rather than being mis-validated.
- **Name constraints beyond dNSName and iPAddress.** A *critical* constraint extension naming an
  unsupported type is rejected; a non-critical one is ignored, as RFC 5280 permits.
- **A public-suffix list for cookies.** Only the "no dot in the domain" guard is implemented, so
  `Domain=com` is refused but `Domain=co.uk` is not. Documented rather than faked.
- **IDNA.** Pass A-labels (punycode); a non-ASCII hostname is rejected with a message saying so.
- **`br` and `zstd` content encodings.** The runtime has `DecompressionStream` for gzip, deflate
  and deflate-raw only. The client therefore never advertises `br` — asking for it would return
  bytes that cannot be decoded.
- **HTTP/2 and HTTP/3.** ALPN offers exactly `http/1.1`; a server selecting anything else fails
  closed.

**Sockets cannot cross request contexts.** The pool is per-`Client` and per-invocation by design;
there is no cross-request connection cache, because the runtime does not permit one.

**Concurrency.** The platform allows six connections simultaneously awaiting response headers.
A crawler wanting more parallelism must pipeline within that limit.

## Cost on a live Worker

Every number here was measured on the Cloudflare edge with `wrangler tail`, through a real proxy,
grouped per isolate so that a first execution is never averaged together with a warm one. Workers
bill CPU time, not wall time, and the overwhelming majority of a request here is spent waiting on
the network, which is not billed.

### What a page costs

Fetching a size-controlled origin through a proxy, warm, medians over seven-plus rounds on one
isolate, gzip on the wire:

| Page size | One page, new connection | Each further page, same connection |
| --- | --- | --- |
| 1 KB | 11 ms | 2–3 ms |
| 16 KB | 11 ms | 3 ms |
| 64 KB | 11 ms | 2–4 ms |
| 256 KB | 7 ms | 3.4 ms |
| 1 MB | 11 ms | 6–12 ms |
| 4 MB | 31 ms | 21–35 ms |

A simple model fits every row to within the spread:

> **≈ 9.5 ms to open a connection + 2 ms per request + 5–8 ms per MB of body**

The ranges are real, not imprecision: absolute CPU on this platform varies by up to ~1.5×
between isolates and runs (the same sweep repeated lands on faster and slower machines), so the
row values are medians and the spread is what repeated same-isolate measurement actually shows.
The per-MB term was ~25 ms/MB before the decode and socket read paths were rebuilt around BYOB
reads — the old cost was per-chunk stream-boundary crossings, not bytes; see below.

The connection term recovered independently from each row lands between 5 and 11 ms, which agrees
with the 9–12 ms measured for a new connection by other means. Most of it is the TLS handshake and
certificate chain validation; almost none of it is parsing (see below).

**Reuse is the lever.** Thirty 16 KB pages from one host cost about 103 ms down one connection and
about 300 ms opening thirty. That gap is the entire argument for holding a `Client` rather than
calling `createFetch` per request, and it widens as pages get smaller.

### What a fresh isolate costs

V8 tiers up per function per isolate, so the first executions of the TLS and HTTP paths run
interpreted. The excess decays over roughly six requests:

| | First request | Excess over the warm floor, whole ramp |
| --- | --- | --- |
| Without `warmup()` | 46 ms | 61 ms (≈ 4.4 ms/request over an isolate's early life) |
| `warmup()` once | 22 ms | 40 ms (≈ 2.8 ms/request) |
| `warmup({ iterations: 5 })` | 16 ms | 15 ms (≈ 1.1 ms/request) |

Warming costs 10 ms of startup at one iteration and 22 ms at five, against a 1 s startup budget.
It does not lower the warm floor — the effect is entirely on the ramp.

### Where the cost is, and is not

Chain validation is signature verification, not parsing. Parsing a whole chain is ~158 µs; a single
ECDSA P-384 verify is 665–816 µs, about 12× a P-256 verify and 27× an RSA-2048 verify. A typical
EC chain carries two P-384 links, so **an all-ECDSA chain validates in ~3.5 ms against ~0.8 ms for
an RSA one**. If you control the origin, its certificate's key type is worth a thought.

For small responses, decoding is dominated by constructing the `DecompressionStream`, not by the
bytes: ~2 ms for a 559-byte body, so for small JSON `decompress: false` can be cheaper than gzip.

For large bodies the per-byte cost is not really per byte — it is per stream-boundary crossing.
The runtime's `DecompressionStream` emits 4096-byte chunks and its sockets deliver reads of at
most 4096 bytes, and every chunk that crosses between the runtime and JS costs tens of
microseconds regardless of size. Both hot paths therefore drain their sources with BYOB reads
into 64 KiB views (a BYOB read hands over everything already buffered in one crossing, and
resolves partially filled the moment any byte exists, so streaming latency is unchanged). That
rebuild took the decode stage from ~28 ms to ~6 ms per MB of decompressed output — measured by
A/B-ing both implementations inside one isolate: 110 ms against 23 ms for the same 4 MB body.
What remains is close to floor: inflate itself (~2 ms/MB) plus materialising the body into a JS
string (~1.7 ms/MB), and that last term is the one cost the platform's own `fetch` also bills.

Importing the package is free. The 121 bundled anchors are base64 strings indexed by a hash of the
subject DN, and only the one anchor a chain lands on is ever decoded, so startup stays at ~2 ms for
the 380 KB bundle (133 KB gzipped) and a request that imports but does not use the package costs
0 ms.

### Plan limits

On the paid plan the 30 s default CPU limit is not the binding constraint — that is roughly 3 000
connections or 1 GB of body in one invocation, and the limit of six connections simultaneously
awaiting response headers binds long before CPU does.

The free plan documents 10 ms of CPU per invocation, which a new connection (10–15 ms) sits at or
above and a pooled request (2–4 ms) fits inside comfortably. In practice the runtime tolerates
occasional overage and carries unused budget forward, so single requests well past 10 ms do
complete — measured, several hundred milliseconds completed and the runtime terminated a request
around 2 s with `exceededCpu`. **That is not the same as showing sustained use above 10 ms is
viable**, because those probes were low-rate and bursty, exactly the shape such an allowance
forgives. If you intend to run this on the free plan, reuse connections and measure your own
sustained average rather than trusting either the documented number or the burst behaviour.

## Runtime requirements

WebCrypto (X25519, ECDH P-256/384/521, ECDSA, RSA-PSS, RSASSA-PKCS1, HKDF, HMAC, AES-GCM),
WHATWG Streams including BYOB readers, `TextEncoder`/`TextDecoder`, `DecompressionStream`, `URL`,
`Headers`, `Request`, `Response`, `AbortSignal`, `btoa`. All present on workerd, Node ≥ 20, Deno
and Bun. The only runtime-specific piece is the `connect` function you supply.

## Testing

```bash
npm test          # 866 offline tests, hermetic, no network
npm run test:live # explicit; needs TUNNELFETCH_PROXY in the environment
```

The offline suite never touches the network and is enforced not to: a repo-hygiene suite fails the
build if any test file names a routable host, if `src/` imports from `node:`, if it contains a URL,
a vendor name, `Math.random`, or a `console.*` call, or if any module under `src/` has no test.

Every byte-consuming parser is run through `underAllChunkings`, which feeds identical bytes whole,
one byte at a time, and at several pseudo-random split points, and asserts all runs agree. A parser
that behaves differently under different chunk shapes has a bug that only appears under real
network fragmentation, which is the kind of bug that cannot be reproduced from a report.

The TLS key schedule and record layer are pinned byte-for-byte against **RFC 8448** "Example
Handshake Traces for TLS 1.3": the AEAD reproduces the RFC's exact ciphertext records, and the
record layer replays the RFC's full wire images in both directions. Both TLS drivers are tested
against independently written test servers — the 1.2 server is built on `node:crypto` rather than
on this package's own primitives, so a client bug cannot be cancelled out by the same bug on the
server side.

`probe/` holds a reproducible capability probe that emits machine-readable JSON, and
`probe/results/` the measurements this design rests on. `live/` is the edge interop rig.

Credentials are read from the environment only. The live suite fails loudly when it is not
configured rather than skipping: a green tick that means "we did not check" is worse than a red one.

## Attribution

Trust anchors are derived from the Mozilla / Common CA Database (CCADB), used under
CDLA-Permissive-2.0. Regenerate with `npm run roots:refresh`; the generated module records its
source, retrieval date, upstream SHA-256 and anchor count, because a stale root store is a silent
availability bug that surfaces months later as "TLS randomly fails".

[`jawj/subtls`](https://github.com/jawj/subtls) (MIT) is a valuable proof-of-concept demonstration
that TLS 1.3 over WebCrypto is workable on this class of runtime, and was read as a reference.

## License

MIT.
