# tunnelfetch

[English](README.md) · [简体中文](README.zh-CN.md)

[![CI](https://github.com/latentharbor/tunnelfetch/actions/workflows/ci.yml/badge.svg)](https://github.com/latentharbor/tunnelfetch/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/tunnelfetch)](https://www.npmjs.com/package/tunnelfetch)
[![license](https://img.shields.io/npm/l/tunnelfetch)](LICENSE)


A `fetch`-shaped HTTP client that can route through an HTTP CONNECT, HTTPS, or SOCKS5 proxy on
runtimes that expose only raw TCP — principally Cloudflare Workers (`workerd`).

Zero dependencies. ESM. No build step. No `node:` imports anywhere in `src/`.

> **Maturity.** This is a new implementation, not a battle-tested one. It implements TLS 1.2/1.3 and
> certificate validation in userland — a category where good tests are necessary and not sufficient.
> It has over 1100 hermetic tests, RFC vectors, byte-by-byte fragmentation, live edge interop, seeded
> fuzzing of every peer-facing parser, and 95% line coverage. It has **not** had an external
> security audit. Treat it as a high-quality implementation worth trying, not as something proven
> in production. Please report anything you find — see [SECURITY.md](SECURITY.md).

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
TLS 1.3 (`0x0304`), `TLS_AES_128_GCM_SHA256`, X25519, ALPN negotiating `h2` or `http/1.1`, HTTP/2
and chunked and content-length framing, gzip decoded, chains validated against 121 bundled CCADB
roots.

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

The jar is deliberately minimal — it does RFC 6265 domain and path matching, `Secure`, host-only
cookies, expiry and `Max-Age`, and nothing else. It does enforce the **`__Host-` and `__Secure-`
name prefixes**, because those are not a convenience: the name is the server's claim that the
cookie was set with particular attributes, and a client that ignores the claim silently removes a
protection the server is relying on. A `Set-Cookie` that breaks its own prefix is refused whole,
never repaired — repairing it would manufacture exactly the proof the server must not get.

Prefix matching is case-**in**sensitive, which is a MUST in RFC 6265bis §5.4 and not an obvious
choice: servers routinely compare cookie names case-insensitively, so a client matching
case-sensitively will store `__SeCuRe-SID` without applying any of the rules and the server cannot
tell it from the real one. Matching case-sensitively is CVE-2024-5699.

Two related rules of §5.7 are **not** implemented, and are worth knowing if you rely on the jar for
security: "Leave Secure Cookies Alone" (step 16), so a plain-named `Secure` cookie set over https
can still be overwritten from http, and the 4096-octet name-plus-value cap (step 4).

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
into unbilled ones and is free money. Where startup CPU *is* billed — Cloudflare's dynamic Worker
loading, for instance — it is not free but is usually still worth it: the startup cost is paid once
per isolate and amortises over every request that isolate serves, so it pays for itself past about
**7 requests per isolate** and loses below that. It also costs real wall time at isolate start,
which matters if your startup budget is already tight. A library should not make that choice for
its consumer.

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

### `br`, `zstd`, and other codings

`gzip` and `deflate` are built in because the runtime decompresses them natively. Anything else is
pluggable: give `decoders` a function per coding and it is appended to `Accept-Encoding` and applied
to matching responses. Registering is what makes advertising honest — asking for a coding you cannot
read turns every such response into garbage, so the two move together and cannot drift.

```js
import { Client } from 'tunnelfetch';
import { connect } from 'cloudflare:sockets';
import { BrotliDecStream, BrotliStreamResultCode, initSync } from 'brotli-dec-wasm/web';
import wasm from 'brotli-dec-wasm/web/bg.wasm';

// Module scope, so instantiation lands in isolate startup, which this runtime does not bill.
// Measured on the edge: it costs nothing detectable (12 ms startup with it, 12 ms without).
initSync({ module: wasm });

const brotli = (stream) => {
  const dec = new BrotliDecStream();
  return stream.pipeThrough(new TransformStream({
    transform(chunk, c) {
      let r = dec.dec(chunk, 1 << 20);
      if (r.buf.length) c.enqueue(r.buf);
      while (r.code === BrotliStreamResultCode.NeedsMoreOutput) {
        r = dec.dec(new Uint8Array(0), 1 << 20);
        if (r.buf.length) c.enqueue(r.buf);
      }
    },
  }));
};

const client = new Client({ connect, proxy, decoders: { br: brotli } });
// Now sends `Accept-Encoding: gzip, deflate, br` and decodes `Content-Encoding: br`.
```

Order is registration order after the built-ins, so `{ br, zstd }` produces exactly the
`gzip, deflate, br, zstd` a Chrome sends — which is the actual reason to do this. This client
presents curl's TLS and HTTP/2 fingerprints by default, and `gzip, deflate` is what curl sends, so
the default is already consistent. It stops being consistent the moment you dress the handshake up
as a browser and leave the header behind.

It is not a saving. Measured on the edge, decoding the same 256 KB page to the same bytes, **all
through the same `ReadableStream -> ReadableStream` shape a `decoders` entry actually has**:

| Implementation | Algorithm | ms/MB | vs native gzip |
|---|---|---|---|
| `DecompressionStream` — the runtime's own C++ | inflate | **2.75** | 1.0x |
| WASM zstd (bundled, decode-only build of facebook/zstd) | zstd | 5.5 | 2.0x |
| WASM brotli (bundled, decode-only build of google/brotli) | brotli | 7.0 | 2.5x |
| WASM brotli (`brotli-dec-wasm` from npm) | brotli | 10.5 | 3.8x |
| JS inflate (`fflate` / `pako`) | inflate | 7.5 / 8.2 | 2.7x / 3.0x |
| JS brotli (`brotli`) | brotli | 19.7 | 7.2x |

An earlier version of this table said 4.7 ms/MB for `brotli-dec-wasm`, and that figure was wrong in
a way worth naming: it was measured by driving the decoder in a bare loop, while the README's own
example wires it up as a `decoders` entry, which is a stream. The same decoder costs **4.7 in a
loop and 10.5 behind a `TransformStream` — the stream machinery is 121% on top**, and the number
that belongs here is the one matching the documented usage. Measured and used must be the same
thing.

Two things still fall out, both worth knowing before reaching for WebAssembly anywhere else in a
Worker. **WASM is roughly 3x faster than JavaScript at the same algorithm** (brotli: 7.0 against
19.7) — so if a coding has no native path, WASM is the right way to add one. And **native is about
3x faster than JavaScript** (inflate: 2.75 against 7.5–8.2), while WASM lands 2–2.5x above native —
so where a native path already exists, nothing in userland improves on it. That is why `gzip` and
`deflate` are not overridable: replacing them could only ever be slower, and doing it silently is
the kind of quiet downgrade this package refuses everywhere else.

Brotli itself lands at 2.5x native inflate. That gap is the price of the coding, and the wire bytes
it saves do not pay it back — see [What this cannot do](#what-this-cannot-do-and-why). Decoder names
are validated as HTTP tokens, a decoder that throws fails the body closed rather than truncating it,
and an unregistered coding is still refused.

### The Chrome identity, in one import

```js
import { Client } from 'tunnelfetch';
import { chrome } from 'tunnelfetch/profile/chrome';

const client = new Client({ profile: chrome, connect, proxy, decoders: { br, zstd } });
```

The subpath carries the two primitives this runtime has no native path for — ML-KEM-768 for the
`X25519MLKEM768` key exchange and ChaCha20-Poly1305 for the record layer, both compiled to
freestanding WASM and both with known-answer tests in this repository. **Importing it is the
opt-in:** a bundler pulls them in only for code on this path, so the default identity carries none
of it.

Nothing else to supply: `br` and `zstd` are bundled too. They were held back at first, on the
grounds that there is no single right implementation — measurement dissolved that. A decode-only
build of the reference C is 1.5x faster than the npm alternative at the interface this package
actually uses, and half the size.

The whole cost of the four blobs is **3 ms once per isolate** — module-scope instantiation lands in
startup, which this runtime does not bill, so only the first request in a fresh isolate sees
anything and every request after it sees nothing. Measured against an otherwise identical
deployment that imports none of them:

| | with all four WASM modules | importing none |
|---|---|---|
| first request in a fresh isolate | 3 ms | 0 ms |
| requests 2–5 | 0 ms | 0 ms |
| request 6 onward | 0 ms | 0 ms |

Per-byte decoding is separate and conditional: you pay it only when an origin actually serves `br`
or `zstd`. See the codec table above.

### Customising an identity

Three levels, in the order you are likely to want them.

**Override one field.** `tls` merges per-field, so naming one thing keeps the rest of the profile:

```js
new Client({ profile: chrome, tls: { alpn: ['http/1.1'] } });
// alpn replaced; extensionOrder, grease, ciphers, groups all still Chrome's
```

Top-level fields (`headerOrder`, `http2Settings`, `http2PseudoHeaderOrder`, `http2HpackIndexing`)
replace wholesale, since a half-merged order is not an order.

**Derive a profile.** A profile is a plain frozen object, so spreading one is the whole mechanism —
no API to learn. This is the right way to change a User-Agent for every request:

```js
const mine = { ...chrome, name: 'chrome+mine',
               headers: [['User-Agent', 'mybot/1.0'], ['X-Tag', 'a']] };
new Client({ profile: mine, connect, proxy });
```

**Write one from scratch.** Nothing about the built-ins is privileged:

```js
const firefox = {
  name: 'my-firefox/130',
  tls: { alpn: ['h2', 'http/1.1'], ciphers: [0x1302, 0x1301],
         extensionOrder: [0, 10, 11, 13, 16, 23, 43, 45, 51, 0xff01], grease: false },
  headerOrder: ['host', 'user-agent', 'accept', 'accept-language', 'accept-encoding', '*', 'connection'],
  headers: [['User-Agent', 'Mozilla/5.0 Firefox/130.0']],
  http2Settings: [[1, 65536], [4, 131072], [5, 16384]],
  http2PseudoHeaderOrder: [':method', ':path', ':authority', ':scheme'],
  requires: [],
};
```

`requires` applies to your profile exactly as it does to the built-ins: name a capability the
Client has not been given and construction is refused, naming what is missing. A custom identity
gets the same guard against advertising what it cannot perform.

Profile `headers` are defaults — a per-request header of the same name wins — while explicit
`Client` options win over the profile. So the precedence runs: per-request, then Client options,
then the profile.

Verified end to end, not merely constructed:

| Origin | | TLS | Group | HTTP |
|---|---|---|---|---|
| `blog.cloudflare.com` | 200 | 1.3 | `0x11ec` X25519MLKEM768 | h2 |
| `www.shopify.com` | 200 | 1.3 | `0x11ec` X25519MLKEM768 | h2 |

### HTTP/2 — access, not speed

The client offers `h2` and `http/1.1` in ALPN by default and speaks whichever the server selects.
There is no separate API: a request that lands on an `h2` connection just reports `httpVersion: '2'`
in its `tunnelfetch` detail. Set `http2: false` to offer only `http/1.1`.

**The reason to implement HTTP/2 here is access, not performance, and on this runtime it costs
_more_ CPU than HTTP/1.1, not less.** Two things make that true. HPACK is header compression work
that HTTP/1.1 simply does not do; and multiplexing buys latency a Worker handler — which usually
issues one request and awaits it — cannot spend. So if you are reaching for HTTP/2 expecting a
speed-up on a CPU-metered platform, it is the wrong lever. What it buys is reaching sites that treat
HTTP/1.1 as a bot signal. That was measured, not assumed — one proxy, one browser `User-Agent`, one
set of headers, changing only the protocol:

```
stackoverflow.com  --http1.1 -> 403 "Just a moment..."  (Cloudflare challenge, cf-mitigated: challenge)
                   --http2   -> 200, 291 KB of real content
```

Across a ten-site sample HTTP/2 changed the outcome on exactly one: four sites were blocked
identically on both protocols and five were fine either way. So the honest expectation is "unlocks
roughly one site in ten", not "solves bot detection".

**And that expectation has a shelf life.** Re-measured the same day this landed, from the same
proxies, that site now challenges HTTP/2 as well — `curl --http2` is refused there exactly as this
package is, while the same proxies still fetch other sites normally. So the capability is real and
correct (ALPN negotiates `h2`, and this client is treated identically to curl's), but the specific
access it was built to win did not survive a day. Bot detection is adversarial and moves; a
protocol is a window, not a property. Do not adopt HTTP/2 here on the strength of one site's
behaviour — measure your own targets, and expect the answer to change. Our TLS fingerprint and curl's produced
identical outcomes on every reachable host in that sample, so JA3-style TLS shaping is not what
gates access here — but curl's **HTTP/2** fingerprint passed where HTTP/1.1 was challenged. So the
`SETTINGS` frame values, the initial window sizes, the connection `WINDOW_UPDATE`, and the
pseudo-header order are matched byte-for-byte to curl (nghttp2 1.69.0), captured off the wire.
This is empirical: a naïve h2 fingerprint can fail exactly where curl's succeeds, which would waste
the whole exercise.

### Fingerprints

Both halves are matched to **curl 8.21.0 / OpenSSL 3.6.3** and both are fully configurable. The TLS
backend matters more than the curl version — the same curl built against SecureTransport produces a
completely different ClientHello — so the reference is captured off the wire, not recalled, and
pinned in `test/tls/fingerprint.test.js` and `test/http2/fingerprint.test.js`.

| Layer | Default | Configure with |
|---|---|---|
| ClientHello extension **order** | curl's, exactly, for every extension both send | `tls.extensionOrder` |
| Cipher suites | the AEAD suites this package implements, in curl's relative order | `tls.ciphers` |
| Supported groups | `x25519, secp256r1, secp384r1, secp521r1` | `tls.groups` |
| Signature algorithms | ECDSA and RSA-PSS/PKCS#1 over SHA-256/384/512 | `tls.sigSchemes` |
| ALPN | `h2, http/1.1` | `tls.alpn` |
| HTTP/2 `SETTINGS` ids **and order** | curl's: `MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, ENABLE_PUSH`. The **values** differ by default — see below | `http2Settings` |
| h2 preface, `WINDOW_UPDATE`, pseudo-header order | curl's, byte-for-byte | `http2ConnectionWindow`, `http2PseudoHeaderOrder` |
| HPACK representation | curl's (`:path` without indexing, the rest incremental) | `http2HpackIndexing` |
| `Accept-Encoding` | `gzip, deflate` — curl's | `decoders` appends |

**The default `SETTINGS` values are this package's, not curl's, and that is a deliberate trade.**
`profiles.curl` carries curl 8.21.0's real `INITIAL_WINDOW_SIZE` of **64 KiB**, captured and pinned
in `test/tls/_captured-h2.js`. The connection default without a profile is **10 MiB**, which is what
curl 8.7.1 sent and what this package keeps: a 64 KiB stream window means one `WINDOW_UPDATE` per
32 KiB consumed instead of one per 5 MiB.

**Measured, on a 8.7 MB body over h2 against a real origin, both windows interleaved in one
isolate: the 64 KiB window costs about +1.4 ms of CPU per decompressed MB** — roughly **6–7%** on
top of the ~21.7 ms/MB this package spends moving a large body. That is the price of the accurate
fingerprint, and for most callers it is worth paying; if you are moving large bodies and do not need
to look like curl, set `http2Settings` yourself.

Two cautions on that number. The minimum-of-samples rule this document recommends elsewhere **fails
here**: with unequal sample counts and a lossy origin the minima moved between +2 ms and +13 ms
across sweeps, because the arm with more samples gets a lower minimum for free. The figure above is
p25 and median, which agreed with each other and with the arithmetic — 8.7 MB at a 32 KiB replenish
threshold is ~276 extra frames, and ~276 × ~47 µs is ~13 ms.

Until 1.6.2 the profile carried curl **8.7.1's** window while presenting curl **8.21.0's**
ClientHello: one named client, two source versions, and a split identity that only a capture could
find, because each half was individually true of some curl.

**`extensionOrder` arranges extensions; it cannot add them.** The builder filters to the extensions
it actually generated and sorts those, so an identity needing one this package does not build is not
reachable by ordering. Chromium sends five that it does not:

| | |
| --- | --- |
| `signed_certificate_timestamp` | 18 |
| `compress_certificate` | 27 |
| `session_ticket` | 35 |
| `application_settings` | 17613 |
| `encrypted_client_hello` | 65037 |

So `profiles.chrome` presents a Chromium cipher list, group list and GREASE placement over an
extension **set** that is curl's. A test reads that gap straight out of the committed Chromium
capture and fails if it changes, so it cannot drift quietly — but it is a real difference and a
JA3/JA4 hash sees it.

`tls.omitExtensions` is the subtractive counterpart, and `status_request` (5) is what it exists for:
that is the one extension this package sends which curl does not, so an identity matching a sample
without it had no way to drop it. Dropping it gives up OCSP stapling — the only revocation signal
this package consumes — so pairing it with `trust.revocation: 'require-staple'` is refused at
configuration time rather than left to fail every connection on a certificate that was never asked
to carry a staple.

`tls.extraExtensions` takes pre-encoded extensions and is the only way to close it. They are ordered
like any other and reproduced on a HelloRetryRequest retry, because a second hello that changed its
extension set would be both malformed (RFC 8446 §4.1.2) and a signal in itself. Encoding them
correctly is the caller's job; this package does not parse what it did not build.

**Every offered cipher must be one this package can perform — unless you say otherwise.**
`tls.ciphers` used to be taken verbatim, so a list containing a CBC or RSA-key-exchange suite put a
number on the wire that a server could select, after which the AEAD layer had nothing to build and
the connection died mid-handshake. Such a list is refused at configuration time by default, and an
explicit `TLS_CHACHA20_POLY1305_SHA256` with no injected implementation is refused rather than
silently dropped — quietly presenting a different fingerprint from the one you asked for is the
worst outcome available to a package like this one.

But refusing outright is the wrong default to have no escape from, because **the restriction is
itself a fingerprint**:

| | suites offered | performable here |
| --- | --- | --- |
| curl 8.21.0 | 30 | 7 |
| Chromium | 15 | 7 |

A hello restricted to what can be honoured carries a cipher list less than half the length of any
real client's, and list length and contents are exactly what a JA3 hash reads. `tls.allowUnperformableCiphers`
offers the accurate list. The trade is narrow: the first unperformable suite sits at index 5 of
curl's list and 7 of Chromium's, behind the TLS 1.3 suites, so a server with 1.3 available never
reaches one. If a server does select one the handshake fails, and the error names the option rather
than reading like a defect here.

Most of the gap is not a missing feature. Sixteen of curl's twenty-three are CBC — MAC-then-encrypt,
which cannot be implemented without a Lucky13 padding oracle in JavaScript — and two more are RSA key
exchange with no forward secrecy. Both are refusals this package intends to keep. The three that
*are* implementable are the TLS 1.2 ChaCha20-Poly1305 suites, and they are not implemented yet.

Extension order matters because JA3 and JA4 hash the extension list **in wire order**, so it is most
of what a fingerprinter reads. `pre_shared_key` is forced last whatever you ask for: RFC 8446
§4.2.11 defines the binder transcript as the hello truncated just before the binders, which is a
well-defined byte range only if nothing follows them.

**Where the default deliberately differs from curl**, and why it cannot simply be copied: a
ClientHello is an *offer*, and a server may take you up on any of it. Advertising what you cannot do
trades a fingerprint mismatch for a broken handshake, which is worse and fails silently.

| curl sends | This package | Why |
|---|---|---|
| 30 cipher suites, incl. ChaCha20, RSA key exchange and CBC | 6 AEAD suites, or 7 with ChaCha20 injected | RSA-kx and CBC are refused by design — a server selecting `TLS_RSA_WITH_AES_256_CBC_SHA` would get a dead connection. `TLS_CHACHA20_POLY1305_SHA256` is injectable via `ciphers: { chacha20 }`: WebCrypto has no ChaCha20 here, so an implementation is supplied rather than a `node:crypto` dependency taken |
| `X25519MLKEM768` group and a 1216-byte key share | offered only when injected | ML-KEM is not a WebCrypto primitive; supply it as `groups: { x25519mlkem768 }` (what `profiles.chrome` requires) and the group and its 1216-byte hybrid key share go on the wire |
| SHA-1 signature schemes | not offered | Refused deliberately |
| `encrypt_then_mac` | not sent | Applies only to CBC suites, which are not offered |
| `post_handshake_auth` | not sent | Invites a post-handshake `CertificateRequest`, which is not implemented |
| — | `status_request` | curl does not ask for a stapled OCSP response; this package must, because a staple is its only revocation signal |

ChaCha20-Poly1305 and X25519MLKEM768 are reachable by **injection**: an implementation of each is
supplied through `ciphers` / `groups`, which is precisely what `profiles.chrome` requires, and
neither is offered unless one is — a suite or group advertised but not performable is a dead
connection if a server takes it. RSA key exchange and CBC suites stay refused on purpose;
`tls.ciphers` and `tls.groups` will let you offer them anyway, and the handshake will then fail if a
server picks one, which is yours to own.

A test asserts this delta is exactly the list above, so gaining one of these capabilities without
updating the table fails the build.

Everything an HTTP/1.1 body has, an HTTP/2 body keeps: streaming (SSE works unchanged), trailers,
gzip decoding, and the idle deadline wrapping the raw body before any decode. The one thing that is
structurally different is under the hood — a single h2 connection multiplexes every concurrent
request to an origin rather than being checked out one request at a time. `install()`, redirects,
cookies, and `verify=` all behave identically.

```js
const client = new Client({ connect, proxy: env.PROXY_URL });
const res = await client.fetch('https://example.org/', {
  headers: { 'user-agent': 'Mozilla/5.0 (…) Chrome/140.0.0.0 Safari/537.36' },
});
res.tunnelfetch.httpVersion; // '2' if the server chose h2, '1.1' otherwise
```

## API

### `new Client(options)`

| Option | Default | Meaning |
| --- | --- | --- |
| `connect` | — | Socket factory. On Workers, the `connect` export of `cloudflare:sockets`. Required for anything the platform's `fetch` cannot serve. |
| `proxy` | `null` | URL string or object. `http:`, `https:`, `socks5:`, `socks5h:`. |
| `trust` | `{mode:'system'}` | Certificate policy; see below. |
| `tls` | `{}` | Handshake options (`alpn`, `groups`, `ciphers`, `offerGroups`). Here `groups`/`ciphers` are number lists — the suite and group ids to offer, in preference order. |
| `ciphers` | `{}` | Injected AEAD implementations by capability name: `{ chacha20 }` (a `seal`/`open` pair). WebCrypto has no ChaCha20 here, so `TLS_CHACHA20_POLY1305_SHA256` is offered only when this is supplied. Required by `profiles.chrome`. |
| `groups` | `{}` | Injected key-exchange implementations by capability name: `{ x25519mlkem768 }` (ML-KEM-768 `keygen`/`encapsulate`/`decapsulate`). ML-KEM is not a WebCrypto primitive, so the post-quantum hybrid group is offered only when this is supplied. Required by `profiles.chrome`. |
| `timeouts` | see below | `connectMs`, `handshakeMs`, `headersMs`, `idleMs`, `totalMs`. |
| `cookies` | `false` | Enable a per-Client cookie jar. |
| `maxRedirects` | `20` | |
| `maxBodyBytes` | **`32 MiB`** | Enforced from `Content-Length` before a byte is read, on the raw stream, and on the DECODED output — including a decoder you registered. `Infinity` opts out; see [the note on the default](#the-body-cap-has-a-default-now). |
| `decompress` | `true` | Decode `Content-Encoding` at all. gzip and deflate are built in. |
| `decoders` | `{}` | Extra codings, e.g. `{ br: fn }`. Each is added to `Accept-Encoding`. See [`br`, `zstd`](#br-zstd-and-other-codings). |
| `keepAlive` | `true` | |
| `http2` | `true` | Offer `h2` in ALPN and speak it if the server selects it. See [HTTP/2](#http2--access-not-speed). |
| `forceTunnel` | `false` | Never delegate to the platform's `fetch`. |
| `nativeFetch` | `globalThis.fetch` | Delegation target. |

`client.fetch(input, init)` takes and returns the platform's `Request`/`Response`. The response
carries a non-standard `tunnelfetch` property with `{proxied, proxy, tls, httpVersion, framing}`.

`client.close()` releases every pooled socket. A `Client` that is not closed leaks sockets for the
lifetime of the isolate.

#### The body cap has a default now

**`maxBodyBytes` defaulted to `Infinity` through 1.5.0. From 1.6.0 it is 32 MiB, and that is a
breaking change** — a download larger than 32 MiB now needs an explicit `maxBodyBytes`, compressed
or not, because this option bounds the wire body as well as the decoded one.

The reason is that "no limit" is not a freedom on a runtime with a hard memory ceiling; it is a way
to be killed by a peer. A 53-byte brotli body decoding to 32 MB is measured here, not hypothetical,
and the bundled `br`/`zstd` decoders self-limit at 256 MiB — **twice the 128 MB a Workers isolate
gets**, so that fallback cannot fire before the isolate is already dead. A client whose entire
purpose is fetching URLs you do not control should not ship "unbounded" as the setting you get for
not having read this table.

32 MiB is a quarter of the ceiling, so a body buffered to the cap by `.arrayBuffer()` still leaves
the isolate room to survive and report it, and it is two orders of magnitude above any page or API
response. If you are deliberately moving large files, say so:

```js
new Client({ connect, proxy, maxBodyBytes: Infinity });   // or any number you have thought about
```

The trade is deliberate: an unasked-for limit is discoverable the first time it bites, and names the
option in its error. An unasked-for OOM is neither.

#### The proxy sees a fingerprint too

`Proxy-Connection` is a pre-standard hop header that never reached a spec. The origin never sees it;
the proxy always does. Clients disagree — some send `keep-alive`, some `close`, some omit it — so for
anyone matching a client's behaviour *at the proxy* it is part of the fingerprint, and it used to be
hard-coded.

```js
new Client({ connect, proxy: { ...cfg, proxyConnection: 'close' } });  // or null to omit it
```

The default stays `keep-alive`, which avoids a class of proxy that closes the tunnel after one
request. Omitting the header is not the same as sending `close`.

### Trust — the `verify=` knob

```js
{ mode: 'system' }                                  // bundled CCADB roots (default)
{ mode: 'anchors', anchors: [pemOrDer, ...] }       // exactly these, nothing else
{ mode: 'pinned', pins: ['sha256/BASE64...'] }      // full validation plus an SPKI pin set
{ mode: 'custom', verify: async (chain, host) => {} } // your policy; throw to reject
{ mode: 'none', insecureAcceptAnyCertificate: true } // no verification at all
```

Revocation is checked via **stapled OCSP** (RFC 6960 over the TLS `status_request` extension):
every hello asks the server to staple, and a stapled response must parse strictly, match the
validated certificate's issuer and serial, carry a verified signature from the issuing CA or an
authorised responder, and be inside its freshness window — a verified `revoked` (or `unknown`)
always fails the connection. A *missing* staple is tolerated by default, because most servers do
not staple and hard-failing would break the majority of the web; callers whose peers do staple
can demand one:

```js
{ mode: 'system', revocation: 'require-staple' }    // absence becomes OCSP_REQUIRED
```

There is deliberately no value that ignores a revoked verdict.

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
HTTP/3 — which this package cannot — and reaches origins raw sockets are forbidden from dialling.

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
- **ChaCha20-Poly1305, unless injected.** WebCrypto has no ChaCha20 on this runtime, so it is not
  built in — taking a `node:crypto` dependency would cost the package its "web platform only"
  property. It is *injectable*, though: pass `ciphers: { chacha20 }` (a `seal`/`open` pair, e.g. a
  WASM build) and `TLS_CHACHA20_POLY1305_SHA256` is offered — in curl's captured position, second
  after AES-256-GCM — and used. Not built in because a server can only pick a suite we offered, TLS
  1.3 mandates AES-128-GCM, and AES-GCM is universal in TLS 1.2; the reason to add it is matching a
  browser that offers it (`profiles.chrome`), not compatibility. The post-quantum
  **X25519MLKEM768** group is injectable the same way — `groups: { x25519mlkem768 }` — for the same
  reason: ML-KEM is not a WebCrypto primitive here.
- **Client certificates (mTLS), 0-RTT, renegotiation.** A `HelloRequest` is refused rather than
  honoured. 0-RTT is a decision rather than an omission: early data can be replayed, so offering
  it would let an attacker who captured a POST replay it. (Session resumption itself *is*
  implemented — a ticket is kept per pool key and offered with `psk_dhe_ke`.)
- **Revocation fetching (CRL downloads, OCSP responder queries).** Both need network round trips
  mid-handshake, through the proxy, and an OCSP query tells the CA which origins you visit.
  Revocation *is* checked from a **stapled** OCSP response when the server sends one (see Trust
  above); what is not implemented, and not planned, is going to fetch what the server did not
  staple.
- **Certificate policy processing** (`policyConstraints`, `inhibitAnyPolicy`). Because they are
  always critical, their presence causes a rejection rather than being mis-validated.
- **Name constraints beyond dNSName and iPAddress.** A *critical* constraint extension naming an
  unsupported type is rejected; a non-critical one is ignored, as RFC 5280 permits.
- **A public-suffix list for cookies.** Only the "no dot in the domain" guard is implemented, so
  `Domain=com` is refused but `Domain=co.uk` is not. Documented rather than faked.
- **IDNA.** Pass A-labels (punycode); a non-ASCII hostname is rejected with a message saying so.
- **`br` and `zstd` in the default identity.** The runtime's `DecompressionStream` accepts gzip,
  deflate and deflate-raw only — measured, not assumed — so both come from WebAssembly, and the
  default entry point carries neither. Import
  [`tunnelfetch/profile/chrome`](#the-chrome-identity-in-one-import) and they arrive wired in, or
  register your own through [`decoders`](#br-zstd-and-other-codings). What the main entry will not
  do is pull ~140 KB of compiled C into every bundle for a coding most callers never meet.

  Leaving them off is safe rather than lossy: content negotiation means a server never sends what
  was not asked for, so a Brotli-serving origin simply returns gzip. What it costs is bandwidth —
  the same page measured 290 KB as gzip against 99 KB as `br` — and bandwidth is not what this
  platform bills. On CPU the trade runs the other way: brotli decodes at 2.5x native inflate, and
  harder compression is worse rather than better, because decompression work scales with the OUTPUT
  bytes. The reason to turn `br` on is matching a browser's `Accept-Encoding`, not saving CPU.

- **Streaming request bodies.** A request body is read fully into memory before the request is
  sent, because the framing has to be declared in a `Content-Length` this client can stand behind
  and because a body may have to be replayed on a redirect. Fine for the JSON an SDK sends; wrong
  for a large upload, and it means `duplex: 'half'` streaming uploads are not supported. Response
  bodies are streamed throughout and are never buffered on your behalf.
- **HTTP/3.** ALPN offers `h2` and `http/1.1` (see [HTTP/2](#http2--access-not-speed)); it does
  not offer `h3`, which is QUIC over UDP and unreachable from a runtime that exposes only raw TCP.
  A server selecting anything the client did not offer fails closed — there is no fallback-and-retry
  at any layer.
- **Server push, HTTP/2 priority, and h2c.** Push is disabled in our SETTINGS and a `PUSH_PROMISE`
  is a connection error; the RFC 9113 priority scheme is deprecated and PRIORITY frames are ignored;
  and h2 runs only over ALPN-negotiated TLS, never cleartext with prior knowledge.

**Sockets cannot cross request contexts.** The pool is per-`Client` and per-invocation by design;
there is no cross-request connection cache, because the runtime does not permit one.

**Concurrency.** The limit is six connections **per Worker invocation** simultaneously awaiting
response headers — not per Worker and not per account, so separate requests to your Worker each get
their own six. A connection stops occupying a slot the moment its response head arrives, so the
limit bounds how many handshakes can be in flight at once, not how many bodies can be downloading.
A crawler wanting more parallelism inside one invocation must pipeline within that limit.

## Cost on a live Worker

Every number here was measured on the Cloudflare edge with `wrangler tail`, through a real proxy,
grouped per isolate so that a first execution is never averaged together with a warm one. Workers
bill CPU time, not wall time, and the overwhelming majority of a request here is spent waiting on
the network, which is not billed.

### What a request costs

Fetching `sizeorigin/` through a proxy, gzip on the wire, medians of n>=5 with every size in one
sweep and one isolate. The method is stated because the last version of this table did not state
one precisely enough to reproduce: **a warm page is `(reuse=4 - reuse=1) / 3`**, the cost of pages
two through four down a connection that is already open, and the last column is the fresh-connection
number the same sweep produced.

| Body | Warm page | Per decompressed MB | First request on a new connection |
| --- | --- | --- | --- |
| 1 KB | **1.3 ms** | — | 8 ms |
| 16 KB | **2.3 ms** | 149 ms/MB | 9 ms |
| 64 KB | **6.0 ms** | 96 ms/MB | 13 ms |
| 256 KB | **14.3 ms** | 57 ms/MB | 28 ms |
| 1 MB | **36.3 ms** | 36 ms/MB | 59 ms |
| 4 MB | **102 ms** | 26 ms/MB | 135 ms |

The last column is not "warm page plus a handshake". At 4 MB it is 33 ms above the warm page while a
handshake costs single digits, because the *first* body through a connection also runs the decode
loop before V8 has tiered it up. Budget a new origin at that column, not at the first one.

**Re-measured August 2026, and the mid-sizes moved.** The 4 MB row reproduced almost exactly
(102 against a previously published 104); 64 KB through 1 MB came in 20-30% lower than the figures
this table used to carry. That is not the socket-view change two sections below — A/B-ing the old
and new view size in one isolate moved a warm 1 MB page by about 1 ms — so it is either day-to-day
variance beyond what a single sweep can see, or a difference in how the superseded table was taken.
The old numbers are not recoverable to check, which is the argument for stating the method here.

**Read the per-MB column before doing any arithmetic with this table.** It falls 5.7x from end to
end, so there is no such thing as a per-MB rate for this package. A least-squares line through the
16 KB and larger points is `6.30 + 24.30 x MB`, which predicts 6.33 ms for a 1 KB body against a
measured 1.3 — wrong by 4.9x. Any budget built on a single per-MB figure will be wrong at one end
or the other.

The reason is that V8 tiers up **inside a single request**. A 1 MB body runs the decode loop
interpreted for much of its length; a 4 MB body pays that once and runs the rest optimised.
`36.3 + 3 x 21.9 = 102` fits, so the steady-state cost is about **22 ms/MB with a ~36 ms entry fee
per request**. For a size not in the table, interpolate within it rather than extrapolating from a
rate.

The cold-start cost is a **total**, not something to add to a row above:

| First request in a fresh isolate | cost of that request | excess over the warm floor, whole ramp |
| --- | --- | --- |
| without `warmup()` | **46 ms** | 61 ms (≈ 4.4 ms/request over an isolate's early life) |
| `warmup()` once | 22 ms | 40 ms (≈ 2.8 ms/request) |
| `warmup({ iterations: 5 })` | **16 ms** | 15 ms (≈ 1.1 ms/request) |

Both figures used to appear in the table above as "+46 ms" and "+16 ms", which turned a total into
an increment and doubled the documented cold start. The `+` is refutable from the numbers alone: a
first request that cost 9.2 + 16 would carry 16 ms of excess by itself, which is more than the 15 ms
of excess the *whole* ramp contains. These were measured on a small body; a cold isolate's first
4 MB request has never been measured and is certainly worse, since far more of the decode loop runs
interpreted.

**These figures replace ones that were measured wrong, and the mistake is worth describing.** The
origin they came from tiled a 150-byte HTML fragment, which gzip compressed **220:1** — so a "1 MB
body" was four kilobytes on the wire, and every measurement taken against it priced decompression
while erasing the per-wire-byte cost of TLS records and streaming entirely. Real pages compress
around 4:1. The origin now tiles 154 KiB of real minified JavaScript, which lands at 2.76:1: gzip's
window is 32 KiB, so a repeat period that large does not compress away.

The correction is large. Body-heavy rows are **two to three times** what this table said through
1.4.0, and no amount of care about medians or minimums would have caught it, because the numbers
were internally consistent — they were answers to the wrong question.

That correction is the reason the table above now measures its fresh-connection column instead of
deriving one. Through 1.11.0 that column was the warm figure plus a flat 7.5 ms and a third column
was the warm figure plus 1.5 ms, which is why their deltas were identical to one decimal across a
4000x range in body size — a derived column cannot disagree with its source, so it cannot check it
either. Both are gone.

The connection term that falls out of the current sweep is **6–7 ms** (1 KB fresh 8 ms against a
1.3 ms warm page), consistent with the 7–10 ms this section used to advise treating it as, and still
not something to do arithmetic with: at 4 MB the gap between fresh and warm is 33 ms, and most of
that is V8 tiering rather than the handshake.

An independent check was once quoted here as agreement and is not: a real 3.6 MB file from a CDN
cost 142 ms where the model predicts about 94 ms. It was taken in a different sweep against a
different origin, so it does not refute the table either — it belongs here as a reminder that a
single cross-sweep reading cannot confirm or deny anything in this document.

Two further cautions. The 2.76:1 content is slightly *less* compressible than a typical page, so
these are mildly conservative rather than optimistic. And CPU on this platform varies by up to ~1.5×
between isolates, so the shape matters more than any single figure.

### What the optional switches cost

Everything above is the default identity: curl's fingerprint, gzip and deflate, no post-quantum, no
GREASE. Each switch below is off unless asked for, and the table is what asking costs. Measured on
the edge the same way as the rest — differencing two work counts, minimum of samples.

| Switch | Cost | Paid |
|---|---|---|
| `grease: true` | not measurable | a handful of extra bytes in one hello |
| `tls.extensionOrder: 'shuffle'` | not measurable | shuffling ~11 items, once per handshake |
| `headerOrder` | not measurable — the ordered list is *faster* than the platform `Headers` (1.6 µs against 3.8 µs) | per request |
| `groups: { x25519mlkem768 }` | **+0.15 ms** with the bundled WASM, **+1.35 ms** with a pure-JS ML-KEM | per **connection**, not per request — amortised across every request that reuses it |
| `ciphers: { chacha20 }` | **+2.95 ms/MB** (bundled WASM AEAD 4.89 against AES-GCM 1.95), and only if the server *selects* it | per byte. Servers with AES hardware generally prefer AES-GCM, so the usual cost is zero and the offer is what matters |
| `decoders: { br }` | **+4.2 ms/MB** over the native gzip path (7.0 against 2.75) | per byte, whenever an origin serves brotli |
| `decoders: { zstd }` | **+2.8 ms/MB** (5.5 against 2.75) | per byte, whenever an origin serves zstd |
| `profile: chrome` via `tunnelfetch/profile/chrome` | **+3 ms once per isolate** for four WASM modules, then the per-byte rows above as origins use them | |

**The socket read view moved in 1.12.0**, from 64 KiB to 16 KiB, alongside the proxy tunnel becoming
a byte stream. No API changed and `tls.pullBytes` still overrides it — but on a proxied connection
that override did nothing before 1.12.0, so anyone who had tuned it was tuning a value nothing read.
Both are covered below.

Two defaults moved in 1.4.0 and neither is visible in the table above them: matching curl's cipher
order means AES-256-GCM is negotiated where AES-128-GCM used to be, measured at **+4%** per MB
(1.50 against 1.45 ms/MB — hardware AES makes the extra rounds cheap), and the ordered header list
replaced the platform `Headers`, which is slightly *cheaper*. Both are inside the ±1.5× spread the
figures above already carry.

Bundle: importing `tunnelfetch/profile/chrome` adds **~22 KB gzipped** for the two WASM primitives.
Nothing else imports them, so a caller on the default identity carries none of it.

### What that costs in dollars

Workers Standard bills $5/month including 10 million requests and 30 million CPU milliseconds, then
$0.30 per additional million requests and $0.02 per additional million CPU milliseconds. Applying
the measurements above, with the charge split out so it is clear what is yours to change:

| Workload | CPU/request | 10M/mo | 1B/mo |
| --- | --- | --- | --- |
| Platform `fetch`, 16 KB — reference; it cannot use a proxy | 0.3 ms | $5.00 | $307.40 |
| Platform `fetch`, 4 MB — same reference, measured | 3.2 ms | $5.04 | $365.40 |
| Pooled connection, 16 KB pages | 2.3 ms | $5.00 | $347.40 |
| New connection per request, 16 KB | 9 ms | $6.20 | $481.40 |
| Pooled connection, 1 MB pages | 36.3 ms | $11.66 | $1,027.40 |
| New connection per request, 1 MB | 59 ms | $16.20 | $1,481.40 |
| Pooled connection, 4 MB pages | 102 ms | $24.80 | $2,341.40 |
| New connection per request, 4 MB | 135 ms | $31.40 | $3,001.40 |

`$5 + max(0, requests - 10M) x $0.30/M + max(0, cpu_ms - 30M) x $0.02/M`, and nothing else. The
CPU column is the warm-page and fresh-connection columns of the table above; any figure here that
does not fall out of that table is a bug in this README.

**The `max(0, ...)` is new.** The previous version of this table billed every request and every
CPU millisecond, ignoring the allowance the sentence above it describes — so it overstated the
10M/mo column by up to 70% ($8.70 where the bill is $5.00) while being within 0.2% at 1B, where
the allowance is a rounding error. The overstatement was against this package, not for it, which
is presumably why it survived several readings.

The reference row is given at two sizes because the platform's own `fetch` is **not flat** — it
scales at about 0.82 ms per decompressed MB, measured on a size ladder from one CDN so that only the
size changes. Quoting it as a single 0.3 ms and comparing that against a 4 MB row was a like-for-
unlike comparison, and it flattered this package's competition rather than this package.

These dollar figures follow the corrected CPU measurements above, so the body-heavy rows are **two
to three times** what this table said through 1.4.0. That correction is not a regression in the
package; it is the removal of an origin whose content compressed 220:1.

"Cold" carries the measured fresh-isolate ramp of +4.4 ms per request amortised; "warmed" is the
same workload with `warmup({ iterations: 5 })`, which brings it to +1.1 ms. The saving is $0.66/month
at ten million requests and $66/month at a billion, identical across every row because the ramp is a
property of the isolate rather than of the request. The reference rows carry no ramp: the platform's
`fetch` has no JavaScript protocol stack to tier up.

#### What each Chrome-identity option costs

The rows above are the default identity: gzip on the wire, AES-256-GCM, x25519. The Chrome row
bundles every change together, which is not much use for deciding. Priced one at a time against a
pooled 1 MB workload at a billion requests a month, warmed:

| Change from the baseline | CPU/request | 1B/mo | Δ | Paid when |
| --- | --- | --- | --- | --- |
| baseline — gzip, AES-256-GCM, x25519, warm | 36.3 ms | $1,027 | — | always |
| origin serves `br` instead of gzip | 40.5 ms | $1,111 | **+$84** | the origin chooses `br` |
| server selects ChaCha20-Poly1305 | 39.3 ms | $1,086 | **+$59** | the server picks it over AES |
| origin serves `zstd` instead of gzip | 39.1 ms | $1,083 | **+$56** | the origin chooses `zstd` |
| X25519MLKEM768, 1 request per connection | 59.2 ms | $1,484 | **+$3** | every handshake |
| X25519MLKEM768, 20 requests per connection | 36.3 ms | $1,028 | **+$0.15** | the same handshake, amortised |

The ML-KEM rows are measured against the **fresh-connection** 1 MB baseline of 59 ms ($1,481), not
against the warm one at the top; the Δ column reflects that, which is why it is $3 rather than the
$154 an earlier version showed. That $154 was the cost of not pooling, attributed to post-quantum
key exchange.

The last two rows are the same 0.15 ms of ML-KEM, and the difference between them is entirely
connection reuse — which is the point worth taking from this table. Post-quantum key exchange is
the cheapest thing here if you keep a `Client` alive and the most expensive if you do not, because
it is per **handshake** while everything else is per byte.

Three of the five are also **conditional and not yours to decide**. `br` and `zstd` cost nothing
until an origin chooses to serve them, and ChaCha20 costs nothing until a server prefers it over
AES-GCM — which servers with AES hardware generally do not. Offering them is what buys the
fingerprint; paying for them happens only when the other end takes you up on it.

The ChaCha20 figure is the **bundled WASM** AEAD measured against the WebCrypto AES-256-GCM it
replaces (4.89 against 1.95 ms/MB). An earlier version of this section quoted +2.0 ms/MB, which was
`node:crypto`'s ChaCha20 — a path this package does not use, because taking it would require
`nodejs_compat`.

Four things fall out of it.

**At ten million requests a month, small pages are free and big ones are not.** A pooled 16 KB
workload sits inside the base fee; a pooled 1 MB workload is $15/month. The included CPU works out
to 3.0 ms per request at that volume, which a 16 KB page fits into and a 1 MB page does not.

**At a billion, $297 of every row is the request charge**, identical across all of them and
unchangeable by anything this package does. Only the CPU is left, and there the largest lever is
not connection reuse — it is body size. Reuse saves $151/month on 1 MB pages; fetching 16 KB pages
instead of 1 MB ones saves $1,004.

**Body-heavy work is where the userland stack actually costs something.** Pooled and warmed on
16 KB pages it is 25% above the platform's own `fetch` — $385 against $307. On 1 MB pages it is
**3.8x** — $1,389 against $365 — because every byte is decrypted, reassembled and decompressed in
JavaScript, and the platform does all three in the runtime where none of it is billed. If your
workload is large bodies, that ratio is the number to plan around, not the 16 KB one.

That reference row is measured, not assumed, and it is not flat. Fetching real pages of different
sizes from the same Worker, marginal cost per request on a reused connection:

| Page | Size | Platform `fetch` | This package, proxied | Ratio |
| --- | --- | --- | --- | --- |
| `example.com` | 0.6 KB | 0.2 ms | 3.8 ms | 12.8× |
| `news.ycombinator.com` | 35 KB | 0.3 ms | 1.8 ms | 5.5× |
| `www.wikipedia.org` | 118 KB | 0.5 ms | 1.5 ms | 3.0× |
| `github.com` | 591 KB | 2.0 ms | 14.0 ms | 7.0× |

The platform's `fetch` scales with body size too — it is not a flat millisecond — because it still
has to materialise the body as a JS value, which is the one per-byte cost both clients pay. What it
does not pay for is TLS, HTTP framing and decompression, all of which happen in the runtime and are
never billed to the caller. These four rows are noisy: CPU time is reported at 1 ms granularity and
these are small numbers, so the ratios bounce between 3× and 13× and are not monotonic in size (the
118 KB page measured cheaper than the 35 KB one). The direction is solid; the individual ratios are
not worth quoting to one decimal place.

**`warmup()` is free on Standard and usually worth it elsewhere.** Its own cost is startup CPU,
which Workers Standard does not bill, so the $66/month the "warmed" columns save at a billion
requests is a pure saving.
Where startup CPU *is* billed — dynamic Worker loading, for instance — the 22 ms is charged once
per isolate and spread across the requests that isolate serves: $25/month at a billion requests and
the ~17.8 requests per isolate measured here, against $65 saved. It stops paying for itself below
about 7 requests per isolate.

### Where the cost is, and is not

Chain validation is signature verification, not parsing. Parsing a whole chain is ~158 µs; a single
ECDSA P-384 verify is 665–816 µs, about 12× a P-256 verify and 27× an RSA-2048 verify. A typical
EC chain carries two P-384 links, so **an all-ECDSA chain validates in ~3.5 ms against ~0.8 ms for
an RSA one**. If you control the origin, its certificate's key type is worth a thought.

For small responses, decoding is dominated by constructing the `DecompressionStream`, not by the
bytes: ~2 ms for a 559-byte body. That is a real fixed cost, but the advice this README used to
draw from it — that `decompress: false` can be cheaper for small JSON — **is backwards for anything
that is not tiny, and it was never measured against the alternative.**

Cost here scales with **wire** bytes, not decoded bytes, because every wire byte is decrypted,
reframed and moved across JS stream boundaries before the decompressor ever sees it. Measured on
the edge: receiving a 4 MB body **uncompressed** costs the same as receiving the 1.5 MB gzip of it
*and inflating that*. Turning compression off trades a decompression you would have paid for 2.7×
the bytes through the entire receive pipeline. **Leave compression on.** The fixed ~2 ms only wins
below roughly the size where a single wire read covers the whole body.

### When not to use this package

**If you can run Node, run Node — and then you do not need this package at all.** `undici` with a
`ProxyAgent` does the same job over `node:tls`, which verifies whatever hostname you name, in C, at
roughly a tenth of the CPU. This package exists because a V8 isolate cannot do that; it is not a
better way to do it.

The arithmetic is worth being blunt about. A billion 4 MB requests a month costs about **$2,341** of
Workers CPU. That workload is roughly 386 requests a second and 4.5 Gbps sustained — **three
dedicated boxes** at Hetzner-class pricing carry it for around **$600**. So for large bodies, buying
servers is about **four times cheaper**, and the gap widens with body size.

Two things flip that back:

* **Egress.** Workers does not bill bandwidth. If those bytes have to leave your own servers again,
  1.45 PB/month is free on an unmetered box and about **$130,000** on AWS. Price your transfer
  before pricing your CPU — it can dwarf everything above.
* **Body size.** Under roughly **128 KB** the per-request cost is small enough that Workers wins on
  price *and* gives you 300+ locations, no operations and no capacity planning. At 16 KB the same
  billion requests is **$375**.

So: small bodies at the edge is what this package is for. Large bodies through a proxy, from a
runtime that could have used native TLS, is the case where it is the wrong tool and the bill says so.

### Passing the body through instead of decoding it

If you are forwarding a response rather than reading it, `decompress: 'passthrough'` asks for gzip as
usual and hands back the **coded** bytes with their `Content-Encoding` and `Content-Length` intact,
so the next hop can relay them:

```js
new Client({ connect, proxy, decompress: 'passthrough' });
```

Measured end to end on a 4 MB body: **118 ms decoding against 82.5 ms passing through, 30% cheaper**,
with 2.76x fewer bytes on the wire at the same time.

**This only helps if you never need the plaintext.** If you parse, extract or transform the body, the
decode is work you owe — passthrough just moves it downstream, where you or your caller pays the same.
It is not a general optimisation. Note also that `decompress: false` is *not* a weaker version of
this: it also drops gzip from `Accept-Encoding`, so the origin sends plaintext and the wire grows
2.76x. It loses on both sides.

### Cost parity with the platform's `fetch` is not reachable, and here is the floor

Two independent investigations reached this separately, which is the main reason it is stated this
flatly.

`gz-native` — the runtime's own `DecompressionStream` inflating 1.5 MB of gzip into 4 MB, collected
natively, with **no JS drain and no receive stack whatsoever** — costs **16 ms**, reproduced across
five independent sweeps. The platform's entire 4 MB `fetch`, TLS and HTTP and inflate included,
costs about **3.6 ms**.

So the cheapest way this package could possibly turn that gzip into bytes is already **4.4× the
platform's whole request**, before one byte of TLS or HTTP/2 is touched. The asymmetry is not about
code quality: **Cloudflare bills the CPU of a `DecompressionStream` running in your isolate and does
not bill the equivalent gunzip inside its own `fetch`.** Nothing written in JavaScript goes below a
billed native floor.

The remaining ~30× is the JS-orchestrated record layer, HTTP/2 demultiplexing and stream pipeline —
roughly **80% of the per-request cost at 4 MB, against 20% for decode**. An earlier version of this
section put the emphasis on decoding; that was wrong, and it sent optimisation effort at the smaller
of the two. For which of those three layers the 80% belongs to, see "Which layer the receive path
actually spends its megabyte on" below — the answer is not the record layer.

What would close it is a primitive that does not exist: a `startTls` that verifies the **origin**
hostname rather than the `connect()` peer, which would let the platform's own `fetch` run inside the
tunnel. That is the missing piece this whole package exists to work around, and it is worth
understanding as a **capability gap in the runtime, not a performance bug here**.

For large bodies the per-byte cost is not really per byte — it is per stream-boundary crossing.
The runtime's `DecompressionStream` emits 4096-byte chunks and its sockets deliver reads of at
most 4096 bytes, and every chunk that crosses between the runtime and JS costs tens of
microseconds regardless of size — measured here at about **17 µs per crossing**, from a ladder
that collects the same 1 MB in 4 KiB chunks (6.0 ms/MB) through 256 KiB chunks (1.67 ms/MB).
Both hot paths therefore drain their sources with BYOB reads, which collect several of those
chunks into one crossing and resolve partially filled the moment any byte exists, so streaming
latency is unchanged. How many they collect is the transport's decision and not the view's — a
BYOB read never waits to fill — so a view sized far above what the transport actually hands over
buys nothing and costs the allocation. Measured over a 4 MB body: **37 KB average fill on a direct
socket, 8 KB through a proxy**.

The view they read into is **16 KiB, and the size was swept rather than assumed**. It matters more
than it looks. The input is pumped by a JS task on the same event loop as the puller, so the
decompressor usually holds only a chunk or two when a read arrives and the read comes back
partially filled — measured over a 1 MB body: 93 reads, *all 93 partial*, average fill 11.3 KiB.
A 64 KiB view therefore allocates 5.8 MB of throwaway buffer to carry 1 MB of data. Swept on the
edge, CPU per MB of decompressed output, all five interleaved inside one isolate:

| BYOB view | 4 KiB | 8 KiB | **16 KiB** | 32 KiB | 64 KiB |
|---|---|---|---|---|---|
| decode stage, ms/MB | 19.33 | 16.00 | **13.00** | 15.33 | 17.67 |

A clean U: too small pays per-read overhead, too large pays for allocation it never fills. The
64 KiB that used to sit here was chosen from a probe that fed the decompressor through a native
`pipeTo` — which runs ahead and *does* fill a 64 KiB view (16 reads, none partial). That is a
regime the shipped wiring never enters. The probe and the product disagreed and the probe was
believed. Correcting it cut the stage **31%**, 18.0 → 12.3 ms/MB, A/B-ed in one isolate.

What remains is **not** close to floor, and an earlier version of this section wrongly said it was.
Native inflate of the same content costs 4.3 ms/MB against the stage's 12.3, so roughly **8 ms/MB
is this package's own plumbing** — the JS input pump and the output wrapper.

Most of that has since been closed by the native `IdentityTransformStream` relay, **but only for
`maxBodyBytes: Infinity`**, and the default is 32 MiB. Re-measured on the edge, same op, same
fixture, same isolate, differenced between a 1 MB and a 4 MB body:

| `maxBodyBytes` | decode stage, ms per decoded MB |
|---|---|
| `Infinity` — native relay, no JS in the byte path | **4.3** |
| 32 MiB (the default) — pull-driven JS wrapper | **7.7** |

So the bomb guard costs **3.3 ms per decoded megabyte**, about 13 ms on a 4 MB body, and it is the
largest remaining item in the body path. That is not a bug — the cap is enforced by counting bytes
and counting requires seeing them in JS — but the size of it was not known before and it is worth
saying out loud rather than leaving inside a comment. The counting itself is free (7.00 with it,
7.33 without); it is the wrapper the counting forces that costs. If you are relaying bodies you
already bound some other way, `maxBodyBytes: Infinity` is worth 43% of this stage.

Importing the package is free. The 121 bundled anchors are base64 strings indexed by a hash of the
subject DN, and only the one anchor a chain lands on is ever decoded, so startup stays at ~2 ms for
the 380 KB bundle (133 KB gzipped) and a request that imports but does not use the package costs
0 ms.

### Which layer the receive path actually spends its megabyte on

Every figure above is measured **through a proxy, against a Cloudflare origin**, which is the shape
this package exists for and also the shape that makes a per-layer answer impossible: two variables
move at once. The `wire` ladder in `live/` removes both — one nginx origin that serves the same file
over `http` and `https`, `Range` requests fixing the wire volume exactly, and no proxy — so the
rungs differ by exactly one layer each.

Per megabyte of **wire** (not of decompressed body), differenced between a 1 MB and a 4 MB range on
a **single request**, so no per-request work is inside the division. Three independent sweeps, run
hours apart:

| rung | ms per wire MB | added by this layer |
|---|---|---|
| raw socket, BYOB reads, no TLS | 2.0 – 3.0 | — |
| + the TLS record layer | 4.7 – 6.7 | +2.7 – 4.3 |
| + HTTP/2 | 9.3 – 12.0 | **+4.7 – 6.0** |
| + the `Client`, decoding off | 13.3 – 16.0 | +2.3 – 4.0 |

The origin serves `.gz` files with no `Content-Encoding`, so nothing decodes on any rung and the
decode stage is not in this table — price it separately from the section above. The top rung runs
`maxBodyBytes: Infinity`, which also keeps the body cap out of the number.

The absolute values move about 30% between sweeps, which is the run-to-run variance this document
warns about everywhere else; what does not move is the ordering. **HTTP/2 demultiplexing was the
largest single layer in all three sweeps** — on its own it costs about as much per wire megabyte as
the socket and the entire TLS record layer beneath it cost together. (An earlier draft of this
paragraph said "more than", on two sweeps. The third one does not support that, and the claim it
does support is strong enough.)

Everything else in this document points the other way — "42 ms of a 106 ms 4 MB request is socket
reads and record decryption" is the figure the `pullBytes` sweep left behind, and it is what sent
the last two rounds of optimisation at the record layer. That figure is not wrong for the path it
was taken on; it just never separated the socket from the parsing, and the separation is where the
answer was.

### A knob that was never connected on the path this package exists for

Running the same ladder **with** a proxy turned up the reason those earlier figures were so much
larger, and it was not the network.

`openTunnel` finishes a CONNECT (or SOCKS5) handshake holding a buffered reader, because the peer
may have sent tunnel payload in the same chunk as the reply, and it handed that onward wrapped in
`new ReadableStream({ pull })`. Correct, and a **plain** stream rather than a byte stream. The TLS
record layer asks for a BYOB reader and quietly falls back to a default one when it cannot have it,
so *every proxied connection* lost BYOB reads — and with them `tls.pullBytes`, whose only job is to
size them.

Same origin, 1 MB through the record layer, n=15 in one isolate, before the fix:

| | `pullBytes: 16 KiB` | `pullBytes: 1 MiB` |
|---|---|---|
| direct | min 25, p50 31 | min 73, p50 90 |
| **proxied** | min 95, p50 111 | min 101, p50 121 |

**2.9× on a direct socket and 6% through a proxy** — the knob was not being read. Which also means
the sweep that chose the old 64 KiB default, captioned "against a real proxied socket", was four
samples of one configuration; the clean U it reported was run-to-run noise.

`src/proxy/tunnel.js` makes the tunnel a byte stream and, once the handshake's leftovers are
drained, hands the caller's own view straight to the socket — so a read through a tunnel costs what
a read without one costs. With the knob reaching the code, the sweep is worth having:

| ms, 1 MB at the record layer, p50 | 8 KiB | **16 KiB** | 32 KiB | 64 KiB | 256 KiB |
|---|---|---|---|---|---|
| direct | 21 | 20 | 18 | 22 | 40 |
| proxy A | 51 | 61 | 61 | 89 | 152 |
| proxy B | 68 | 74 | — | 102 | — |

Monotonic on both proxies, shallow on the direct path, and the mechanism is the average-fill figure
above: too *large* is what costs, because the view is a ceiling that a BYOB read never waits to
reach. The default is now **16 KiB**, which is within ~20% of the best column on all three paths
where 64 KiB was up to 45% off, and allocates a quarter as much.

End to end through the real `Client` and a proxy, n=13, 16 KiB against the old 64 KiB: **63 against
78 ms** for 1 MB and **145 against 164 ms** for 4 MB on the median, and within noise on the minimum
at 4 MB. Smaller than the record-layer sweep alone suggests, because HTTP/2 and the client plumbing
above it do not scale with the view — but nothing measured anywhere favours the old value.

This is also a caution about the instrument rather than only about the code. The first attempt at
the end-to-end A/B reported the two view sizes agreeing to the millisecond, which read as "the
change does nothing"; the rig was not threading `pullBytes` into the `Client` rung at all, so both
columns were the same configuration. Two columns agreeing *exactly* is not a null result, it is a
wiring bug.

The record layer's share is now small enough to break down: of the 2.7–4.3 ms/MB it adds, WebCrypto
AES-256-GCM over 16 KiB records is **1.67 ms/MB**, so the JavaScript record parsing itself is
somewhere around **1–3 ms/MB**. That number closes a direction rather than opening one — see below.

The origin here sends 8 KiB DATA frames, so HTTP/2's share works out to roughly 35 µs per frame,
which is the same order as the ~25–30 µs per stream-boundary crossing measured elsewhere in this
document. It is not concentrated in any one call: coalescing queued DATA payloads into one enqueue
was implemented and measured, and it is not the answer. See "Three optimisations that measured as
nothing", below.

**And now the open question this ladder raises, stated rather than buried.** The whole stack here —
socket, TLS, HTTP/2, `Client` — comes to 13–16 ms per wire megabyte. The proxied figure for the
**record layer alone** is 38.5 ms for a 4 MB body, and that body is about 1.45 MB on the wire, so
roughly 27 ms per wire megabyte for one rung. Two to five times the whole direct-socket stack, for
a fraction of it.

Something in the proxied path costs several times what the same code costs on a direct socket, and
the candidates have not been separated: the proxy adds a second TCP hop whose delivery pattern this
package does not control, and the Cloudflare origin used there sizes its TLS records dynamically and
chunks a gzip it generates on the fly. Both would raise the per-record and per-crossing counts
without any code being slower.

**Every dollar figure in this document is derived from the proxied path**, so none of them are
invalidated by the ladder — they measure what a real request costs, which is what a bill is made of.
But they should not be read as measuring *this package's code*, and until the proxied path is
decomposed the same way, "where the cost is" has an answer only for the direct one. Running the
`wire` ladder against a proxy is the missing experiment; it needs credentials the rig takes as an
`x-proxy` header and nothing else.

### Moving TLS into WebAssembly: measured, and closed

The idea was to put record framing and buffer management in Wasm and leave the AEAD in JavaScript,
where `crypto.subtle` reaches AES-NI. The ladder above closes it, and not by finding Wasm slow —
**by bounding the prize**.

Everything a Wasm record layer could replace is the JavaScript record parsing, and that is roughly
**1–3 ms per wire megabyte** out of a 13–16 ms/MB receive path — at best a fifth of it, and the
smallest of the four rungs. The socket underneath is not something Wasm can make faster. The AEAD
would have to cross back to `crypto.subtle` regardless, because a software AES inside Wasm has no
AES-NI to reach, and at 1.67 ms/MB the AEAD is a large share of the rung being attacked. HTTP/2 and
the `Client`, which together cost two to three times as much as the whole TLS rung, are untouched
by any of it.

So the ceiling on the whole exercise is one to three milliseconds per megabyte, in exchange for
reimplementing TLS record framing in another language and re-deriving in Rust every byte of the
ClientHello-ordering and cipher-offer work this package exists for. Measured cost of the boundary
does not even enter into it.

Two things the measurements *do* settle, neither of which changes that:

- The per-crossing cost does not scale with crossings at TLS granularity: splitting the same
  transfer into 256 crossings of 16 KiB measured identically to one crossing of 4 MB. Whatever a
  Wasm design cost, it would not be the number of times it crossed.
- Getting a megabyte into linear memory and walking record-shaped headers over it is **cheap** — so
  cheap that the loop building the test fixture dominates the same measurement, which is why no
  single number for it is quoted here. Wasm is not the problem. There is just nothing on this path
  for it to win.

### Emscripten is not the problem people say it is

Cloudflare's Kitesurf post warns that with "Emscripten (for example) and its many layers of mocked
dependencies, the compiled binary can get bulky and slow", which is a claim about a toolchain and
cheap to check. `live/wasm/build.sh` builds the same three functions three ways — all `no_std` /
freestanding, all importing nothing, all producing bit-identical output on the same input — and then
runs the same comparison on a **real** primitive: the exact C this package already ships as its
ChaCha20-Poly1305, recompiled by Emscripten.

| | module | record walk, 4 MB | ChaCha20-Poly1305 seal |
|---|---|---|---|
| C, `emcc -O3 -sSTANDALONE_WASM` | **460 B** | 8 ms | **5.00 ms/MB** |
| Rust, `wasm32-unknown-unknown`, `no_std` | 632 B | 8 ms | — |
| C, `clang --target=wasm32 -nostdlib` + `rust-lld` | 647 B | 8 ms | — |
| C, wasi-sdk 25 `-nostdlib` — what ships | 8839 B | — | 5.67 ms/MB |
| WebCrypto AES-256-GCM, for scale | — | — | 1.67 ms/MB |

Emscripten produced the **smallest** module of the three, and the record walk came back at the same
millisecond for all three — that column is not a tie broken by rounding, it is three readings that
never separated across eight interleaved rounds. On the cipher Emscripten came out slightly ahead of
the wasi-sdk build this package ships, which is inside the noise and not a reason to add a second
toolchain to the build.

The warning is about what you compile, not what compiles it: drag in a libc, a filesystem shim or a
`main()` and Emscripten will emulate all of it, and the 8839-byte wasi-sdk row above is itself mostly
libsodium rather than toolchain. But `-sSTANDALONE_WASM --no-entry` over code that calls nothing
emits what LLVM would emit anyway. The shipped ChaCha20 stays on wasi-sdk; there is nothing here
worth a build dependency.

### Three optimisations that measured as nothing

Recorded because each looked obviously right, and because what killed two of them was a counter
disagreeing with a stopwatch. All three were implemented, measured on the edge, and reverted; none
of them is in `src/`.

**Recycling the BYOB pull buffer.** `ByteReader` allocates a fresh view for every pull, so the
`pullBytes` U-curve's right arm is allocation, not boundary crossings. Reusing one store and copying
the fill out removes that arm completely — at `pullBytes: 1 MiB`, 89 ms → 20 ms for 4 MB. It is also
**a wash at the then-default 64 KiB** (21 against 23) and *worse* below it, because the copy-out
stops paying for itself. Since the right answer turned out to be a *smaller* view rather than a
cheaper large one (see below), making large views cheap buys nothing, and the change was dropped.

**A native `pipeTo` for the decode stage's input.** The output side of `decompressionStage` already
avoids JavaScript entirely on the uncapped path; the input side is still a JS loop reading the source
and writing each chunk into the decompressor. Handing the source to `pipeTo` once the 2-byte deflate
sniff is done removes that loop — and measured identically at 64 KiB and 16 KiB input chunks, ~10%
better only at 4 KiB. Not worth the change: it moves the source's cancellation from a reader that
can be cancelled directly to a pipe that can only be aborted through a signal, which is a real
teardown-semantics change on the body path in exchange for nothing.

**Coalescing HTTP/2 DATA payloads.** One body-stream `pull()` hands over one DATA frame, so a body
crosses the ReadableStream boundary once per frame — 128 times per MB at this origin. Merging queued
payloads up to 64 KiB looked like a 40% cut to the HTTP/2 rung across one sweep. It is not: the chunk
counters came back **identical** with and without it — 512 chunks of 8192 either way — because a
consumer that keeps up finds exactly one payload queued at every pull, so the merge never runs. Held
open with an artificial delay so the queue could build, 8x fewer enqueues bought 0.3–1.0 ms/MB of the
4.7–6.0 that HTTP/2 costs. The apparent win was the minimum of nine integer-millisecond samples
moving while the median did not.

### Streaming APIs, and what they cost

An SSE response from an LLM API is the opposite shape to everything else measured here: a small body
arriving as one event per output token rather than a large one in a few chunks. The per-chunk costs
that are a footnote for a 4 MB page are the whole bill here.

Measured against a real streaming endpoint through a proxy, with the API's own `usage` block as the
token count rather than an estimate from response size:

| | per event | CPU per 1M output tokens | cost per 1M output tokens |
| --- | --- | --- | --- |
| this package | **250–310 µs** | 250–310 s | **$0.0050–0.0062** |
| platform `fetch` — reference; it cannot use a proxy | ~105 µs | 105 s | $0.0021 |

Those are half a cent per million output tokens against **$0.60** of model charge for the same
tokens. An earlier version of this table read "$5,000–6,200" — the same digits with the decimal
point six places out, from writing a per-million-*requests* figure into a per-million-*tokens*
column. The ratio quoted below was computed correctly and is unaffected; the table was not.

Events map to output tokens roughly 1:1, so a 128K-token completion is about **35 s of CPU**. That
is spread across the minutes the model takes to generate it — utilisation is 2–5%, so it is a
billing question, not a capacity one.

**As a share of what you pay, it is constant.** CPU and the model's output charge both scale with
output tokens, so the ratio does not move with length: at $0.6/M output it is **~0.9% of the model
bill**, at any size. Input tokens appear only in the denominator and push it lower.

A range is given rather than a figure because this measurement repeats to about ±20%. Two things
were tried and did not survive that: HTTP/1.1 came out ahead of HTTP/2 in one sweep and behind in
the next, and turning decoding off measured both faster and slower. **Neither is a recommendation.**

Splitting the gap to the platform's own `fetch`: decoding is a small part of it and the transport is
~155 µs per event, spread across the record layer, framing, the byte reader, the body stream and the
deadline wrapper — a few tens of microseconds each, with no single layer to remove. That is why the
`IdentityTransformStream` win on large bodies has no equivalent here: there, one JavaScript layer
could be deleted outright; here there are seven, each small.

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
`Headers`, `Request`, `Response`, `AbortSignal`, `btoa`. The only runtime-specific piece is the
`connect` function you supply.

| Runtime | Offline suite | Notes |
|---|---|---|
| Node 22, 24 | **all pass** | what CI gates on |
| Node 20 | not supported | `TextDecoder` treats `iso-8859-1` as true ISO-8859-1 instead of aliasing it to windows-1252 as WHATWG requires, so bodies in that charset decode differently. Left maintenance April 2026 |
| workerd | live edge suite passes | the target runtime; exercised end to end by the scheduled edge job rather than by the offline suite |
| Deno 2.9 | 2 failures | both failures are in the TLS 1.2 test server's secp521r1 path, not in the package; WebCrypto ECDSA and ECDH on P-521 both work standalone under Deno. Unresolved, so support is not claimed |
| Bun 1.3 | 3 failures | a module-resolution difference in one repo-hygiene test, one timing-sensitive deadline test, and the same TLS 1.2 suite test. Unresolved, so support is not claimed |

Node 22 and workerd are the supported pair. Deno and Bun very nearly work and are not tested in CI
— running the suite there is a good first contribution.

CI runs every version in `engines`, and a repo-hygiene test fails if the two ever disagree — an
untested support floor is a claim, not a fact.

## Testing

```bash
npm test          # offline, hermetic, no network
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

Every parser that consumes bytes a peer controls — the TLS record layer and handshake messages,
X.509, OCSP, HTTP/1.1 heads, chunked bodies, HTTP/2 frames, HPACK — is fuzzed against one
property: **any input either parses or throws a
`TunnelFetchError`.** An untyped throw, a `TypeError` from a missing null check or a `RangeError`
from a bad offset, is a finding: it means a check is missing and every caller relying on the typed
contract to fail closed will not catch it.

The fuzzer is seeded and dependency-free, so a failure prints the seed, the iteration and the case
in base64 — reproducible exactly, which a fuzzer whose failures cannot be replayed is not. Targets
are auto-discovered from `test/fuzz/targets/`; adding one is dropping a file in. The suite also
fuzzes *itself*: two synthetic targets prove the engine reports an untyped throw and does not report
a typed one, because a green fuzz run otherwise only proves the fuzzer never looked.

```bash
FUZZ_ITERATIONS=1000000 node --test test/fuzz/fuzz.test.js   # a soak
FUZZ_SEED=12345 node --test test/fuzz/fuzz.test.js           # a different corner
```

CI runs a fixed seed on every commit, as a gate; the scheduled workflow runs three million
iterations with the run id as the seed, which is the half that searches new ground.

`probe/` holds a reproducible capability probe that emits machine-readable JSON, and
`probe/results/` the measurements this design rests on. `live/` is the edge interop rig, and
`sizeorigin/` is the size-controlled origin the cost table is taken against — it lived outside the
repository until August 2026, was deleted, and took the table's reproducibility with it.

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
