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

It is not a saving. Measured on the edge, decoding the same 256 KB page to the same bytes:

| Implementation | Algorithm | ms/MB |
|---|---|---|
| `DecompressionStream` — the runtime's own C++ | inflate | **2.5** |
| WASM brotli (`brotli-dec-wasm`) | brotli | 4.7 |
| JS inflate (`fflate` / `pako`) | inflate | 7.5 / 8.2 |
| JS brotli (`brotli`) | brotli | 19.7 |

Two things fall out, and both are worth knowing before reaching for WebAssembly anywhere else in a
Worker. **WASM is about 4x faster than JavaScript at the same algorithm** (brotli: 4.7 against
19.7) — so if a coding has no native path, WASM is the right way to add one. And **native is about
3x faster than JavaScript at the same algorithm** (inflate: 2.5 against 7.5–8.2) — so where a
native path already exists, nothing in userland improves on it. That is why `gzip` and `deflate`
are not overridable: replacing them could only ever be slower, and doing it silently is the kind of
quiet downgrade this package refuses everywhere else.

Brotli itself lands at 1.9x native inflate. That gap is the price of the coding, and the wire bytes
it saves do not pay it back — see [What this cannot do](#what-this-cannot-do-and-why). Decoder names
are validated as HTTP tokens, a decoder that throws fails the body closed rather than truncating it,
and an unregistered coding is still refused.

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
| HTTP/2 `SETTINGS` ids **and order** | curl's: `MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, ENABLE_PUSH` | `http2Settings` |
| h2 preface, `WINDOW_UPDATE`, pseudo-header order, HPACK representation | curl's, byte-for-byte | fixed |
| `Accept-Encoding` | `gzip, deflate` — curl's | `decoders` appends |

Extension order matters because JA3 and JA4 hash the extension list **in wire order**, so it is most
of what a fingerprinter reads. `pre_shared_key` is forced last whatever you ask for: RFC 8446
§4.2.11 defines the binder transcript as the hello truncated just before the binders, which is a
well-defined byte range only if nothing follows them.

**Where the default deliberately differs from curl**, and why it cannot simply be copied: a
ClientHello is an *offer*, and a server may take you up on any of it. Advertising what you cannot do
trades a fingerprint mismatch for a broken handshake, which is worse and fails silently.

| curl sends | This package | Why |
|---|---|---|
| 30 cipher suites, incl. RSA key exchange and CBC | 6 AEAD suites | Not implemented, by design. A server selecting `TLS_RSA_WITH_AES_256_CBC_SHA` would get a dead connection |
| `X25519MLKEM768` group and a 1216-byte key share | not offered | ML-KEM is not implemented |
| SHA-1 signature schemes | not offered | Refused deliberately |
| `encrypt_then_mac` | not sent | Applies only to CBC suites, which are not offered |
| `post_handshake_auth` | not sent | Invites a post-handshake `CertificateRequest`, which is not implemented |
| — | `status_request` | curl does not ask for a stapled OCSP response; this package must, because a staple is its only revocation signal |

Closing that gap means implementing ML-KEM, RSA key exchange and CBC suites — a different project,
and the last two are things this package refuses on purpose. `tls.ciphers` and `tls.groups` will let
you offer them anyway; the handshake will then fail if a server picks one, and that is yours to own.

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
| `tls` | `{}` | Handshake options (`alpn`, `groups`, `ciphers`, `offerGroups`). |
| `timeouts` | see below | `connectMs`, `handshakeMs`, `headersMs`, `idleMs`, `totalMs`. |
| `cookies` | `false` | Enable a per-Client cookie jar. |
| `maxRedirects` | `20` | |
| `maxBodyBytes` | `Infinity` | Enforced from `Content-Length` before a byte is read. |
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
- **ChaCha20-Poly1305.** It buys nothing: a server can only pick a suite we offered, TLS 1.3
  mandates AES-128-GCM, and AES-GCM is universal in TLS 1.2 deployments. WebCrypto has no
  ChaCha20, so offering it would mean a `node:crypto` dependency for zero compatibility gain.
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
- **`br` and `zstd` out of the box.** The runtime's `DecompressionStream` accepts gzip, deflate and
  deflate-raw only — measured, not assumed. Neither is *unreachable*, though: register a decoder
  with [`decoders`](#br-zstd-and-other-codings) and the coding is advertised and decoded. Nothing
  ships built in, because the only way to get Brotli here is WebAssembly, and a 208 KB binary blob
  would cost this package both its zero dependencies and its ability to be imported without a
  bundler. Bringing your own makes that cost, and that supply chain, yours and visible.

  Leaving it off is safe rather than lossy: content negotiation means a server never sends what was
  not asked for, so a Brotli-serving origin simply returns gzip. What it costs is bandwidth — the
  same page measured 290 KB as gzip against 99 KB as `br` — and bandwidth is not what this platform
  bills. Measured on the edge, the trade runs the wrong way: WASM Brotli decodes at about
  **1.9x** the CPU of the runtime's native inflate, and even on the page with the largest wire
  saving in a 14-site survey, the 186 KB saved bought back ~1.2 ms while the extra decoding cost
  several times that. Harder compression makes it worse, not better — brotli quality 11, which is
  what a CDN serves from cache, is 16% smaller on the wire than quality 5 and **46% more expensive
  to decode**, because decompression work scales with the OUTPUT bytes and a denser encoding means
  more work per byte produced. The reason to turn `br` on is matching a browser's
  `Accept-Encoding`, not saving CPU.
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

Fetching a size-controlled origin through a proxy, warm, medians over seven-plus rounds on one
isolate, gzip on the wire. The last column is the same numbers as a rate, which is the form worth
carrying around:

| | New connection | Each further request, same connection | Marginal rate |
| --- | --- | --- | --- |
| 1 KB body | 11 ms | 2–3 ms | — |
| 16 KB body | 11 ms | 3 ms | — |
| 64 KB body | 11 ms | 2–4 ms | — |
| 256 KB body | 7 ms | 3.4 ms | ~13 ms/MB |
| 1 MB body | 11 ms | 6–12 ms | ~9 ms/MB |
| 4 MB body | 31 ms | 21–35 ms | ~7 ms/MB |
| **Same 16 KB page over HTTP/2** | 12 ms | 2.2 ms | — |
| **First request in a fresh isolate** | 46 ms | — | — |
| **…after `warmup({ iterations: 5 })`** | 16 ms | — | — |

One model fits every body-size row to within its spread:

> **≈ 9.5 ms to open a connection + 2 ms per request + 5–8 ms per MB of body**

The connection term recovered independently from each row lands between 5 and 11 ms, agreeing with
the 9–12 ms measured for a new connection by other means. Most of it is the TLS handshake and
certificate chain validation; almost none of it is parsing (see below).

The ranges are real, not imprecision: absolute CPU on this platform varies by up to ~1.5× between
isolates and runs — the same sweep repeated lands on faster and slower machines — so the values are
medians and the spread is what repeated same-isolate measurement actually shows.

**Reuse is the lever.** Thirty 16 KB pages from one host cost about 103 ms down one connection and
about 300 ms opening thirty. That gap is the entire argument for holding a `Client` rather than
calling `createFetch` per request, and it widens as pages get smaller.

**HTTP/2 is more expensive in every cell and cheaper in none** — 12 ms against 8 ms for one page on
a new connection, 76 ms against 67 ms for thirty pages on one connection, changing only the offered
ALPN against the same origin and proxy. The overhead is HPACK plus frame and stream bookkeeping,
concentrated at connection setup: the preface, the `SETTINGS` exchange, and the first header block.
Multiplexing, the thing HTTP/2 is *for* in a browser, buys latency a one-request-per-handler Worker
cannot spend. Reach for it when a site refuses HTTP/1.1, and set `http2: false` on paths that do
not need it. (These two rows came from the Workers GraphQL analytics API rather than `wrangler
tail`, which would not survive the measurement network here; same edge CPU-time metric, quantiled
per minute.)

**The fresh-isolate rows are a ramp, not a step.** V8 tiers up per function per isolate, so the
first executions run interpreted and the excess decays over roughly six requests: 61 ms of total
excess above the warm floor without `warmup()`, 15 ms with it at five iterations — about 4.4 ms and
1.1 ms per request respectively, amortised over an isolate's early life. Warming costs 10 ms of
startup at one iteration and 22 ms at five, against a 1 s budget, and does not lower the warm floor.

### What that costs in dollars

Workers Standard bills $5/month including 10 million requests and 30 million CPU milliseconds, then
$0.30 per additional million requests and $0.02 per additional million CPU milliseconds. Applying
the measurements above, with the charge split out so it is clear what is yours to change:

| Workload | CPU/request | 10M/mo, cold | 10M/mo, warmed | 1B/mo, cold | 1B/mo, warmed |
| --- | --- | --- | --- | --- | --- |
| Platform `fetch` — reference; it cannot use a proxy | 0.3 ms | $5.00 | $5.00 | $307.40 | $307.40 |
| Pooled connection, 16 KB pages | 3.3 ms | $5.93 | $5.28 | $454.60 | $389.60 |
| Pooled connection, 1 MB pages | 9.2 ms | $7.11 | $6.46 | $572.60 | $507.60 |
| New connection per request, 16 KB | 11 ms | $7.47 | $6.82 | $608.60 | $543.60 |
| New connection per request, 1 MB | 14.5 ms | $8.17 | $7.52 | $678.60 | $613.60 |
| New connection per request, 4 MB | 30 ms | $11.27 | $10.62 | $988.60 | $923.60 |

"Cold" carries the measured fresh-isolate ramp of +4.4 ms per request amortised; "warmed" is the
same workload with `warmup({ iterations: 5 })`, which brings the ramp down to +1.1 ms. The saving is
$0.65/month at ten million requests and $65/month at a billion, identical across every row because
the ramp is a property of the isolate rather than of the request. The reference row carries no ramp
because the platform's own `fetch` has no JavaScript protocol stack to tier up.

Four things fall out of it.

**At ten million requests a month, none of this matters.** Every row lands between $5 and $11
because the included quotas swallow it — the included CPU works out to 3.0 ms per request at that
volume, so anything that reuses connections is inside the base fee entirely, cold starts included.

**At a billion, $297 of every row is the request charge**, identical across all of them and
unchangeable by anything this package does. Only the CPU is left to optimise, and there the
difference between reusing connections and not is $154/month on 16 KB pages.

**Pooled and warmed, the whole userland stack costs about 27% more than the platform's own
`fetch`** — $390 against $307 — for something the platform's `fetch` cannot do at all.

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
which Workers Standard does not bill, so the $65/month the "warmed" columns save at a billion
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
