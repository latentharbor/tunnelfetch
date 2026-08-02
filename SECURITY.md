# Security policy

## Reporting a vulnerability

Report privately through GitHub's [Report a vulnerability][advisory] form on this repository, which
opens a draft advisory only the maintainers can see. Please do not open a public issue for anything
with a security impact.

[advisory]: https://github.com/latentharbor/tunnelfetch/security/advisories/new

Useful things to include, roughly in order of how much they help: what an attacker gains, a
reproduction (a test against the in-memory harness in `test/` is ideal — no network needed), the
affected version, and which of the properties below you believe is broken.

You should get an acknowledgement within 5 days. If a fix is warranted it goes out as a patch
release with an advisory naming the reporter, unless you would rather not be named.

## What this package is responsible for

It implements TLS 1.2 and 1.3, X.509 path validation, and OCSP stapling checks in JavaScript,
because the runtime cannot perform a TLS handshake over a socket that is already open — which is
what a proxy CONNECT tunnel is. That means the usual reason to trust a TLS implementation, that it
is one of a handful everybody uses, does not apply here. Reports are genuinely welcome.

The properties worth attacking:

- **Certificate validation fails closed.** An unverified chain, an expired or not-yet-valid
  certificate, a hostname that does not match, a missing intermediate, a signature that does not
  check out, a pin that does not match, a revoked certificate under `require-staple` — every one
  must throw a typed error. Anything that returns a `Response` instead is a vulnerability.
- **No silent downgrade.** A version, cipher suite, group, or ALPN protocol the client did not
  offer must be refused, naming the value the server chose. Never negotiated down, never retried
  weaker.
- **Trust policies never share a connection.** The pool key covers every field the verifier reads,
  so a connection validated under one policy can never serve a request under another.
- **Credentials stay put.** Proxy credentials must not appear in errors, logs, or the `tunnelfetch`
  response detail. Session tickets are keyed to the full pool key and are dropped on `close()`.
- **A peer cannot make this client allocate without bound.** Response heads, proxy replies, and
  bodies all have caps that are enforced before the bytes are read, and every one of them has a
  finite DEFAULT. `maxBodyBytes` defaulted to `Infinity` through 1.5.0, which made this claim false
  for any caller who had not set it: a 53-byte brotli body reaching 32 MB is measured, not
  hypothetical. It is 32 MiB from 1.6.0. A caller may still pass `Infinity`, and that is then their
  decision rather than this package's default.
- **Ambiguity is an error.** Conflicting framing, a truncated body, an unknown record type, a
  header the parser cannot agree on — all must throw rather than guess.

## What is out of scope

- Anything that requires a proxy you already control to be malicious *and* the caller to have set
  `trust: { mode: 'none' }`. That mode requires a second explicit flag precisely because it turns
  verification off.
- Denial of service against a server you point this at. That is your relationship with that server.
- Traffic analysis and TLS fingerprinting. The client presents curl's fingerprint by default and
  makes no claim to be indistinguishable from anything.
- Vulnerabilities in decoders you register yourself via `decoders`. That code is yours; the package
  takes no dependencies of its own.

## Fuzzing

Every peer-facing parser — the TLS record layer and handshake messages, X.509, OCSP, HTTP/1.1 heads, chunked bodies, HTTP/2 frames, HPACK — is fuzzed against the property above — any input either parses or throws a
`TunnelFetchError`. To search a corner nobody has:

```bash
FUZZ_ITERATIONS=5000000 FUZZ_SEED=$RANDOM node --test test/fuzz/fuzz.test.js
```

A failure prints the seed and the exact case in base64. If you find one, that message is the whole
report — please send it.

## Supported versions

The latest minor release receives security fixes. This package has not yet had an external audit;
if you are considering one, or have run one, please get in touch.
