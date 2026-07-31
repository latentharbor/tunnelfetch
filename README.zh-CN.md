# tunnelfetch

[English](README.md) · [简体中文](README.zh-CN.md)

一个 `fetch` 形态的 HTTP 客户端，能在只暴露原始 TCP 的运行时上——主要是 Cloudflare Workers (`workerd`)——通过 HTTP CONNECT、HTTPS 或 SOCKS5 代理发出请求。

零依赖。ESM。无构建步骤。`src/` 中没有任何 `node:` 导入。

```js
import { Client } from 'tunnelfetch';
import { connect } from 'cloudflare:sockets';

const client = new Client({ connect, proxy: 'http://user:pass@proxy.example:8080' });
const res = await client.fetch('https://api.example.com/v1/things');
const data = await res.json();
await client.close();
```

## 为什么会有这个包

在 Cloudflare Workers 上，没有任何受支持的方式能让 HTTPS 请求经第三方代理发出。原因是结构性的，而且每一条都在边缘实测过，不是推断出来的：

1. **`fetch()` 没有代理选项。** 没有 `proxy`，没有 `agent`，也没有 `dispatcher`。运行时的出站路由控制 (`fetcher`、`globalOutbound`) 指向的是其他 Worker，不是代理。
2. **`node:net` / `node:tls` 帮不上忙。** 它们是真实存在的，但都实现在同一套 `cloudflare:sockets` API 之上，继承了它的每一条限制。
3. **`cloudflare:sockets` 的 `connect()` 给的是原始 TCP**，所以 CONNECT 或 SOCKS5 握手完全做得到——做不到的是隧道*里面*的那层 TLS。

第三点就是问题的全部。`startTls()` 拿传给 `connect()` 的主机名去校验对端证书。而在隧道里，那个主机名是**代理**，不是源站，于是运行时校验的是一个错误的身份。`expectedServerHostname` 选项看起来像解法，其实不是：workerd 自己的源码称它 "not currently supported"，每次使用都会记日志，还带着一个 autogate，准备将来干脆拒绝它。2026-07-31 于边缘实测：

| 实验 | 结果 |
| --- | --- |
| `connect(A)` → `startTls()` | 握手完成，数据正常流动 |
| `connect(A)` → `startTls({expectedServerHostname: B})` | 握手**仍然**完成——这个选项挪动的是 SNI，不是身份校验那道门 |
| `connect(A)` → `startTls({expectedServerHostname: "probe.invalid"})` | 仍然完成 |
| 到源站的 CONNECT 隧道 → `startTls({expectedServerHostname: origin})` | **`TLS Handshake Failed`** |

隧道这一例 fail closed，这是正确的失败方式——但它也没留下任何一条路。而且 `getPeerCertificate()` 抛出 `not implemented`，`SocketInfo` 只带地址，`rejectUnauthorized: false` 一用就抛错，所以证书既没法查看，也没法事后重新校验。

所以，在 Worker 里发出经代理的 HTTPS 请求的唯一办法——同时也是提供 httpx 风格 `verify=` 的唯一办法——就是在用户态实现 TLS。这个包做的就是这件事。

**已在 Cloudflare 边缘端到端验证**，经由五个不同的第三方代理：TLS 1.3 (`0x0304`)、`TLS_AES_128_GCM_SHA256`、X25519、ALPN `http/1.1`、chunked 与 content-length 两种 framing、gzip 解码、证书链按 121 个内置 CCADB 根证书完成校验。

## 安装

```bash
npm install tunnelfetch
```

包在 `src/` 下直接发布纯 ESM。没有构建产物，也没有 `nodejs_compat` 要求——线上实测环境部署时不带任何兼容性标志。

TypeScript 声明放在 `types/`，由源码里的 JSDoc 生成并签入仓库，因此安装时不需要构建任何东西。这些声明不是摆设：`trust` 是一个判别联合，这让好几种把安全配置写错的方式变成编译期错误，而不是运行期错误。

```ts
new Client({ trust: { mode: 'pinned' } });
//                   ^ Property 'pins' is missing but required in type 'PinnedTrust'

new Client({ trust: { mode: 'none' } });
//                   ^ Property 'insecureAcceptAnyCertificate' is missing but required
```

## 用法

### 作为自定义 `fetch`

OpenAI 与 Anthropic 的 SDK，以及大多数值得走代理的库，都接受一个 `fetch` 函数。这个形态就是本包的首要交付物。

```js
import { Client } from 'tunnelfetch';
import { connect } from 'cloudflare:sockets';
import Anthropic from '@anthropic-ai/sdk';

const transport = new Client({ connect, proxy: env.PROXY_URL });

const client = new Anthropic({
  apiKey: env.ANTHROPIC_API_KEY,
  fetch: transport.fetch,          // 已在构造时绑定；连接池跨调用存活
});
```

`client.fetch` 在构造函数里就绑定好了，正是为了能直接按引用交给 SDK。这里请优先用它而不是 `createFetch`：后者每次调用都开一条连接、用完即关，在按 CPU 计费的运行时上意味着每个请求都重付一次完整 TLS 握手——实测约 10 ms，而池化请求是 1.2 ms。`createFetch` 是给一次性调用准备的，对应 httpx 的模块级快捷函数。

### 连接复用与 cookie jar

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

边缘实测：第一个请求 678 ms，发往同一源站的第二个 135 ms。

### 替换全局 fetch

有的库只会直接调用全局 `fetch`，为它们准备的是：

```js
import { install } from 'tunnelfetch';
const uninstall = install({ connect, proxy: env.PROXY_URL });
try { await thirdPartyLibrary(); } finally { uninstall(); }
```

这件事绝不会在 import 时自动发生。悄悄替换全局对象，会让进程里每一个不相干的故障看起来都像这个包的 bug。

### Server-sent events

SSE 在这里没有任何专属代码：它就是一个 `text/event-stream` 的 body，与其它 body 无异。真正要紧的是 body 确实在流式传输——这一点在边缘经代理实测过，一个 592 KB 的响应分成 442 个 chunk 到达，第一个 chunk 与响应头同一时刻。

```js
const client = new Client({
  connect,
  proxy: env.PROXY_URL,
  timeouts: { idleMs: 60_000, totalMs: 0 },
});
const res = await client.fetch(url, { headers: { accept: 'text/event-stream' } });
for await (const chunk of res.body) {
  // 事件写出即到达，而不是等整个响应结束
}
```

有两个设置值得刻意选择。`idleMs` 量的是 chunk 之间的间隔，不是总时长——把它调到高于你的上游心跳间隔，否则一条安静但活着的流会被切断。`totalMs` 默认关闭，这正是长连接想要的；只在需要兜底时才打开。

中途放弃一条流，连接绝不会回到池里：它的位置是未知的，复用会把上一个响应的残余拼接到下一个请求上。

## API

### `new Client(options)`

| 选项 | 默认值 | 含义 |
| --- | --- | --- |
| `connect` | — | socket 工厂。在 Workers 上就是 `cloudflare:sockets` 导出的 `connect`。凡平台 `fetch` 无法承接的请求都需要它。 |
| `proxy` | `null` | URL 字符串或对象。`http:`、`https:`、`socks5:`、`socks5h:`。 |
| `trust` | `{mode:'system'}` | 证书策略；见下文。 |
| `tls` | `{}` | 握手选项 (`alpn`、`groups`、`ciphers`、`offerGroups`)。 |
| `timeouts` | 见下文 | `connectMs`、`handshakeMs`、`headersMs`、`idleMs`、`totalMs`。 |
| `cookies` | `false` | 启用该 Client 专属的 cookie jar。 |
| `maxRedirects` | `20` | |
| `maxBodyBytes` | `Infinity` | 在读入任何字节之前就按 `Content-Length` 强制执行。 |
| `decompress` | `true` | gzip/deflate。永远不含 `br`——见限制一节。 |
| `keepAlive` | `true` | |
| `forceTunnel` | `false` | 永不委托给平台的 `fetch`。 |
| `nativeFetch` | `globalThis.fetch` | 委托目标。 |

`client.fetch(input, init)` 接受并返回平台的 `Request`/`Response`。响应上带有一个非标准的 `tunnelfetch` 属性，内容为 `{proxied, proxy, tls, httpVersion, framing}`。

`client.close()` 释放池中全部 socket。不关闭的 `Client` 会在 isolate 的整个生命周期里泄漏 socket。

### Trust — `verify=` 旋钮

```js
{ mode: 'system' }                                  // bundled CCADB roots (default)
{ mode: 'anchors', anchors: [pemOrDer, ...] }       // exactly these, nothing else
{ mode: 'pinned', pins: ['sha256/BASE64...'] }      // full validation plus an SPKI pin set
{ mode: 'custom', verify: async (chain, host) => {} } // your policy; throw to reject
{ mode: 'none', insecureAcceptAnyCertificate: true } // no verification at all
```

`mode: 'none'` 必须同时带上第二个标志；靠打错字是到不了这一档的。pin 不匹配时会把实际看到的 pin 报出来，正确的值可以直接从日志里复制：

```
CertificateError [CERT_PIN_MISMATCH]: no certificate in the chain matches any configured pin
(observed: sha256/uOmwqBIvMM6bY2khsu8Tmp+ltdXst3nxA6Z3ZuKeAWA=, sha256/ZSagvDzj…)
```

### 什么情况下会改用平台的 `fetch`

只有当一个请求能被**完全等价地**满足时，才会委托给平台自己的 `fetch`：没有代理、默认信任策略、没有 TLS 选项、没有 `forceTunnel`。其余一律走本包的协议栈。把一个要求 pin 证书的请求，交给一个用着另一套信任库的实现，等于回答了一个调用方从未问过的问题。

在委托适用的时候，它通常正是你想要的：更快、不消耗计费 CPU、会说 HTTP/2 和 /3，还能到达原始 socket 被禁止拨号的那些源站。

### 超时

| 截止时间 | 默认值 | |
| --- | --- | --- |
| `connectMs` | 10 000 | TCP 连接与代理握手 |
| `handshakeMs` | 15 000 | TLS 握手 |
| `headersMs` | 30 000 | 状态行与响应头 |
| `idleMs` | 60 000 | **响应体分块之间的间隔** |
| `totalMs` | `0` (关闭) | 整个请求的上限 |

真正起控制作用的是 idle 截止线，不是总时长：对流式响应来说，“距上一个字节过了多久”才是出问题的信号，“总共花了多久”不是。所有计时器都由流事件驱动，而不是去读时钟——因为在这个运行时上，`Date.now()` 在一整段同步代码执行期间是冻结的，只有跨过 I/O 才会前进；靠轮询时钟实现的截止时间，要么永远不触发，要么在一个毫不相干的时刻触发。

这些是活性控制，不是成本控制。运行时按 CPU 计费而不是按墙钟计费，所以一条等着慢速对端的连接是免费的；而且响应头一旦到达，它就不再占用「一次调用最多同时等待响应头的六个槽位」之一。正是这种不对称决定了 `idleMs` 的默认值应当偏长：设得过长，只不过多挂着一条不计费的连接；设得过短，则会掐死一个本来会成功的请求。不要试图把它对齐到对端的心跳间隔——会发送保活事件的流式 API 通常并不承诺间隔，而一个正在算长答案、还没吐出第一个字节的对端，本就该安静那么久。

`headersMs` 是唯一真正占用那个响应头等待槽位的阶段，所以更紧。如果对端会把整个慢响应缓冲完才发响应头，就调高它；流式对端会立刻发响应头，永远用不到。

## 它做不到什么，以及为什么

这一节才是重点。每一条限制都是有意为之。

**直连（不走代理）能到达的网络少得可怜。** `connect()` 拒绝 Cloudflare 自家的地址段，而互联网相当大的一部分正坐在这些地址段后面——今天连 `example.com` 也在其中。拒绝在 0–6 ms 内发生，报 `proxy request failed, cannot connect to the specified address`。现实后果是：**证书 pinning 与自定义 anchors 只有走代理才用得上**，因为直连模式根本到不了大多数源站。

**只支持 TLS 1.3 与 1.2，只支持 AEAD。** 可协商的范围：TLS 1.3 配 AES-128/256-GCM，TLS 1.2 配 ECDHE + AES-GCM。密钥交换 X25519、P-256、P-384、P-521。签名 ECDSA、RSA-PSS、RSA-PKCS#1 (SHA-256 及以上)、Ed25519。

未实现，也不打算实现：

- **任何 TLS 版本下的 CBC 密码套件。** CBC 是 MAC-then-encrypt，要扛住 Lucky13，padding 校验就必须是常数时间的。JavaScript 承诺不了常数时间——JIT 分层和 GC 保证了这一点——所以发布 CBC，就是以兼容性之名发布一个 padding oracle。这一条对 TLS 1.2 的 CBC 套件与对 TLS 1.0/1.1 同等成立。
- **TLS 1.0 / 1.1。** RC4 已被攻破，那里剩下的全是 CBC。浏览器自 2020 年起就拒绝这两个版本。注意其中的区别：*同时也*支持 1.0/1.1 的服务器没有问题，我们会与它协商出 1.2 或 1.3；够不着的只有*除此之外什么都不支持*的服务器。
- **RSA 密钥传输。** 没有前向保密。
- **ChaCha20-Poly1305。** 加上它换不来任何东西：服务器只能从我们报出的套件里选，TLS 1.3 强制要求 AES-128-GCM，而 AES-GCM 在 TLS 1.2 的实际部署中无处不在。WebCrypto 没有 ChaCha20，要提供它就得引入 `node:crypto` 依赖，兼容性收益却是零。
- **客户端证书 (mTLS)、会话恢复、0-RTT、重协商。** 收到 `HelloRequest` 会拒绝，而不是照办。
- **证书吊销 (CRL / OCSP)。** 检查吊销需要在握手中途发一次网络请求；这没有实现，而假装实现了比坦白说明更糟。
- **证书策略处理** (`policyConstraints`、`inhibitAnyPolicy`)。它们永远是 critical 的，所以一旦出现就直接拒绝，而不是被错误地校验过去。
- **dNSName 与 iPAddress 之外的名称约束。** 标为 *critical* 且指名不支持类型的约束扩展会被拒绝；非 critical 的则按 RFC 5280 允许的那样忽略。
- **cookie 的 public suffix list。** 只实现了“域名里没有点”这一道防护，所以 `Domain=com` 会被拒绝，`Domain=co.uk` 不会。如实写明，而不是伪造。
- **IDNA。** 请传 A-label (punycode)；非 ASCII 主机名会被拒绝，并附上说明原因的报错。
- **`br` 与 `zstd` 内容编码。** 运行时的 `DecompressionStream` 只支持 gzip、deflate 和 deflate-raw。因此客户端从不声明接受 `br`——主动要它，换回来的只会是解不开的字节。
- **HTTP/2 与 HTTP/3。** ALPN 只提供 `http/1.1` 一项；服务器选了别的即 fail closed。

**socket 不能跨请求上下文。** 连接池按设计随 `Client`、随单次调用存在；不存在跨请求的连接缓存，因为运行时不允许有。

**并发。** 平台允许同时有六条连接处于等待响应头的状态。想要更高并行度的爬虫，必须在这个限额之内做流水线。

## 线上 Worker 的开销

用 `wrangler tail` 在边缘实测，warm isolate，重复运行取中位数，经真实代理。Workers 按 CPU 时间计费，不按墙钟时间，而这里的一个请求约 95% 的时间都在等网络。

| | CPU |
| --- | --- |
| 启动（脚本上传分析） | **1 ms**，对应 344 KB 的 bundle / gzip 后 122 KB |
| 导入了包但未使用的请求 | **0 ms** |
| 全新 isolate 里的第一个请求 | **~35–50 ms**——TLS 路径的一次性 JIT |
| 此后的 TLS 1.3 握手 + 请求 | **~9–13 ms** |
| 池化连接上的后续请求（无 body） | **~1.2 ms** |
| 再加 80 KB 的 gzip body，解压并解码 | **~16 ms** |

有两个值得纳入规划的推论：

- **导入这个包是免费的。** 121 个锚点的信任库存成 base64 字符串，按 subject DN 的哈希建索引，只有证书链实际落到的那一个锚点才会被解码。import 时什么都不解析，这正是启动停在 1 ms 的原因。
- **该摊销的是握手。** 复用连接把 ~10 ms 的开销变成 ~1 ms——当一个请求处理程序要发不止一次调用时，这就是用 `Client` 而不用 `createFetch` 的全部理由。边缘实测墙钟时间：对一个源站的第一个请求 185 ms，第二个 72 ms。

对照付费套餐默认 30 s 的 CPU 上限，单次调用大约够 2 000 次握手，或约 150 MB 的解压后响应体——实践中先卡住你的是六并发连接上限，远轮不到 CPU。

**免费套餐不可行**：每个请求只给 10 ms CPU，连一次握手都装不下。请用付费套餐 (默认 30 s，上限 5 min)。

## 运行时要求

WebCrypto (X25519、ECDH P-256/384/521、ECDSA、RSA-PSS、RSASSA-PKCS1、HKDF、HMAC、AES-GCM)、含 BYOB reader 的 WHATWG Streams、`TextEncoder`/`TextDecoder`、`DecompressionStream`、`URL`、`Headers`、`Request`、`Response`、`AbortSignal`、`btoa`。这些在 workerd、Node ≥ 20、Deno 与 Bun 上全部具备。唯一与具体运行时绑定的部分，是你自己提供的 `connect` 函数。

## 测试

```bash
npm test          # 866 offline tests, hermetic, no network
npm run test:live # explicit; needs TUNNELFETCH_PROXY in the environment
```

离线套件从不接触网络，而且这一点是被强制执行的：一套仓库卫生套件会让构建失败，只要任何测试文件写了可路由的主机名，`src/` 从 `node:` 导入，`src/` 里出现 URL、厂商名、`Math.random` 或 `console.*` 调用，或者 `src/` 下有任何模块没有测试。

每一个按字节消费输入的解析器都会过一遍 `underAllChunkings`：同一串字节分别以整块、逐字节、以及若干伪随机切分点的方式喂入，并断言所有跑法结果一致。在不同分块形状下表现不同的解析器，带着一个只在真实网络分片下才现身的 bug——而那正是那种无法凭报告复现的 bug。

TLS 密钥调度与记录层逐字节钉死在 **RFC 8448** "Example Handshake Traces for TLS 1.3" 上：AEAD 复现出 RFC 里一模一样的密文记录，记录层把 RFC 的完整线上字节在两个方向上原样重放。两个 TLS 驱动都对着独立编写的测试服务器测试——1.2 的服务器建在 `node:crypto` 上，而不是本包自己的原语上，这样客户端的 bug 就不可能被服务器端的同一个 bug 抵消掉。

`probe/` 存放一个可复现的能力探测，输出机器可读的 JSON；`probe/results/` 存放本设计所依据的测量结果。`live/` 是边缘互操作实测环境。

凭据只从环境读取。live 套件在未配置时会大声失败而不是跳过：一个意思是“我们没检查”的绿勾，比红叉更糟。

## 致谢

信任锚点派生自 Mozilla / Common CA Database (CCADB)，按 CDLA-Permissive-2.0 使用。用 `npm run roots:refresh` 重新生成；生成的模块会记录来源、获取日期、上游 SHA-256 与锚点数量——因为过期的根证书库是一个无声的可用性 bug，几个月后才以“TLS 随机失败”的面目浮出水面。

[`jawj/subtls`](https://github.com/jawj/subtls) (MIT) 是一个很有价值的概念验证，证明了在这类运行时上用 WebCrypto 跑 TLS 1.3 是可行的，编写本包时曾将其作为参考阅读。

## 许可证

MIT。
