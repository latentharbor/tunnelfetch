# tunnelfetch

[English](README.md) · [简体中文](README.zh-CN.md)

[![CI](https://github.com/latentharbor/tunnelfetch/actions/workflows/ci.yml/badge.svg)](https://github.com/latentharbor/tunnelfetch/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/tunnelfetch)](https://www.npmjs.com/package/tunnelfetch)
[![license](https://img.shields.io/npm/l/tunnelfetch)](LICENSE)


一个 `fetch` 形态的 HTTP 客户端，能在只暴露原始 TCP 的运行时上——主要是 Cloudflare Workers (`workerd`)——通过 HTTP CONNECT、HTTPS 或 SOCKS5 代理发出请求。

零依赖。ESM。无构建步骤。`src/` 中没有任何 `node:` 导入。

> **成熟度。** 这是一个新实现，不是久经沙场的实现。它在用户态实现了 TLS 1.2/1.3 与证书校验——在这个领域，好的测试是必要条件，但不是充分条件。它有一千一百多个离线测试、RFC 向量、逐字节分片、真实边缘互操作测试、对每一个面向对端的解析器做种子化 fuzzing，行覆盖率 95%；但它**没有**经过外部安全审计。请把它当作一个值得一试的高质量实现，而不是一个已被生产验证的东西。发现任何问题都欢迎报告——见 [SECURITY.md](SECURITY.md)。

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

**已在 Cloudflare 边缘端到端验证**，经由五个不同的第三方代理：TLS 1.3 (`0x0304`)、`TLS_AES_128_GCM_SHA256`、X25519、ALPN 协商出 `h2` 或 `http/1.1`、HTTP/2、chunked、content-length 三种 framing、gzip 解码、证书链按 121 个内置 CCADB 根证书完成校验。

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

`client.fetch` 在构造函数里就绑定好了，正是为了能直接按引用交给 SDK。这里请优先用它而不是 `createFetch`：后者每次调用都开一条连接、用完即关，在按 CPU 计费的运行时上意味着每个请求都重付一次完整 TLS 握手——实测约 10 ms，而复用已有连接的请求是 0.9 ms。`createFetch` 是给一次性调用准备的，对应 httpx 的模块级快捷函数。

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
await client.close();          // 必须调用：释放池中的 socket
```

边缘实测：第一个请求 678 ms，发往同一源站的第二个 135 ms。

这个 jar 是刻意最小化的——它做 RFC 6265 的域名与路径匹配、`Secure`、host-only cookie、过期与 `Max-Age`，
别的都不做。但它**强制执行 `__Host-` 与 `__Secure-` 名字前缀**，因为那不是便利功能:名字本身就是服务端
「这个 cookie 是带着特定属性设置的」这一声明，而一个忽略该声明的客户端，等于悄悄拿掉了服务端正在依赖的一层
保护。一个违背自己前缀的 `Set-Cookie` 会被**整条拒绝**，绝不「修好再存」——修好它，恰恰就制造出了服务端最
不该拿到的那份证明。

前缀匹配是**大小写不敏感**的，这是 RFC 6265bis §5.4 的 MUST，而且并不是个显然的选择:服务端普遍按大小写不敏感
比较 cookie 名字，所以一个按大小写敏感匹配的客户端会把 `__SeCuRe-SID` 原样存下、一条规则都不施加，而服务端
分辨不出它和真的那个有什么区别。按大小写敏感匹配就是 CVE-2024-5699。

§5.7 里有两条相关规则**没有**实现，如果你要靠这个 jar 提供安全性，值得知道:「Leave Secure Cookies Alone」
（第 16 步），所以一个普通名字的 `Secure` cookie 即便是在 https 上设置的，仍可能被 http 覆盖;以及名字加值
4096 字节的上限（第 4 步）。

### 替换全局 fetch

有的库只会直接调用全局 `fetch`，为它们准备的是：

```js
import { install } from 'tunnelfetch';
const uninstall = install({ connect, proxy: env.PROXY_URL });
try { await thirdPartyLibrary(); } finally { uninstall(); }
```

这件事绝不会在 import 时自动发生。悄悄替换全局对象，会让进程里每一个不相干的故障看起来都像这个包的 bug。

### 预热一个全新 isolate

V8 按函数、按 isolate 编译与优化，所以经过一个全新 isolate 的第一个请求，TLS 和 HTTP 路径是解释运行的——
46 ms，而热态地板约 10 ms，超额部分在大约六个请求内衰减。`warmup()` 在模块作用域用真实的驱动重放一次录制好的
握手，这样第一个真实请求碰到的就是引擎已经分层优化过的代码。

```js
import { warmup } from 'tunnelfetch';

await warmup();                       // 模块作用域，每个 isolate 一次
export default { async fetch(req, env) { /* ... */ } };
```

它是 opt-in 的，本包永远不会自己调用它，因为这笔账不是对每个人都一样。标准 Workers 不对启动 CPU 计费，所以这是
把计费的请求毫秒换成不计费的，纯赚。在**会**对启动计费的形态上——比如 Cloudflare 的动态 Worker 加载——它不免费，
但通常仍然划算：启动成本每个 isolate 只付一次，会被这个 isolate 服务的所有请求摊掉，所以超过约**每 isolate 7 个
请求**它就回本，低于这个数则亏。它同时也在 isolate 启动时消耗真实墙钟时间，如果你的启动预算本就紧张，这一点要考虑。
一个库不该替使用者做这个决定。

它不缓存任何东西、不持有任何状态：重放用一个显式的 anchors 模式配置，拿自己合成的链去验自己烘焙的根，从不触碰
内置的根库；不调用 `warmup()` 时行为逐字节相同，只是一开始慢一些。一个导入了但从不调用它的 Worker 实测不受影响。
每种迭代次数分别买到什么，见开销那一节的表。

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

### `br`、`zstd` 与其它编码

`gzip` 和 `deflate` 是内置的，因为运行时原生就能解。其余都是可插拔的：给 `decoders` 传一个"每种编码一个函数"的表，该编码就会被追加进 `Accept-Encoding`，并被用于解码匹配的响应。注册这个动作本身，正是"声明"变得诚实的前提——请求一个自己读不了的编码，会把每一个这样的响应变成乱码，所以两者绑在一起、不可能漂移。

```js
import { Client } from 'tunnelfetch';
import { connect } from 'cloudflare:sockets';
import { BrotliDecStream, BrotliStreamResultCode, initSync } from 'brotli-dec-wasm/web';
import wasm from 'brotli-dec-wasm/web/bg.wasm';

// 放在模块作用域，实例化就落进 isolate 启动阶段，而这个运行时不对启动计费。
// 边缘实测：这一步的成本测不出来（带它启动 12 ms，不带也是 12 ms）。
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
// 此后会发送 `Accept-Encoding: gzip, deflate, br`，并解码 `Content-Encoding: br`。
```

顺序是内置项之后按注册顺序排，所以 `{ br, zstd }` 得到的正是 Chrome 发的 `gzip, deflate, br, zstd`——而这才是做这件事的真正理由。这个客户端默认呈现 curl 的 TLS 与 HTTP/2 指纹，而 `gzip, deflate` 正是 curl 发的，所以默认状态本就是一致的。它不再一致，恰恰是从你把握手打扮成浏览器、却把这个头留在原地的那一刻开始。

它不是一项省钱优化。边缘实测，把同一个 256 KB 页面解成同样的字节：

| 实现 | 算法 | ms/MB |
|---|---|---|
| `DecompressionStream`——运行时自己的 C++ | inflate | **2.5** |
| WASM brotli（`brotli-dec-wasm`） | brotli | 4.7 |
| JS inflate（`fflate` / `pako`） | inflate | 7.5 / 8.2 |
| JS brotli（`brotli`） | brotli | 19.7 |

由此得到两条结论，在 Worker 里任何地方考虑用 WebAssembly 之前都值得知道。**同一算法下 WASM 比 JavaScript 快约 4 倍**（brotli：4.7 对 19.7）——所以某个编码若没有原生实现，WASM 是补上它的正确方式。**同一算法下原生又比 JavaScript 快约 3 倍**（inflate：2.5 对 7.5–8.2）——所以只要已经有原生路径，用户态怎么写都赢不了。这正是 `gzip` 和 `deflate` 不可覆盖的原因：替换它们只可能更慢，而静默地这么做，恰恰是这个包在别处一律拒绝的那种悄悄降级。

brotli 本身落在原生 inflate 的 2.5 倍。这个差价就是这个编码的成本，而它省下的线上字节买不回来——见[这个包做不到什么](#这个包做不到什么为什么)。解码器名字会按 HTTP token 校验；解码器抛错时响应体 fail closed，而不是被截断；未注册的编码依然会被拒绝。

### 一行 import 得到 Chrome 身份

```js
import { Client } from 'tunnelfetch';
import { chrome } from 'tunnelfetch/profile/chrome';

const client = new Client({ profile: chrome, connect, proxy, decoders: { br, zstd } });
```

这个子路径带着运行时没有原生实现的两个原语——`X25519MLKEM768` 密钥交换要的 ML-KEM-768,以及记录层要的 ChaCha20-Poly1305,都编译成无依赖的 WASM,并且都在本仓库里有已知答案测试。**导入即 opt-in**:打包器只为走这条路径的代码拉入它们,默认身份一个字节都不背。

`br` 和 `zstd` 仍然要你自己带。它们不是密码学、没有唯一正解,所以 profile 会一直拒绝到你提供为止——**一个声称支持 br 却读不了的 Chrome,比一个老实说不支持的更糟**。

不是「能构造出来」,是端到端验证过:

| 源站 | | TLS | 群 | HTTP |
|---|---|---|---|---|
| `blog.cloudflare.com` | 200 | 1.3 | `0x11ec` X25519MLKEM768 | h2 |
| `www.shopify.com` | 200 | 1.3 | `0x11ec` X25519MLKEM768 | h2 |

### 自定义一个身份

三个层次,按你大概率会用到的顺序。

**改一个字段。** `tls` 是逐项合并的,点名一项不会丢掉 profile 的其余部分:

```js
new Client({ profile: chrome, tls: { alpn: ['http/1.1'] } });
// alpn 换了;extensionOrder、grease、ciphers、groups 仍然是 Chrome 的
```

顶层字段(`headerOrder`、`http2Settings`、`http2PseudoHeaderOrder`、`http2HpackIndexing`)是整体替换——一个合并了一半的顺序不成其为顺序。

**派生一个 profile。** profile 就是个普通的冻结对象,spread 它就是全部机制,没有 API 要学。想给所有请求换 User-Agent,这就是正确做法:

```js
const mine = { ...chrome, name: 'chrome+mine',
               headers: [['User-Agent', 'mybot/1.0'], ['X-Tag', 'a']] };
new Client({ profile: mine, connect, proxy });
```

**从零写一个。** 内置的那两个没有任何特权:

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

`requires` 对你自己的 profile 和对内置的一视同仁:声明一项 Client 没有拿到的能力,构造就会被拒绝并指名缺什么。**自定义身份同样受"不许声明做不到的事"的约束。**

profile 的 `headers` 是默认值——单次请求的同名 header 会盖掉它;而 `Client` 的显式选项会盖掉 profile。所以优先级是:每请求 > Client 选项 > profile。

### 四个 WASM 模块的冷启动成本

模块作用域的实例化落在启动阶段,而这个运行时**不对启动计费**,所以只有全新 isolate 的第一个请求看得见,之后为零。对照一组除了「有没有 import 这四个模块」之外完全相同的部署:

| | 带四个 WASM 模块 | 一个都不导入 |
|---|---|---|
| 全新 isolate 的第一个请求 | 3 ms | 0 ms |
| 第 2–5 个请求 | 0 ms | 0 ms |
| 第 6 个请求以后 | 0 ms | 0 ms |

每字节的解码成本是另一回事,而且是**有条件的**:只有源站真的发 `br` 或 `zstd` 时才付。

### HTTP/2 — 要的是访问，不是速度

客户端默认在 ALPN 中同时报出 `h2` 与 `http/1.1`，服务器选中哪个就说哪个。没有单独的 API：
落在 `h2` 连接上的请求，只是在自己的 `tunnelfetch` 详情里报 `httpVersion: '2'` 而已。设置
`http2: false` 则只报 `http/1.1`。

**在这里实现 HTTP/2，为的是访问，不是性能——而且在这个运行时上，它消耗的 CPU 比 HTTP/1.1
*更多*，不是更少。** 这由两件事决定：HPACK 是 HTTP/1.1 根本不做的头部压缩工作；多路复用买到的
是延迟，而一个通常只发一个请求、然后等它返回的 Worker handler 花不出去这笔延迟。所以，如果你
是在按 CPU 计费的平台上指望靠 HTTP/2 提速，那是拉错了杠杆。它真正买到的，是够得着那些把
HTTP/1.1 当作机器人信号的站点。这一点是测出来的，不是想当然——同一个代理、同一个浏览器
`User-Agent`、同一组请求头，只改协议：

```
stackoverflow.com  --http1.1 -> 403 "Just a moment..."  (Cloudflare challenge, cf-mitigated: challenge)
                   --http2   -> 200, 291 KB of real content
```

在十个站点的样本里，HTTP/2 恰好只改变了一个站点的结果：四个站点在两种协议下被一视同仁地拦住，
五个两种协议都畅通。所以诚实的预期是“十个站点大约解锁一个”，而不是“解决了反爬”。

**而这个预期本身是有保质期的。** 就在这个功能落地的当天，用同样的代理重测，那个站点已经连
HTTP/2 一起挑战了——`curl --http2` 在那里被拒，和本包被拒得一模一样，而同样的代理抓其它站点
仍然正常。所以这项能力是真实且正确的（ALPN 确实协商出 `h2`，这个客户端受到的对待与 curl
无异），但它当初要赢下的那个具体访问，没撑过一天。反爬是对抗性的，一直在动；协议是一时的窗口，
不是恒定的属性。不要因为某一个站点的表现就在这里启用 HTTP/2——去测你自己的目标，并且预期答案
会变。在那个样本里，我们的 TLS 指纹和 curl 的在每一个可达主机上结果完全一致，所以 JA3 一类的
TLS 指纹塑形不是这里的门槛——但 curl 的 **HTTP/2** 指纹能过 HTTP/1.1 被挑战的地方。因此
`SETTINGS` 帧的取值、初始窗口大小、连接级的 `WINDOW_UPDATE`、伪头的顺序，全部逐字节对齐
curl（8.7.1 / nghttp2），照线上抓包原样复刻。这么做是实证需要，不是讲究：一个想当然的 h2
指纹，可能恰好败在 curl 能过的地方——那这整件事就白做了。

### 指纹

两侧都对齐 **curl 8.21.0 / OpenSSL 3.6.3**，且全部可自定义。TLS 后端比 curl 版本更要紧——同一个 curl 用 SecureTransport 编译出来的 ClientHello 完全不同——所以参照物是从线上抓下来的，不是凭记忆写的，并且钉死在 `test/tls/fingerprint.test.js` 与 `test/http2/fingerprint.test.js` 里。

| 层 | 默认 | 配置项 |
|---|---|---|
| ClientHello 扩展**顺序** | 与 curl 完全一致（就双方都发的那些而言） | `tls.extensionOrder` |
| 密码套件 | 本包实现的 AEAD 套件，按 curl 的相对顺序 | `tls.ciphers` |
| supported_groups | `x25519, secp256r1, secp384r1, secp521r1` | `tls.groups` |
| 签名算法 | SHA-256/384/512 上的 ECDSA 与 RSA-PSS/PKCS#1 | `tls.sigSchemes` |
| ALPN | `h2, http/1.1` | `tls.alpn` |
| HTTP/2 `SETTINGS` 的 id **与顺序** | curl 的：`MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, ENABLE_PUSH`。**取值**默认不同——见下 | `http2Settings` |
| h2 前导、`WINDOW_UPDATE`、伪头顺序 | curl 的，逐字节一致 | `http2ConnectionWindow`、`http2PseudoHeaderOrder` |
| HPACK 表示 | curl 的（`:path` 不索引，其余 incremental） | `http2HpackIndexing` |
| `Accept-Encoding` | `gzip, deflate`——curl 的 | `decoders` 会追加 |

**默认的 `SETTINGS` 取值是本包自己的，不是 curl 的，这是一个有意的取舍。** `profiles.curl` 带的是
curl 8.21.0 实测的 `INITIAL_WINDOW_SIZE` = **64 KiB**，抓包固化在 `test/tls/_captured-h2.js`。而不加
profile 时连接的默认值是 **10 MiB**——那是 curl 8.7.1 发的值，本包为吞吐保留它：64 KiB 的流窗口意味着大
body 上要多得多的 `WINDOW_UPDATE` 往返，而本文档的成本部分已经说明，钱就花在 body 传输上。**这个吞吐差异
我没有实测过**，所以如果你在 `profiles.curl` 下搬大 body，先测再依赖，或者自己设 `http2Settings`。

1.6.2 之前，这个 profile 带着 curl **8.7.1** 的窗口，却呈现 curl **8.21.0** 的 ClientHello：同一个具名
客户端，两个来源版本——一个只有抓包才能发现的身份分裂，因为两半各自都真的属于某个 curl。

扩展顺序之所以要紧，是因为 JA3 和 JA4 哈希的正是**线上顺序**的扩展列表，那是指纹识别读到的主要内容。`pre_shared_key` 无论你怎么配都强制排最后：RFC 8446 §4.2.11 把 binder 的转录定义为"截到 binder 之前的那段 hello"，只有后面不跟东西时这个范围才成立。

**默认值刻意与 curl 不同的地方**，以及为什么不能照抄：ClientHello 是一份**要约**，服务器可以接受其中任何一项。声明你做不到的事，等于拿指纹不一致换一次握手失败——后者更糟，而且是静默的。

| curl 发送 | 本包 | 原因 |
|---|---|---|
| 30 个套件，含 RSA 密钥交换与 CBC | 6 个 AEAD 套件 | 有意不实现。服务器选中 `TLS_RSA_WITH_AES_256_CBC_SHA` 会得到一条死连接 |
| `X25519MLKEM768` 群及 1216 字节 key share | 不提供 | 未实现 ML-KEM |
| SHA-1 签名方案 | 不提供 | 明确拒绝 |
| `encrypt_then_mac` | 不发 | 只对 CBC 套件有意义，而 CBC 不提供 |
| `post_handshake_auth` | 不发 | 会招来握手后的 `CertificateRequest`，未实现 |
| — | `status_request` | curl 不索要 OCSP staple；本包必须要，因为 staple 是它唯一的吊销信号 |

要抹平这个差距，得先实现 ML-KEM、RSA 密钥交换和 CBC 套件——那是另一个项目，而且后两者是本包**故意**不做的。`tls.ciphers` 和 `tls.groups` 允许你照样把它们报出去；服务器一旦选中握手就会失败，后果由你自己承担。

有一个测试断言这张差异表**恰好**就是上面这些，所以哪天获得了其中某项能力却没更新这张表，构建会直接失败。

HTTP/1.1 的 body 有的，HTTP/2 的 body 全都保留：流式（SSE 原样可用）、trailer、gzip 解码、
以及在任何解码之前先包住原始 body 的 idle 截止线。结构上唯一不同的在水面之下——一条 h2 连接把
发往同一源站的所有并发请求复用在一起，而不是一次签出、一次只服务一个请求。`install()`、重定向、
cookie 与 `verify=` 的行为全部一致。

```js
const client = new Client({ connect, proxy: env.PROXY_URL });
const res = await client.fetch('https://example.org/', {
  headers: { 'user-agent': 'Mozilla/5.0 (…) Chrome/140.0.0.0 Safari/537.36' },
});
res.tunnelfetch.httpVersion; // 服务器选了 h2 就是 '2'，否则是 '1.1'
```

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
| `maxBodyBytes` | **`32 MiB`** | 在读入任何字节之前就按 `Content-Length` 强制执行,并在原始流和**解码后的输出**上各执行一次——包括你自己注册的解码器。传 `Infinity` 可以退出;见[关于这个默认值](#正文上限现在有默认值了)。 |
| `decompress` | `true` | 是否解码 `Content-Encoding`。gzip 与 deflate 内置。 |
| `decoders` | `{}` | 额外的编码，如 `{ br: fn }`；每一个都会被加进 `Accept-Encoding`。见 [`br`、`zstd`](#brzstd-与其它编码)。 |
| `keepAlive` | `true` | |
| `http2` | `true` | 在 ALPN 中报出 `h2`，服务器选中即使用。见 [HTTP/2](#http2--要的是访问不是速度)。 |
| `forceTunnel` | `false` | 永不委托给平台的 `fetch`。 |
| `nativeFetch` | `globalThis.fetch` | 委托目标。 |

`client.fetch(input, init)` 接受并返回平台的 `Request`/`Response`。响应上带有一个非标准的 `tunnelfetch` 属性，内容为 `{proxied, proxy, tls, httpVersion, framing}`。

`client.close()` 释放池中全部 socket。不关闭的 `Client` 会在 isolate 的整个生命周期里泄漏 socket。

#### 正文上限现在有默认值了

**`maxBodyBytes` 在 1.5.0 及以前默认是 `Infinity`,从 1.6.0 起是 32 MiB,这是一个破坏性变更**——下载超过
32 MiB 的内容现在需要显式设置 `maxBodyBytes`,压没压缩都一样,因为这个选项同时约束线上正文和解码后的正文。

理由是:在一个有硬性内存上限的运行时里,「不设限」不是自由,是一条被对端杀死的路径。53 字节的 brotli 正文解码出
32 MB,这是实测的,不是假想;而内置的 `br`/`zstd` 解码器自限在 256 MiB——**是 Workers isolate 那 128 MB 的
两倍**,所以那道兜底根本不可能在 isolate 死掉之前触发。一个存在意义就是去抓你控制不了的 URL 的客户端,不该把
「无上限」作为「没读过这张表就会拿到」的默认值。

32 MiB 是天花板的四分之一,所以即使被 `.arrayBuffer()` 整个缓冲到上限,isolate 也还有余量活下来并报告出来;
而它比任何页面或 API 响应都高两个数量级。如果你确实要搬大文件,就明说:

```js
new Client({ connect, proxy, maxBodyBytes: Infinity });   // 或者任何一个你想清楚了的数字
```

这个取舍是有意的:一个没被要求的上限,在第一次挡住你的时候是可发现的,而且错误信息里会点名那个选项;一次没被
要求的 OOM 两者都不是。

### Trust — `verify=` 旋钮

```js
{ mode: 'system' }                                  // bundled CCADB roots (default)
{ mode: 'anchors', anchors: [pemOrDer, ...] }       // exactly these, nothing else
{ mode: 'pinned', pins: ['sha256/BASE64...'] }      // full validation plus an SPKI pin set
{ mode: 'custom', verify: async (chain, host) => {} } // your policy; throw to reject
{ mode: 'none', insecureAcceptAnyCertificate: true } // no verification at all
```

吊销状态通过 **OCSP stapling**（RFC 6960，经 TLS `status_request` 扩展）检查：每个 hello 都请求服务器附上装订响应；收到的装订响应必须严格解析、与已验证证书的签发者和序列号匹配、签名经签发 CA 或其授权应答者验证通过、且处于新鲜度窗口之内——已验证的 `revoked`（以及 `unknown`）一律使连接失败。服务器**没有**装订时默认放行，因为大多数服务器不装订，硬性失败会弄断大半个网络；已知对端会装订的调用方可以强制要求：

```js
{ mode: 'system', revocation: 'require-staple' }    // 缺失即 OCSP_REQUIRED
```

刻意不存在任何能忽略 revoked 结论的配置值。

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
- **客户端证书（mTLS）、0-RTT、重协商。** `HelloRequest` 会被拒绝而不是照做。0-RTT 是决定而非遗漏:early data 可被重放，提供它等于让捕获了 POST 的攻击者可以重放它。（会话恢复本身**已经实现**——ticket 按池键保存，用 `psk_dhe_ke` 提供。）
- **吊销信息的主动获取（下载 CRL、查询 OCSP 应答者）。** 两者都要在握手中途经代理多跑网络往返，而且 OCSP 查询会把你访问的源站告诉 CA。吊销状态**会**从服务器装订（staple）的 OCSP 响应中校验（见上文 Trust 一节）；没有实现、也不打算实现的，是替服务器去取它没有装订的东西。
- **证书策略处理** (`policyConstraints`、`inhibitAnyPolicy`)。它们永远是 critical 的，所以一旦出现就直接拒绝，而不是被错误地校验过去。
- **dNSName 与 iPAddress 之外的名称约束。** 标为 *critical* 且指名不支持类型的约束扩展会被拒绝；非 critical 的则按 RFC 5280 允许的那样忽略。
- **cookie 的 public suffix list。** 只实现了“域名里没有点”这一道防护，所以 `Domain=com` 会被拒绝，`Domain=co.uk` 不会。如实写明，而不是伪造。
- **IDNA。** 请传 A-label (punycode)；非 ASCII 主机名会被拒绝，并附上说明原因的报错。
- **默认身份里的 `br` 与 `zstd`。** 运行时的 `DecompressionStream` 只接受 gzip、deflate 和 deflate-raw——这是实测的,不是假设的——所以两者都来自 WebAssembly,而默认入口一个都不带。导入 [`tunnelfetch/profile/chrome`](#一行-import-得到-chrome-身份) 就已经接好,或者用 [`decoders`](#brzstd-与其它编码) 注册你自己的。主入口不会做的事,是为一个大多数调用方永远遇不到的编码,把约 140 KB 的编译后 C 拉进每一个 bundle。

  不开它是安全的,而不是有损的:内容协商决定了服务器绝不会发送没被请求的编码,所以提供 Brotli 的源站只会返回 gzip。代价是带宽——同一个页面 gzip 是 290 KB、`br` 是 99 KB——而带宽恰恰不是这个平台计费的东西。在 CPU 上这笔交易是反着的:brotli 解码是原生 inflate 的 2.5 倍,而且压得越狠越亏不是越省,因为解压的工作量跟着**输出**字节走。开 `br` 的理由是让 `Accept-Encoding` 与浏览器一致,不是省 CPU。

- **流式请求体。** 请求体会先完整读入内存再发出：一是框定长度需要一个这个客户端敢于担保的 `Content-Length`，二是遇到重定向时可能需要重放。对 SDK 发的那点 JSON 完全够用；对大文件上传就不合适，也意味着不支持 `duplex: 'half'` 的流式上传。响应体则全程流式，任何时候都不会替你缓冲。
- **HTTP/3。** ALPN 报出的是 `h2` 与 `http/1.1`（见 [HTTP/2](#http2--要的是访问不是速度)）；不报 `h3`——那是跑在 UDP 上的 QUIC，从一个只暴露原始 TCP 的运行时根本够不着。服务器若选中客户端未曾报出的协议，一律 fail closed——任何一层都不存在回退重试。
- **服务器推送、HTTP/2 优先级与 h2c。** 推送在我们的 SETTINGS 里就是关闭的，收到 `PUSH_PROMISE` 即为连接错误；RFC 9113 的优先级机制已被废弃，PRIORITY 帧一律忽略；h2 只跑在 ALPN 协商出的 TLS 之上，绝不以“prior knowledge”走明文。

**socket 不能跨请求上下文。** 连接池按设计随 `Client`、随单次调用存在；不存在跨请求的连接缓存，因为运行时不允许有。

**并发。** 限制是**每次 Worker 调用**最多六条连接同时处于等待响应头的状态——不是每个 Worker，也不是每个账号，所以打到你 Worker 的不同请求各有各的六条。连接在响应头到达的那一刻就腾出槽位，所以它约束的是「同时能有多少次握手在飞」，而不是「同时能下载多少个 body」。想在一次调用内跑更高并行度的爬虫，必须在这个限额之内做流水线。

## 线上 Worker 的开销

下面每一个数字都是在 Cloudflare 边缘上用 `wrangler tail` 实测的，经过真实代理，并且按 isolate 分组统计——
所以首次执行绝不会和热态平均在一起。Workers 按 CPU 时间计费而不是墙钟时间，而这里一个请求的绝大部分时间
花在等网络上，那部分不计费。

### 一个请求要多少

通过代理抓取一个尺寸可控的源站，热态，同一 isolate 上 7 轮以上取中位数，传输走 gzip。最后一列是同样的数字
换算成速率，那是更值得随身记住的形式：

| Body | 5 页均摊 | 复用连接 | 新建连接 |
| --- | --- | --- | --- |
| 1 KB | 3.2 ms | 1.7 ms | 9.2 ms |
| 16 KB | 4.6 ms | 3.1 ms | 10.6 ms |
| 64 KB | 8.2 ms | 6.7 ms | 14.2 ms |
| 256 KB | 18.2 ms | 16.7 ms | 24.2 ms |
| 1 MB | 54.8 ms | 53.3 ms | 60.8 ms |
| 4 MB | 119.8 ms | 118.3 ms | 125.8 ms |

冷启动成本是**总数**,不是往上面某一行加的增量:

| 全新 isolate 的第一个请求 | 这个请求的成本 | 整条爬坡相对热态地板的超额 |
| --- | --- | --- |
| 不用 `warmup()` | **46 ms** | 61 ms(≈ 4.4 ms/请求,摊在 isolate 早期) |
| `warmup()` 一次 | 22 ms | 40 ms(≈ 2.8 ms/请求) |
| `warmup({ iterations: 5 })` | **16 ms** | 15 ms(≈ 1.1 ms/请求) |

这两个数字原先以「+46 ms」「+16 ms」的形式写在上面那张表里,**把总数变成了增量,让文档里的冷启动成本翻了一倍**。光靠这几个数就能证伪那个 `+`:如果首请求是 9.2 + 16,那它一个人就带了 16 ms 超额,而**整条**爬坡的超额总共才 15 ms。这些是在小正文上测的;冷 isolate 的第一个 4 MB 请求从未测过,而且必然更差——解码循环有多得多的字节跑在解释执行下。

经代理打一个尺寸可控的源站,每尺寸八轮,HTTP/2,线上走 gzip。连接项和每请求项是靠**改变复用次数**分离出来的,不是假设的——两页对十页得出**开连接 9.8 ms**、**每次后续请求 2.25 ms**,剩下的就是正文成本。

**这些数字替换掉了一批测错的,而错在哪里值得写下来。** 它们来自的那个源站重复的是一段 150 字节的 HTML 片段,gzip 把它压到 **220:1**——所以一个"1 MB 正文"在线上只有四千字节,针对它做的每一次测量都只量到了解压,而把 TLS 记录和流处理的**每线上字节**成本整个抹掉了。真实页面大约 4:1。现在源站重复的是 154 KiB 真实压缩后的 JavaScript,压缩比 2.76:1——gzip 的窗口是 32 KiB,这么大的重复周期压不掉。

**修正幅度很大。** 正文偏重的那几行是 1.4.0 及以前所写数字的**两到三倍**,而且再怎么讲究中位数还是最小值都发现不了——因为那些数字**自洽**,它们只是在回答错误的问题。

**右边两列请当作推算值来读,因为它们就是。** 只有「复用连接」那一列是逐尺寸实测的;「新建连接」是它加一个固定的 7.5 ms,「五种页面平均」是加 1.5 ms——这就是为什么在正文大小相差 4000 倍的范围内,两列的差值精确到小数点后一位都不变。而这个 7.5 ms 和紧挨着写的 9.8 ms 对不上;「每次后续请求 2.25 ms」又比 1 KB 复用请求的**全部**成本 1.7 ms 还大,照此推算 1 KB 的正文成本是负的。两者出自不同的扫描,把它们放在一起算,正是本文档反复告诫不要做的跨扫描比较。**把连接项当作 7–10 ms 之间的一个量,不要拿它做算术。**

这里原先还引了一次「独立印证」,它其实不是印证:从 CDN 抓一个真实的 3.6 MB 文件是 142 ms,而这张表对 4 MB 的预测是约 120 ms。那是模型**低估了约 20%**,方向和它刚刚替换掉的那个错误一致。它应当作为警告写在这里,而不是佐证。

还有两点。2.76:1 的内容比典型页面**略难压**,所以这些值偏保守而不是偏乐观;以及这个平台上 CPU 在不同 isolate 之间有最多约 1.5 倍波动,所以形状比任何单个数字更要紧。

### 这些折算成多少钱

Workers Standard 每月 $5，含 1000 万请求和 3000 万 CPU 毫秒，超出部分每百万请求 $0.30、每百万 CPU 毫秒
$0.02。把上面的实测代入，并把冷启动的影响单独列成两组列，这样任一负载「预热与否」的差别是看得见的：

| 工作负载 | CPU/请求 | 1000 万,冷 | 1000 万,预热 | 10 亿,冷 | 10 亿,预热 |
| --- | --- | --- | --- | --- | --- |
| 平台 `fetch`,16 KB —— 参照;它用不了代理 | 0.3 ms | $5.00 | $5.00 | $307.40 | $307.40 |
| 平台 `fetch`,4 MB —— 同一参照,实测 | 3.2 ms | $5.04 | $5.04 | $365.40 | $365.40 |
| 连接复用,16 KB 页面 | 3.1 ms | $5.90 | $5.24 | $451.20 | $385.20 |
| 每请求新建连接,16 KB | 10.6 ms | $7.41 | $6.75 | $602.20 | $536.20 |
| 连接复用,1 MB 页面 | 53.3 ms | $15.94 | $15.28 | $1455.20 | $1389.20 |
| 每请求新建连接,1 MB | 60.8 ms | $17.45 | $16.79 | $1606.20 | $1540.20 |
| 连接复用,4 MB 页面 | 118.3 ms | $28.94 | $28.28 | $2755.20 | $2689.20 |
| 每请求新建连接,4 MB | 125.8 ms | $30.45 | $29.79 | $2906.20 | $2840.20 |

参照那一行给了两个尺寸,因为平台自己的 `fetch` **不是平的**——它按每解压 MB 约 0.82 ms 增长,这是在同一个 CDN 的尺寸阶梯上测的,只有大小在变。把它写成单一的 0.3 ms 再拿去和 4 MB 那一行比,是拿不同的东西相比,而且是**抬高了对手而不是抬高本包**。

这些美元数字跟随上面修正后的 CPU 测量,所以正文偏重的行是 1.4.0 及以前的**两到三倍**。那不是包变慢了,是移除了一个内容压缩比 220:1 的源站。

#### Chrome 身份的每个选项各花多少

上面那张表是默认身份:线上 gzip、AES-256-GCM、x25519。Chrome 那一行把所有变化捆在一起,对做决定没什么用。按"连接复用 + 1 MB 页面 + 十亿请求/月 + 已预热"逐项拆开:

| 相对基线的变化 | CPU/请求 | 10 亿/月,已预热 | Δ | 何时才付 |
| --- | --- | --- | --- | --- |
| 基线 —— gzip、AES-256-GCM、x25519 | 53.3 ms | $1,389 | — | 总是 |
| 源站发 `br` 而不是 gzip | 57.6 ms | $1,474 | **+$85** | 源站选择发 `br` |
| 服务器选中 ChaCha20-Poly1305 | 56.3 ms | $1,448 | **+$59** | 服务器优先选它而非 AES |
| 源站发 `zstd` 而不是 gzip | 56.1 ms | $1,444 | **+$55** | 源站选择发 `zstd` |
| 协商 X25519MLKEM768,每连接 1 个请求 | 61.0 ms | $1,542 | **+$153** | 每次握手 |
| 协商 X25519MLKEM768,每连接 20 个请求 | 53.3 ms | $1,390 | **+$0.15** | 同一次握手,摊薄后 |

**最后两行是同样的 0.15 ms ML-KEM,差别完全来自连接复用**——这才是这张表最值得带走的一条。后量子密钥交换在你让 `Client` 活着时是这里最便宜的东西,在你不这么做时是最贵的,因为它是**每握手**,而其余全是每字节。

五项里有三项还是**有条件的,而且不由你决定**。`br` 和 `zstd` 在源站选择发它们之前一分不花;ChaCha20 在服务器优先选它而非 AES-GCM 之前也是——而有 AES 硬件加速的服务器通常不会。**报出去买的是指纹,付钱只在对端真的接受时发生。**

ChaCha20 那个数字是**内置的 WASM** AEAD 对它所替代的 WebCrypto AES-256-GCM 测的(4.89 对 1.95 ms/MB)。本节早先的版本写的是 +2.0 ms/MB,那是 `node:crypto` 的 ChaCha20——这个包并不走那条路,因为走它就要 `nodejs_compat`。

由此可以看出四件事。

**在每月一千万请求这个量级上,小页面免费,大页面不是。** 连接复用的 16 KB 负载落在基础费之内;连接复用的 1 MB 负载是每月 $15。这个量级上包含的 CPU 折合每请求 3.0 ms——16 KB 页面塞得进去,1 MB 页面塞不进去。

**到了十亿请求,每一行里有 $297 是请求费**,所有行都一样,这个包做什么都改变不了。剩下的只有 CPU,而在那里最大的杠杆**不是连接复用,是正文大小**:复用在 1 MB 页面上省 $151/月,而把抓取目标从 1 MB 页面换成 16 KB 页面省 $1,004。

**正文偏重的场景才是这套用户态栈真正要花钱的地方。** 连接复用且预热后,16 KB 页面上它比平台自己的 `fetch` 贵 25%($385 对 $307);1 MB 页面上是 **3.8 倍**($1,389 对 $365)——因为每一个字节都要在 JavaScript 里解密、重组、解压,而平台把这三件事都放在运行时里做,一分不计。**如果你的负载是大正文,该拿来做规划的是这个倍数,不是 16 KB 那个。**

那一行参照值是**实测的,不是假设的**,而且它并不是平的。从同一个 Worker 抓不同大小的真实页面,连接复用下的每请求边际成本:

| 页面 | 大小 | 平台 `fetch` | 本包(经代理) | 倍数 |
| --- | --- | --- | --- | --- |
| `example.com` | 0.6 KB | 0.2 ms | 3.8 ms | 12.8× |
| `news.ycombinator.com` | 35 KB | 0.3 ms | 1.8 ms | 5.5× |
| `www.wikipedia.org` | 118 KB | 0.5 ms | 1.5 ms | 3.0× |
| `github.com` | 591 KB | 2.0 ms | 14.0 ms | 7.0× |

平台的 `fetch` 同样随 body 大小增长——它不是恒定的一毫秒——因为它仍然要把 body 物化成 JS 值，那是两边都要付的
唯一一项每字节成本。它不付的是 TLS、HTTP 成帧和解压，这些都在运行时里完成，从不计入调用方的账单。这四行**有
噪声**：CPU 时间按 1 ms 粒度上报，而这些又都是小数值，所以倍数在 3× 和 13× 之间跳，并且不随大小单调（118 KB
那个页面测出来比 35 KB 那个还便宜）。方向是可信的；具体倍数不值得精确到小数点后一位。

**`warmup()` 在 Standard 上免费，在别处通常也划算。** 它自身的代价是启动 CPU，而 Workers Standard 不对启动
CPU 计费，所以十亿请求下「预热」两列省下的每月 $65 是净赚。在**会**对启动计费的形态上——比如动态 Worker
加载——那 22 ms 每个 isolate 只收一次，并摊给该 isolate 服务的请求：十亿请求、按这里实测的每 isolate 约 17.8
个请求算是每月 $25，对着省下的 $65。低于约每 isolate 7 个请求，它就不再回本。

### 成本在哪，不在哪

链验证的成本是验签，不是解析。解析整条链约 158 µs；而单次 ECDSA P-384 验签是 665–816 µs，约为 P-256 验签的
12 倍、RSA-2048 验签的 27 倍。典型 EC 链有两个 P-384 环节，所以**全 ECDSA 链验证约 3.5 ms，RSA 链约 0.8 ms**。
如果源站是你自己的，证书的密钥类型值得想一下。

小响应的解码成本由构造 `DecompressionStream` 主导，而不是字节数：一个 559 字节的 body 也要约 2 ms。这个固定
成本是真的，但本文档过去从它推出的建议——小 JSON 用 `decompress: false` 更划算——**对任何不算极小的响应都是反
的，而且当初根本没有和另一个选项对比着测过。**

这里的成本按**线上字节**走，不按解码后的字节走:每一个线上字节都要先被解密、重新组帧、跨 JS 流边界搬运，解压器
才看得见它。边上实测:收一个 4 MB 的**未压缩**正文，和收它 1.5 MB 的 gzip **再解压**，成本一样。关掉压缩，是
用省下的一次解压，换整条接收管道多走 2.7 倍的字节。**把压缩开着。** 那个固定的约 2 ms 只在正文小到一次线上读
就能读完时才划算。

### 和平台 `fetch` 的成本平价做不到，地板在这里

两次独立调查各自得出了这个结论，这是把它写得这么直白的主要原因。

`gz-native`——运行时自带的 `DecompressionStream` 把 1.5 MB gzip 解成 4 MB，用原生方式收集，**没有任何 JS
抽干、没有任何接收栈**——要 **16 ms**，五轮独立扫描都复现。而平台的整个 4 MB `fetch`，含 TLS、HTTP 和解压，
约 **3.6 ms**。

也就是说，这个包把那段 gzip 变成字节的**最便宜的可能方式**，已经是**平台整个请求的 4.4 倍**，而这还没碰到任何
一个 TLS 或 HTTP/2 字节。这个不对称和代码质量无关:**Cloudflare 对跑在你 isolate 里的 `DecompressionStream`
计费，对它自己 `fetch` 内部等价的 gunzip 不计费。** 用 JavaScript 写的任何东西都下不到一个被计费的原生地板
以下。

剩下的约 30 倍是 JS 编排的记录层、HTTP/2 解复用和流管道——在 4 MB 时约占每请求成本的 **80%，而解码占 20%**。
本节早先的版本把重点放在解码上，那是错的，它把优化精力引向了两者中较小的那个。

真正能补上这个差距的是一个不存在的原语:一个校验**源站**主机名、而不是校验 `connect()` 对端的 `startTls`，
有了它，平台自己的 `fetch` 就能在隧道里跑。那正是这整个包绕开的那块缺失，值得理解为**运行时的能力缺口，而不是
这里的性能 bug**。

大 body 的"每字节成本"其实不按字节计——按的是流边界穿越次数。这个运行时的 `DecompressionStream` 以
4096 字节为块产出输出，套接字单次交付也至多 4096 字节，而每一块在运行时与 JS 之间穿越一次都要几十微秒，
与块大小无关——实测约 **17 µs 一次穿越**，来自同一个 1 MB 分别按 4 KiB（6.0 ms/MB）到 256 KiB
（1.67 ms/MB）收集的阶梯。因此两条热路径都改为用 BYOB 读来抽干来源：它把已经缓冲的数据一次交付，且只要
有一个字节就立即以部分填充返回，流式延迟不变。

读进去的那个视图是 **16 KiB，而且这个尺寸是扫出来的，不是拍的**。它比看上去重要：输入由一个 JS 任务在与
拉取方相同的事件循环上泵送，所以读到达时解压器手上通常只压着一两块，读回来就是部分填充——实测一个 1 MB
body：**93 次读，93 次全是部分填充**，平均每次 11.3 KiB。于是 64 KiB 的视图为了搬 1 MB 数据要分配
**5.8 MB** 的一次性缓冲区。在边上扫，每 MB 解压输出的 CPU，五档在同一个 isolate 里交错跑：

| BYOB 视图 | 4 KiB | 8 KiB | **16 KiB** | 32 KiB | 64 KiB |
|---|---|---|---|---|---|
| 解码级 ms/MB | 19.33 | 16.00 | **13.00** | 15.33 | 17.67 |

干净的 U 形：太小付每次读的开销，太大付永远填不满的分配。原先那个 64 KiB 是从一个用原生 `pipeTo` 喂输入的
探针上选的——`pipeTo` 会跑在前面，**确实**能填满 64 KiB 视图（16 次读，没有一次部分填充）。而那是发布出去的
接线永远不会进入的工况。探针和产品说法不一致，当时信了探针。改过来之后解码级降了 **31%**，18.0 → 12.3
ms/MB，在同一个 isolate 里 A/B。

剩下的**并不**接近地板，本节早先的版本说它接近，那是错的。同样内容的原生 inflate 是 4.3 ms/MB，而这一级是
12.3，也就是说还有约 **8 ms/MB 是本包自己的管道**——JS 输入泵和输出包装。要压下去得重新设计，而不是改一个
常数；这是 body 路径上剩下的最大一项。

导入这个包是免费的。121 个内置锚是以主题 DN 哈希为索引的 base64 字符串，只有链实际落到的那一个会被解码，所以
380 KB 打包（gzip 后 133 KB）的启动时间保持在约 2 ms，而一个导入了但没使用本包的请求是 0 ms。

### 可选开关各自的成本

上面所有数字都是默认身份:curl 指纹、gzip 与 deflate、无后量子、无 GREASE。下面每个开关默认都关着,这张表是「打开它要付什么」。测法与其余部分一致——差分两个工作量、取样本最小值。

| 开关 | 成本 | 何时付 |
|---|---|---|
| `grease: true` | 测不出来 | 一次 hello 里多几个字节 |
| `tls.extensionOrder: 'shuffle'` | 测不出来 | 每次握手洗牌约 11 个元素 |
| `headerOrder` | 测不出来——有序列表比平台的 `Headers` **更快**(1.6 µs 对 3.8 µs) | 每请求 |
| `groups: { x25519mlkem768 }` | 用内置 WASM **+0.15 ms**,用纯 JS 的 ML-KEM **+1.35 ms** | **每连接**,不是每请求——复用该连接的所有请求共同摊薄 |
| `ciphers: { chacha20 }` | **+2.95 ms/MB**(内置 WASM AEAD 4.89 对 AES-GCM 1.95),而且只有服务器**选中**它时才付 | 每字节。有 AES 硬件加速的服务器通常偏好 AES-GCM,所以实际成本往往是零,真正起作用的是"出现在 offer 里" |
| `decoders: { br }` | **+4.4 ms/MB** | 每字节,只要源站发 brotli。压得越狠越亏:quality 11 线上小 16%,解码贵 46% |
| `profile: chrome` | 上面三项之和 | |

1.4.0 里有两个默认值变了,而它们都没有出现在上面那张表里:套件顺序对齐 curl 之后,原本协商 AES-128-GCM 的地方现在协商 AES-256-GCM,实测**贵 4%**(1.50 对 1.45 ms/MB——硬件 AES 让多出来的轮次很便宜);有序 header 列表取代了平台 `Headers`,反而**略微更便宜**。两者都落在上面数字本来就带的 ±1.5× 波动之内。

体积:`import 'tunnelfetch/profile/chrome'` 会为两个 WASM 原语增加约 **22 KB(gzip)**。没有其它地方引用它们,所以走默认身份的使用者一个字节都不背。

### 计划限制

付费计划上 30 秒的默认 CPU 上限不是约束点——那大约是一次调用里 3000 条连接或 1 GB 的 body，而"同时等待响应头
的连接最多六条"这个限制会远早于 CPU 触顶。

免费计划文档写的是每次调用 10 ms CPU，一条新连接（10–15 ms）正好压在这条线上或略高，而池化请求（2–4 ms）则
宽裕地装得下。实际上运行时容许偶发超限并会把没用完的预算结转，所以远超 10 ms 的单个请求确实能完成——实测有
几百毫秒的请求正常返回，运行时在约 2 秒处以 `exceededCpu` 终止。**但这并不等于证明了持续高于 10 ms 是可行的**，
因为那些探测是低速率、突发形状的，恰恰是这种宽容机制会放过的形状。如果你打算在免费计划上跑，请复用连接，并且
测量你自己的持续平均值，而不要相信文档上那个数字或突发行为中的任何一个。

## 运行时要求

WebCrypto (X25519、ECDH P-256/384/521、ECDSA、RSA-PSS、RSASSA-PKCS1、HKDF、HMAC、AES-GCM)、含 BYOB reader 的 WHATWG Streams、`TextEncoder`/`TextDecoder`、`DecompressionStream`、`URL`、`Headers`、`Request`、`Response`、`AbortSignal`、`btoa`。这些在 workerd 与 Node ≥ 22 上全部具备。唯一与具体运行时绑定的部分，是你自己提供的 `connect` 函数。

| 运行时 | 离线测试 | 说明 |
|---|---|---|
| Node 22、24 | **全部通过** | CI 把关的组合 |
| Node 20 | 不支持 | `TextDecoder` 把 `iso-8859-1` 当作真正的 ISO-8859-1，而没有按 WHATWG 要求别名到 windows-1252，该字符集的响应体解码结果不同。已于 2026 年 4 月结束维护 |
| workerd | live 边缘测试全过 | 目标运行时；由定时边缘任务端到端验证，不在离线套件里 |
| Deno 2.9 | 2 个失败 | 两个失败都落在 TLS 1.2 测试服务器的 secp521r1 路径上，不在包内；Deno 的 WebCrypto ECDSA 与 ECDH 在 P-521 上单独测试都正常。原因未定位，因此不宣称支持 |
| Bun 1.3 | 3 个失败 | 一个 repo-hygiene 测试的模块解析差异、一个对时序敏感的 deadline 测试，以及同一个 TLS 1.2 套件测试。原因未定位，因此不宣称支持 |

受支持的组合是 Node 22 与 workerd。Deno 和 Bun 已经非常接近可用，但没有进 CI——把这套测试在那两个运行时上跑通，是一个很好的首次贡献。

CI 会跑 `engines` 里声明的每一个版本，并且有一个 repo-hygiene 测试在两者不一致时直接失败——一个没人跑过的支持下限，是声称，不是事实。

## 测试

```bash
npm test          # offline, hermetic, no network
npm run test:live # explicit; needs TUNNELFETCH_PROXY in the environment
```

离线套件从不接触网络，而且这一点是被强制执行的：一套仓库卫生套件会让构建失败，只要任何测试文件写了可路由的主机名，`src/` 从 `node:` 导入，`src/` 里出现 URL、厂商名、`Math.random` 或 `console.*` 调用，或者 `src/` 下有任何模块没有测试。

每一个按字节消费输入的解析器都会过一遍 `underAllChunkings`：同一串字节分别以整块、逐字节、以及若干伪随机切分点的方式喂入，并断言所有跑法结果一致。在不同分块形状下表现不同的解析器，带着一个只在真实网络分片下才现身的 bug——而那正是那种无法凭报告复现的 bug。

TLS 密钥调度与记录层逐字节钉死在 **RFC 8448** "Example Handshake Traces for TLS 1.3" 上：AEAD 复现出 RFC 里一模一样的密文记录，记录层把 RFC 的完整线上字节在两个方向上原样重放。两个 TLS 驱动都对着独立编写的测试服务器测试——1.2 的服务器建在 `node:crypto` 上，而不是本包自己的原语上，这样客户端的 bug 就不可能被服务器端的同一个 bug 抵消掉。

每一个消费对端字节的解析器——TLS 记录层与握手消息、X.509、OCSP、HTTP/1.1 响应头、分块体、HTTP/2 帧、HPACK——都会被 fuzz，断言的属性只有一条：**任意输入，要么解析成功，要么抛出 `TunnelFetchError`。** 抛出未类型化的错误（少了空值检查的 `TypeError`、越界的 `RangeError`）就是一个发现：它意味着某处检查缺失，而所有依赖类型化契约来 fail closed 的调用方都接不住它。

fuzzer 自带种子、零依赖，失败时会打印种子、迭代序号和 base64 的输入——可以精确复现，而无法复现失败的 fuzzer 算不上 fuzzer。目标从 `test/fuzz/targets/` 自动发现，新增一个就是放一个文件进去。这套测试还会 fuzz **它自己**：两个合成目标分别证明引擎能报出未类型化的抛出、且不会误报类型化的抛出——否则一次全绿的 fuzz 只能证明 fuzzer 从来没睁眼。

```bash
FUZZ_ITERATIONS=1000000 node --test test/fuzz/fuzz.test.js   # 长跑
FUZZ_SEED=12345 node --test test/fuzz/fuzz.test.js           # 换一个角落
```

CI 每次提交跑固定种子，作为门禁；定时任务跑三百万次迭代、用 run id 作种子，那才是真正在搜索新地面的那一半。

`probe/` 存放一个可复现的能力探测，输出机器可读的 JSON；`probe/results/` 存放本设计所依据的测量结果。`live/` 是边缘互操作实测环境。

凭据只从环境读取。live 套件在未配置时会大声失败而不是跳过：一个意思是“我们没检查”的绿勾，比红叉更糟。

## 致谢

信任锚点派生自 Mozilla / Common CA Database (CCADB)，按 CDLA-Permissive-2.0 使用。用 `npm run roots:refresh` 重新生成；生成的模块会记录来源、获取日期、上游 SHA-256 与锚点数量——因为过期的根证书库是一个无声的可用性 bug，几个月后才以“TLS 随机失败”的面目浮出水面。

[`jawj/subtls`](https://github.com/jawj/subtls) (MIT) 是一个很有价值的概念验证，证明了在这类运行时上用 WebCrypto 跑 TLS 1.3 是可行的，编写本包时曾将其作为参考阅读。

## 许可证

MIT。
