# dsh-cookie-guard

仓库：<https://github.com/bigfatdsh/dsh-cookie-guard> · MIT

修复 DSH 登录 Cookie 只增不清、最终把请求头撑爆导致 Web UI 永久打不开的宿主机插件。

## 问题

DSH 的浏览器认证 Cookie 名是：

```text
dsh-auth-<sha256(host:port) 的 base64url>
```

桌面端每次启动通常换一个新端口，于是每次启动都会在浏览器里多写一条名字不同的
`dsh-auth-*` Cookie；旧 Cookie 有 30 天有效期，DSH 从不删除它们。浏览器会把
同一 host 下的所有 Cookie 都塞进 `Cookie` 请求头，累计到 Node 默认的 16 KiB
`maxHeaderSize` 后，服务器在进入任何业务代码之前就直接返回 `431 Request Header
Fields Too Large`。此时清理逻辑也没有机会执行，所以表现为“永久打不开”。

本机实测（修复前）：

```text
GET /  Cookie: big=<20 KB>  ->  431 Request Header Fields Too Large
```

## 修复效果

插件安装到当前 desktop profile 后，在同一台正在运行的 GUI 上实测：

| 场景 | 修复前 | 修复后 |
| --- | --- | --- |
| 20 KB 无效 Cookie | 431 | 401（正常进入认证） |
| 20,746 B Cookie，90 条旧登录 Cookie | 431 | 200，返回 87 条删除指令 |
| 34,426 B Cookie，150 条旧登录 Cookie | 431 | 200，返回 147 条删除指令 |
| 当前实例的有效 Cookie | 200 | 200，且不会被删除 |

34 KB 那次响应里，当前 Cookie 没有被误删，另外 147 条旧 Cookie 均带
`Max-Age=0` 的删除头。请求头从 34 KB 降到约 1 KB。

## 从 GitHub 安装

```bash
dsh plugin add https://github.com/bigfatdsh/dsh-cookie-guard
```

## 已安装

当前 `desktop` profile 已通过插件管理器安装：

- 依赖：`dsh-cookie-guard: link:.../adapted/dsh-cookie-guard`
- bundle：`dsh.profile.bundles` 中的 `dsh-cookie-guard`
- 插件 id：`cookie-guard`

插件是 `link:` 软链，修改本目录源码后重启 DSH 即生效。

其他 profile（例如 `web`）需要手动安装：

```bash
cd ~/.dsh/profiles/web
pnpm add link:/Users/yangletian/Documents/deepseek-harness/default-workspace/adapted/dsh-cookie-guard
```

然后把 `"dsh-cookie-guard"` 加进该 profile `package.json` 的
`dsh.profile.bundles` 数组，重启 DSH。

## 配置

在 bundle 的 `cordis.patch.yml`（或 profile patch）里覆盖：

```yaml
- insert:
    - id: cookie-guard
      name: dsh-cookie-guard
      config:
        maxHeaderBytes: 262144
        keepOtherCookies: 3
        cookieBudgetBytes: 4096
```

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `maxHeaderBytes` | `262144` | 监听器的 `maxHeaderSize`。必须大于 16 KiB，旧请求才进得来。范围 16 KiB–1 MiB。 |
| `keepOtherCookies` | `3` | 除当前实例外，最多保留几条其它端口/实例的有效 Cookie。用于 DSH 多开。范围 0–8。 |
| `cookieBudgetBytes` | `4096` | 认证 Cookie 的预算；超过时从最旧的开始删。范围 256 B–16 KiB。 |

只跑一个实例、想更激进，可设 `keepOtherCookies: 0`，这样除当前 Cookie 外全部删除。
代价是同时开着的另一个 DSH 窗口下次请求会掉登录，需要重新打开它的 token URL。

## 原理

插件在 `webServer` 的请求监听器最前面插入一个处理器（`prependListener`）：

1. 把 `server.maxHeaderSize` 提高到 256 KiB。已经 34 KB 的请求也能进入 JS 处理器，
   而不是被 Node 在 16 KiB 处直接 431。
2. 用与 DSH 完全相同的算法算出当前 authority 的 Cookie 名，把其它
   `dsh-auth-*` 从 `req.headers.cookie` 里剥掉；DSH 的认证代码只会看到当前 Cookie。
3. 对判定为过期、签名无效、或超出“当前 + 3 条最近”预算的 Cookie，在响应里追加
   `Set-Cookie: <name>=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`。
4. 响应头的注入兼容 `writeHead`、`setHeader`、隐式 `end()` 三种写法，不会覆盖
   DSH 自己刚签发的 Cookie。

保留最近 3 条其它 Cookie 是为了多开：A 实例清理时不会立刻把 B 实例的登录态删掉。
最旧的会在下一次启动时被裁掉，所以总量稳定在“当前 + 3”，不会再无限增长。

## 验证

单元测试（22 项，覆盖 34 KB 请求、100 条旧 Cookie、过期/篡改/预算/多实例/303 签发/401）：

```bash
cd adapted/dsh-cookie-guard
node --test
```

对运行中的 GUI 做一次无副作用的头部探测：

```bash
python3 - <<'PY'
import urllib.request, urllib.error
req = urllib.request.Request(
    "http://127.0.0.1:51302/",
    headers={"Cookie": "big=" + "a" * 20000},
)
try:
    print(urllib.request.urlopen(req, timeout=5).status)
except urllib.error.HTTPError as e:
    print(e.code, e.reason)
PY
```

修复后应输出 `401 Unauthorized`；修复前是 `431 Request Header Fields Too Large`。

## 边界

- 删除依赖浏览器执行标准 `Set-Cookie` 过期语义。所有主流浏览器都支持；即使某个
  浏览器不执行删除，256 KiB 的头部上限也会让 UI 继续可用，旧 Cookie 最迟 30 天过期。
- 如果历史 Cookie 已经超过 256 KiB，浏览器自身通常也发不出这么大的请求头。先把
  `maxHeaderBytes` 调到 `1048576` 再重启；仍不行时在浏览器 DevTools 里清一次
  `127.0.0.1` 的站点 Cookie 即可恢复，之后插件会接管。
- 插件不修改 DSH 源码，不依赖第三方包；DSH 升级后只要
  `dsh-client-connection` 的 Cookie 命名算法不变就继续有效。如果上游改成稳定
  Cookie 名，本插件会自动变成“只做头部上限与旧 Cookie 清理”的保险层，不会冲突。

## 回滚

```bash
# 用插件管理器移除 bundle，或手动：
cd ~/.dsh/profiles/desktop
# 从 package.json 删除 dsh-cookie-guard 依赖和 bundles 条目
pnpm install
# 重启 DSH
```

移除后 16 KiB 的 Node 默认上限会恢复，旧问题也会回来。
