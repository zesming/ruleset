# ruleset

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

## 是什么

供 Mihomo、OpenClash 和 Surge 使用的分流规则。个人策略将业务分类组合为有序规则：默认 US、明确直连 DIRECT、明确日本业务 JP、拦截 REJECT。JP 初始为空，不启用全局日本 GeoIP 分流。仓库提供规则和不含节点凭据的接入片段，保留原有 AI、网络测试、固定 US 和国内直连接口。

个人策略定义在 `profiles/us-primary.json`，客户端资源位于 `rules/personal/`，原始输入与发布清单位于 `upstream/personal/`。业务成员与策略映射在远端维护；节点、内网、DNS 服务器和网络接管方式仍由客户端管理。四种出口对应多个有序聚合，保留 AI、拦截、下载、CDN 与通用直连之间的优先级。

| 规则 | 用途 | 通常绑定 |
|---|---|---|
| `ai-cn` | 直连 AI 域名 | 直连组 |
| `ai-global` | 代理 AI 域名 | AI 代理组 |
| `network-test` | 测速、出口 IP 查询等 | 测试选择组 |
| `us` | 人工复核、固定走美国出口的精确域名 | 独立美国出口组（需支持所需 UDP） |
| `cn-direct` | 国内直连域名及平台规则 | 原国内直连组 |
| `ai-process` | Surge macOS 的 AI 进程兜底；iOS 忽略 | AI 代理组 |

规则来自 MetaCubeX、ChinaMax、Sukka 和经复核的 ACL4SSR 增量。GitHub Actions 每天北京时间 08:00 检查更新，校验通过后发布。来源与许可见 [第三方说明](THIRD_PARTY_NOTICES.md)，自写代码采用 [AGPL-3.0](LICENSE)。

`us` 独立于 Meta 的 `network-test` 与 AI 分类，由 `policy.json` 中的人工规则生成。当前仅匹配 `sentitlement2.mobile.att.net`、`epdg.epc.att.net` 和本机抓包观察到的 CNAME `epdg.epc.att-idns.net`。AT&T 文档作一般背景参考，本机抓包记录主机与别名观察；这些依据不保证通话成功。规则只选择路由，客户端需单独维护所需的真实 DNS，并绑定支持所需 UDP 的美国出口策略。

构建时，若一个 `ai-global` 纯域名规则的完整范围被一个已接受、已排除删除项、且不是单标签或公共后缀的 `cn-direct` 域名规则覆盖，它会被归入 `ai-cn` 的直连路由分类。ACL 域名只有在 `acl_review` 中显式标记为 `accept` 后，才可作为自动分类证据；即使 ACL 项因宽泛 base 规则而在 cn-direct 合并输出中冗余保留，`candidate`、`reject` 和未审条目也不会提供窄范围证据。显式的全局 `adds` / `moves` 优先；部分重叠保留原分类并写入清单审计。待审 ACL、关键词、通配符、进程、IP 和 PSL 本身都不作为自动归类证据；`network-test` 始终保留 TEST，`ai-cn` 也不会因直连重叠而改类。该分类只表达规则的路由选择，不判断服务商国籍、账号可用地区或产品能力。证据变化时，每次构建都会重新分类，并由既有输出变化与数量检查把关。

规则类别和客户端文件名 `ai-cn`、`ai-global` 为兼容既有配置而保留；它们表示直连或代理路由，不表示来源的地理分类。

## 怎么用

个人完整策略使用 [Mihomo / OpenClash 片段](examples/personal-mihomo.yaml) 或 [Surge 片段](examples/personal-surge.conf)。在客户端定义 `US`、`JP`、`TEST` 策略，合并片段中的规则和 DNS 配置；保留节点、内网和客户端接管设置。遵循片段顺序，JP 首版为空，未命中业务仍走 US。两个国家的出口分别管理，不使用跨国自动切换。

只接入原有独立分类时，使用以下兼容接口：

1. 按客户端打开示例：[Mihomo / OpenClash Smart](examples/mihomo.yaml) 或 [Surge](examples/surge.conf)。把片段合并到现有配置，将 `DIRECT`、`PROXY`、`TEST` 换成自己的策略组。
2. 保持规则顺序：本地与基础设施例外 → `us` → 网络测试 → AI → 原广告、Apple、Microsoft、CDN、Telegram 等专用规则 → 国内直连 → LAN / IP / GEOIP。`us` 应绑定独立的美国出口策略；示例不提供节点。
3. 接入国内直连时，在原 Sukka `direct`、`domestic` 位置替换为下面三层，沿用原直连策略组。DNS 只引用域名层与特殊规则层，并保留原国内 DNS 服务器。

| 国内直连层 | Mihomo / Smart | Surge | 用于 DNS |
|---|---|---|---|
| 纯域名 | `rules/mihomo/cn-direct-domain.mrs` | `rules/surge/cn-direct.set` | 是 |
| 关键词、通配符 | `rules/mihomo/cn-direct-special.list` | `rules/surge/cn-direct-special.list` | 是 |
| 进程、平台规则 | `rules/mihomo/cn-direct-process.list` | `rules/surge/cn-direct-platform.list` | 否 |

示例使用 `main` 地址跟随更新，每 12 小时检查一次。每次发布的全部文件来自同一个 Git 提交；客户端分别刷新多个 URL 时，短时间内可能读到不同发布版本。Mihomo 的纯域名 MRS 使用 `behavior: domain, format: mrs`，其余 `.list` 使用 `behavior: classical, format: text`；Surge 的 `.set` 用 `DOMAIN-SET`，`.list` 用 `RULE-SET`。

需要修改规则、构建或排查更新时，查看 [维护说明](docs/maintenance.md)；迁移范围与验证边界见 [分流和 DNS 对照](docs/personal-routing-comparison.md)。
