# ruleset

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

## 是什么

供 Mihomo、OpenClash Smart 和 Surge 使用的分流规则，包含国内外 AI、网络测试和国内直连。仓库提供规则与接入片段，不含节点、订阅或完整客户端配置。

| 规则 | 用途 | 通常绑定 |
|---|---|---|
| `ai-cn` | 国内 AI 域名 | 直连组 |
| `ai-global` | 国外 AI 域名 | AI 代理组 |
| `network-test` | 测速、出口 IP 查询等 | 测试选择组 |
| `cn-direct` | 国内直连域名及平台规则 | 原国内直连组 |
| `ai-process` | Surge macOS 的 AI 进程兜底；iOS 忽略 | AI 代理组 |

规则来自 MetaCubeX、ChinaMax、Sukka 和经复核的 ACL4SSR 增量。GitHub Actions 每天北京时间 08:00 检查更新，校验通过后发布。来源与许可见 [第三方说明](THIRD_PARTY_NOTICES.md)，自写代码采用 [AGPL-3.0](LICENSE)。

## 怎么用

1. 按客户端打开示例：[Mihomo / OpenClash Smart](examples/mihomo.yaml) 或 [Surge](examples/surge.conf)。把片段合并到现有配置，将 `DIRECT`、`PROXY`、`TEST` 换成自己的策略组。
2. 保持规则顺序：本地例外 → 网络测试 → AI → 原广告、Apple、Microsoft、CDN、Telegram 等专用规则 → 国内直连 → LAN / IP / GEOIP。
3. 接入国内直连时，在原 Sukka `direct`、`domestic` 位置替换为下面三层，沿用原直连策略组。DNS 只引用域名层与特殊规则层，并保留原国内 DNS 服务器。

| 国内直连层 | Mihomo / Smart | Surge | 用于 DNS |
|---|---|---|---|
| 纯域名 | `rules/mihomo/cn-direct-domain.mrs` | `rules/surge/cn-direct.set` | 是 |
| 关键词、通配符 | `rules/mihomo/cn-direct-special.list` | `rules/surge/cn-direct-special.list` | 是 |
| 进程、平台规则 | `rules/mihomo/cn-direct-process.list` | `rules/surge/cn-direct-platform.list` | 否 |

示例使用 `main` 地址跟随更新，每 12 小时检查一次。首次切换建议把国内直连的全部路由和 DNS URL 中的 `main` 换成同一个完整 Git 提交 SHA，下载成功后一起启用；固定 SHA 不会自动跟随每日更新，升级时也需一起替换。Mihomo 的纯域名 MRS 使用 `behavior: domain, format: mrs`，其余 `.list` 使用 `behavior: classical, format: text`；Surge 的 `.set` 用 `DOMAIN-SET`，`.list` 用 `RULE-SET`。

需要修改规则、构建或排查更新时，查看 [维护说明](docs/maintenance.md)。
