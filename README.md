# ruleset

供 Mihomo、OpenClash Smart 和 Surge 共用的 AI、网络诊断和国内直连分流规则。仓库只维护规则、人工例外和更新逻辑，不包含节点、订阅或完整个人配置。

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

## 规则

| 文件 | 用途 | 来源 |
|---|---|---|
| [ai-cn.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-cn.list) | 国内 AI，通常绑定直连组 | MetaCubeX `category-ai-cn` |
| [ai-global.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-global.list) | 国外 AI，通常绑定 AI 代理组 | MetaCubeX `category-ai-!cn` + 人工补充 |
| [network-test.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/network-test.list) | 网络诊断、测速、出口 IP 查询，绑定测试组 | MetaCubeX `category-ip-geo-detect` + `category-speedtest` |
| [ai-process.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/surge/ai-process.list) | Surge 专用 AI 进程兜底（`PROCESS-NAME`），仅 macOS 生效、iOS 自动忽略；人工维护 | policy.json `surge_process_rules`（无上游） |
| `rules/mihomo/cn-direct-domain.mrs` / `cn-direct-domain.txt`；`rules/surge/cn-direct.set` | 国内直连纯域名；同时供路由与国内 DNS 使用 | ChinaMax Domain、Sukka direct/domestic、经复核的 ACL4SSR ChinaDomain 增量 |
| `rules/{mihomo,surge}/cn-direct-special.list` | 关键词和通配符；同时供路由与国内 DNS 使用 | Sukka direct/domestic |
| `rules/mihomo/cn-direct-process.list`；`rules/surge/cn-direct-platform.list` | 平台专用进程、Surge User-Agent 规则，仅用于路由 | 对应平台的 Sukka direct/domestic |

classical text 输出不含策略名。Surge 纯域名分类额外提供 domain-set 格式（`.set`），内部使用优化的域名查找结构：`rules/surge/ai-cn.set`、`rules/surge/network-test.set`。`ai-global` 含 `DOMAIN-WILDCARD`，仅提供 classical `RULE-SET`。`rules/surge/ai-process.list` 与这些纯域名 `.set` 性质不同：它是含 `PROCESS-NAME` 的 classical `RULE-SET`，只能在 Surge macOS 上使用（iOS 直接忽略进程规则），作为 AI 域名集之后的进程级兜底。

主要上游是 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `meta` 分支；每次更新固定到同一提交，再生成并校验全部输出。

## 接入

- Mihomo / OpenClash Smart：参考 [examples/mihomo.yaml](examples/mihomo.yaml)，使用 `behavior: classical, format: text` 的 `rule-providers`。
- Surge：参考 [examples/surge.conf](examples/surge.conf)，纯域名分类用 `DOMAIN-SET` 引用 `.set` 文件，含通配符的分类用 `RULE-SET` 引用 `.list`。
- 将 `ai-cn` 绑定直连组，`ai-global` 绑定 AI 代理组，`network-test` 绑定测试选择组（默认 US，可选 JP 和直连）。
- 规则顺序：network-test → AI → 广告/Apple/Microsoft/CDN 等通用规则。
- 示例每 12 小时检查更新；客户端需分别下载和缓存各规则文件。
- `cn-direct` 独立于国内 AI 的 `ai-cn`。用三层聚合规则替换原 Sukka `direct`、`domestic` 的域名规则，保持其原位置与原直连策略组；置于广告、AI、Apple/Microsoft/CDN、Telegram 等现有专用规则之后，LAN/IP/GEOIP 之前。不要把聚合规则移到专用规则前。
- DNS 引用 `cn-direct-domain` 与 `cn-direct-special`；进程和 User-Agent 层不参与 DNS。保留原国内 DNS 服务器和直连参数，其他 DNS 策略保持原顺序。
- Surge 大集合使用 `DOMAIN-SET`；关键词、通配符、进程、User-Agent 留在小型 `RULE-SET`。Surge 也会索引 RULE-SET 内的纯域名规则，不能把所有 RULE-SET 视为逐行扫描，或仅凭格式声称固定提速。
- 首次迁移应把路由与 DNS 的所有新 URL 固定到同一个完整 Git 提交 SHA，预取成功后一起切换。`main` 方便跟随每日更新，但客户端分别下载多个 URL，无法保证跨文件原子切换。

## 维护

只编辑 [policy.json](policy.json)，不要手改 `rules/` 生成文件。

- `adds`：永久人工补充，包括兼容入口和 `anthropic.services`。
- `removes`：从对应集合排除指定范围。
- `moves`：调整仍存在于上游的规则分类。
- `route_assertions`：构建时校验指定域名落入预期分类，新增分类需同步补充。
- `surge_process_rules`：Surge macOS 专用的 `PROCESS-NAME` 进程规则（人工维护、无上游）；改这里并附实证来源 `reference` 与 `review_date`，不要手改生成文件。
- `cn_direct`：国内直连的来源、类型白名单、ACL 增量复核、宽后缀复核、补充/排除、规模门槛与固定 MRS 转换器。人工复核按实际访问及来源意图判断，不按服务商国别排除；待审范围不自动成为直连规则。厂商特例不固化到聚合逻辑。

人工操作若与上游或另一分类冲突，构建会停止。规则命中只决定路由，不保证账号、地区或出口 IP 符合服务要求。

## 更新与验证

GitHub Actions 每天北京时间 08:00 检查上游，也支持手动运行。下载失败、格式异常、分类冲突或变化过大时不会覆盖最后一个可用版本。

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py update
python3 scripts/build.py validate --offline
```

`update` 生成并校验候选；`validate --offline` 使用仓库内快照重放。诊断写入 `.build-report/`，发布状态和来源记录在 `manifest.json`、`CHECKED_AT.json` 与 `upstream/provenance.json`。

国内直连使用 3 个上游项目、4 个逻辑集合、6 个实际输入文件：ChinaMax Domain、ACL4SSR ChinaDomain，以及 Sukka direct/domestic 的 Clash 与 Surge 版本。ChinaMax 和 ACL 每轮各固定一个 Git 提交；Sukka 同轮获取四个官方发布文件，记录各自哈希与头部信息，不声称它们来自同一个 Git 提交。六份原文保存在 `upstream/cn-direct/`，全部输出、来源、转换器身份和审查决定纳入同一发布清单。固定的 Public Suffix List 快照仅作为构建验证资源，用来拦截新增的公共/托管后缀和父域扩张，不增加分流来源计数；初版完整宽范围名单随六源哈希一并审核。

MRS 构建需要 `MIHOMO_CONVERTER` 指向 policy 允许的 Mihomo v1.19.17 二进制；Actions 下载官方固定资产并核验 SHA-256。离线重放默认要求原发布平台。显式指定 `validate --offline --allow-cross-platform-replay` 时，必须先使用另一允许平台的转换器，逐字节重现全部七个输出，才接受跨平台重放；本次执行身份留在诊断证据中，原发布记录不被改写。PR 在 Ubuntu 上执行此检查后才能合并。源下载、语法、规模、审查或重放失败时不推送新的 bundle。工作目录写入只对可捕获异常尝试回滚；进程被杀或断电后必须从干净 Git 基线重建，不把残留目录视为已验证发布。远端发布以单个完整 Git 提交为单位。

回滚时恢复代码、policy、全部生成文件和清单，并启用 `publish_hold`，避免自动更新立即覆盖回滚结果；客户端需同步恢复路由与 DNS 两处引用。

## 许可

自写代码采用 [AGPL-3.0](LICENSE)。第三方材料的许可和归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
