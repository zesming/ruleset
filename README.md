# ruleset

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

供 Mihomo、OpenClash 和 Surge 使用的分流规则，默认 US，直连走 DIRECT，日本业务走 JP，拦截走 REJECT。JP 业务集合当前为空。

| 目录 / 文件 | 内容 |
|---|---|
| `rules/personal/{mihomo,surge}/route/` | 客户端聚合规则，如 `us-proxy`、`jp-proxy`、`cn-direct`、`reject`、`test`；接入片段只引用这里，新接入请使用 |
| `rules/personal/{mihomo,surge}/` 下其余文件 | 按来源阶段平铺的个人细分文件，作为兼容接口保留并随每日更新，不是推荐入口 |
| `rules/` | 细分类规则 |
| `profiles/us-primary.json` | 个人分流顺序与聚合定义 |
| `policy.json` | 人工规则与复核决定；`direct_rules` 合入直连并从 Test 排除 |
| `upstream/` | 来源快照、清单与内容哈希 |

接入片段：[Mihomo / OpenClash](examples/personal-mihomo.yaml)、[Surge](examples/personal-surge.conf)。细分类示例：[Mihomo](examples/mihomo.yaml)、[Surge](examples/surge.conf)。

GitHub Actions 每天北京时间 08:00 检查上游，校验通过后发布。维护方法见[维护说明](docs/maintenance.md)，分流与 DNS 行为见[配置说明](docs/personal-routing-comparison.md)。

来源与许可见[第三方说明](THIRD_PARTY_NOTICES.md)，自写代码采用 [AGPL-3.0](LICENSE)。
