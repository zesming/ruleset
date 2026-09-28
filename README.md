# ruleset

供 Mihomo、OpenClash Smart 和 Surge 共用的 AI 域名分流规则。仓库只维护规则、人工例外和更新逻辑，不包含节点、订阅或完整个人配置。

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

## 规则

| 文件 | 用途 | 来源 |
|---|---|---|
| [ai-cn.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-cn.list) | 国内 AI，通常绑定直连组 | MetaCubeX `category-ai-cn` |
| [ai-global.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-global.list) | 国外 AI，通常绑定 AI 代理组 | MetaCubeX `category-ai-!cn` + 人工补充 |
| [network-test.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/network-test.list) | 网络诊断、测速、出口 IP 查询，绑定测试组 | MetaCubeX `category-ip-geo-detect` + `category-speedtest` |

classical text 输出不含策略名。Surge 纯域名分类额外提供 domain-set 格式（`.set`），内部使用优化的域名查找结构：`rules/surge/ai-cn.set`、`rules/surge/network-test.set`。`ai-global` 含 `DOMAIN-WILDCARD`，仅提供 classical `RULE-SET`。

主要上游是 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `meta` 分支；每次更新固定到同一提交，再生成并校验全部输出。

## 接入

- Mihomo / OpenClash Smart：参考 [examples/mihomo.yaml](examples/mihomo.yaml)，使用 `behavior: classical, format: text` 的 `rule-providers`。
- Surge：参考 [examples/surge.conf](examples/surge.conf)，纯域名分类用 `DOMAIN-SET` 引用 `.set` 文件，含通配符的分类用 `RULE-SET` 引用 `.list`。
- 将 `ai-cn` 绑定直连组，`ai-global` 绑定 AI 代理组，`network-test` 绑定测试选择组（默认 US，可选 JP 和直连）。
- 规则顺序：network-test → AI → 广告/Apple/Microsoft/CDN 等通用规则。
- 示例每 12 小时检查更新；客户端需分别下载和缓存各规则文件。

## 维护

只编辑 [policy.json](policy.json)，不要手改 `rules/` 生成文件。

- `adds`：永久人工补充，包括兼容入口和 `anthropic.services`。
- `removes`：从对应集合排除指定范围。
- `moves`：调整仍存在于上游的规则分类。
- `route_assertions`：构建时校验指定域名落入预期分类，新增分类需同步补充。

人工操作若与上游或另一分类冲突，构建会停止。规则命中只决定路由，不保证账号、地区或出口 IP 符合服务要求。

## 更新与验证

GitHub Actions 每天北京时间 08:00 检查上游，也支持手动运行。下载失败、格式异常、分类冲突或变化过大时不会覆盖最后一个可用版本。

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py update
python3 scripts/build.py validate --offline
```

`update` 生成并校验候选；`validate --offline` 使用仓库内快照重放。诊断写入 `.build-report/`，发布状态和来源记录在 `manifest.json`、`CHECKED_AT.json` 与 `upstream/provenance.json`。

## 许可

自写代码采用 [AGPL-3.0](LICENSE)。第三方材料的许可和归属见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
