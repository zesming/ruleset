# ruleset

供 Mihomo、OpenClash Smart 和 Surge 共用的 AI 域名分流规则。仓库只维护规则、人工例外和更新逻辑，不包含节点、订阅或完整个人配置。

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

## 规则

| 文件 | 用途 | 来源 |
|---|---|---|
| [ai-cn.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-cn.list) | 国内 AI，通常绑定直连组 | MetaCubeX `category-ai-cn` |
| [ai-global.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-global.list) | 国外 AI，通常绑定 AI 代理组 | MetaCubeX `category-ai-!cn` + 人工补充 |

两份文件均为不含策略名的 classical text。主要上游是 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `meta` 分支；每次更新固定到同一提交，再生成并校验两份输出。

## 接入

- Mihomo / OpenClash Smart：参考 [examples/mihomo.yaml](examples/mihomo.yaml)。
- Surge：参考 [examples/surge.conf](examples/surge.conf)。
- 将 `ai-cn.list` 绑定直连组，`ai-global.list` 绑定 AI 代理组。
- AI 规则应放在广告、Apple、Microsoft、CDN 等通用规则之前。
- 示例每 12 小时检查更新；客户端需分别下载和缓存两份规则。

## 维护

只编辑 [policy.json](policy.json)，不要手改 `rules/` 生成文件。

- `adds`：永久人工补充，包括兼容入口和 `anthropic.services`。
- `removes`：从两个 AI 集合排除指定范围。
- `moves`：调整仍存在于上游的规则分类。

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
