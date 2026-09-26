# ruleset

供 Mihomo、OpenClash Smart 和 Surge 共用的分流规则。仓库集中维护规则、人工例外和更新逻辑，不包含节点、订阅、密码或完整个人配置。后续其他分类可以继续放在这个仓库。

[![Update ruleset](https://github.com/zesming/ruleset/actions/workflows/update.yml/badge.svg)](https://github.com/zesming/ruleset/actions/workflows/update.yml)

## 当前规则

| 文件 | 默认用途 | 更新来源 |
|---|---|---|
| [ai-cn.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-cn.list) | 国内 AI，绑定直连组 | MetaCubeX 完整 `category-ai-cn` |
| [ai-global.list](https://raw.githubusercontent.com/zesming/ruleset/main/rules/ai-global.list) | 国外 AI，绑定 AI 代理组 | MetaCubeX 完整 `category-ai-!cn` + 少量人工兼容入口 |

两份文件都是不含策略名的 classical text，三个客户端共用。分类按具体域名区分，同一品牌的国内、海外服务可能分别归类。规则命中代理不保证服务地区、账号或出口 IP 符合厂商要求。

主要来源是 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `meta` 分支、`geo/geosite/classical/` 路径。每轮先解析唯一提交号，再获取同一版本的两份文件。本库保留原文及版本记录，即使上游强推后旧提交消失，仍可离线重放。

## 接入

- Mihomo / Smart：使用 [examples/mihomo.yaml](examples/mihomo.yaml) 中的 `http`、`classical`、`text` provider。旧版 Clash 核心不在支持范围。
- Surge：使用 [examples/surge.conf](examples/surge.conf) 中的两条 `RULE-SET`。
- 将国内集合绑定现有直连组、国外集合绑定现有 AI 代理组；引用放在本地网络例外之后、广告/Apple/Microsoft/CDN 等通用域名规则之前。
- 替换原 AI **域名**集合和重复的内联补丁；Apple Intelligence、语音/IP 等独立规则仍可保留。不要让旧域名集合在后面重新捕获已从本仓库排除的域名。
- 示例每 12 小时检查更新。初次接入先确认两个地址均能下载；服务端保留旧版不等于新客户端已有缓存。

两个地址分别下载、分别缓存。仓库一次提交不能保证所有客户端同时切换；跨类别调整后应刷新两份并核对命中。普通日更允许逐步更新。

迁移采用完整 AI 分类，覆盖范围比原有 62 条国外、8 条国内手工补充更广。Sukka 中的 `ai.com`、`g.ai`、`api.github.com` 和 `cloudcode-pa.googleapis.com` 保留原来的精确/后缀匹配方式作为人工例外；不继承署名规则、`openai` 与 `alkalimakersuite` 两条宽泛关键词，也不继承需要 MITM 的 Surge URL 正则。迁移不是对每条旧规则行为的完全复制。

## 日常维护

只编辑 [policy.json](policy.json)，不要手改 `rules/` 生成文件。

- `adds`：永久人工补充，附理由及来源。目前仅保留七条兼容入口；其中 `api.github.com` 是整个 GitHub API 主机，也会影响非 Copilot 请求。
- `removes`：从本项目两个 AI 域名集合排除。之后仍可能命中其他 AI IP、Apple Intelligence 或普通代理规则，不等于强制直连。
- `moves`：把**当前上游仍存在**的所选规则改到指定类别，保留原匹配范围。上游删除后不会被它永久补回；永久保留须显式 `adds`。

子域仍被更大的后缀或通配规则覆盖时，删除/移动会失败，不能假装已排除。应调整整个父范围、请上游细分，或使用客户端前置例外。人工意图重叠、国内外冲突和未批准的分类迁移都阻止发布。

国内外标签描述默认路由选择，并非按厂商国籍自动判断。

## 更新与失败处理

GitHub Actions 计划每天 **北京时间 08:00（UTC 00:00）**运行，也支持在 [Actions](https://github.com/zesming/ruleset/actions/workflows/update.yml) 手动运行。政策、脚本或测试变更会触发重建。定时运行可能受 GitHub 排队影响而延迟；公共仓库长期无活动可能停用，不保证准点。

每轮检查来源、语法、核心服务样例、域名边界、国内外冲突和增删幅度。初始门槛按每个源集合和输出集合分别计算：新增超过 `max(10, ceil(20% × 原数量))` 或删除超过 `max(5, ceil(10% × 原数量))` 暂停该候选。新增和删除分开计算，不能用净数量掩盖替换。

下载失败、空文件、HTML、未知类型/正则、大幅变化或发布竞争时，线上保持最后好版本；诊断保留 14 天。正常小变化自动发布，无需每天批准。数量例外只能批准一个稳定候选身份，不能越过格式、冲突、分类政策或暂停开关。

上游只有已登记的 Azure ChatGPT 正则可转为通配规则：`chatgpt-async-webps-prod-*-*.webpubsub.azure.com`。通配比原正则稍宽：星号可为空、跨点且不限数字；这一差异有明确测试。新正则或旧正则改写会失败，绝不静默丢弃。原始规则消失时，其转换产物也消失。

一次正常发布包含两份输出、两份原文、来源记录和 manifest。输入变化但输出相同时，只更新来源基线，规则文件不制造时间戳变化。整个发布包无变化时，每 30 天记录一次真实成功检查；失败不记成成功。超过 48 小时没有成功检查，应查看 Actions；如定时任务被平台停用，需手动恢复。

## 本地检查

只需要 Python 3.11+ 和 Git，无第三方 Python 依赖：

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build.py update
python3 scripts/build.py validate --offline
```

`update` 联网生成候选，通过检查后写入完整发布包，但不会自动提交或推送。`validate --offline` 使用本地归档输入，不向上游补取旧版本。详细参数见 `python3 scripts/build.py --help`。

`.build-report/` 是本地/Actions 诊断目录，不进入 Git。`manifest.json` 与 `upstream/provenance.json` 记录已接受输入，Git 历史保留先前版本。不要浅克隆后声称完整历史可以离线重放。

## 回滚

回滚必须在**同一提交**中恢复已验证版本的 `rules/`、`upstream/`、`licenses/`、`manifest.json`、对应 `scripts/`、`tests/`、`policy.json`，然后将 `publish_hold.enabled` 设为 `true`，记录原因与回滚版本，并清空 `quantity_approvals`。用新提交恢复，不重写仓库历史。

所有更新入口都遵守暂停开关。暂停时可检查候选和报告差异，但不能替换线上发布包；检查状态明确标为未发布。修复后显式解除暂停，再从当前源完整验证；解除暂停本身不批准旧候选。发布还会检查 main 是否已改变，防止正在运行的旧任务覆盖回滚或人工修改。

## 来源与许可

自写代码采用 [AGPL-3.0](LICENSE)。第三方材料保留各自原许可、归属与修改说明，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。原始快照中的上游说明不删除，不把聚合数据标成全部原创。
