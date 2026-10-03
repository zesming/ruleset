# 维护说明

## 是什么

`policy.json` 管理人工补充和复核决定；`scripts/` 抓取、生成和验证规则；`tests/` 验证解析与发布行为。`rules/` 是供客户端下载的生成文件，`upstream/` 保存原始输入及来源记录。

| 文件或目录 | 内容 |
|---|---|
| `policy.json` | 人工补充、排除、分类调整、复核与发布开关 |
| `rules/` | 已发布的客户端规则 |
| `upstream/` | 未修改的输入快照及 `provenance.json` 来源记录 |
| `manifest.json` | 发布身份、规则清单与内容哈希 |
| `CHECKED_AT.json` | 最近一次成功检查的状态 |
| `.build-report/` | 本地运行诊断；不提交到 Git，可在检查结束后删除 |
| `examples/` | 客户端接入片段 |
| `licenses/` | 第三方许可原文 |

AI 和网络测试来自 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 的 `meta` 分支，每轮固定到一个提交。

国内直连聚合 3 个上游项目、4 个逻辑集合、6 个实际输入：ChinaMax Domain、ACL4SSR ChinaDomain，以及 Sukka direct/domestic 的 Clash、Surge 版本。ChinaMax 和 ACL 各固定一个 Git 提交；Sukka 的四份官方发布文件分别记录哈希和头部信息。原文保存在 `upstream/cn-direct/`，域名跨平台合并，平台表达式分别输出；ACL 待审增量不进入直连规则。

固定的 Public Suffix List 仅用于检测公共/托管后缀和父域扩张，不是分流来源。初版宽范围名单与六份来源哈希一起审核；后续新增范围仍须复核。格式选择不代表固定提速：Surge 会索引 `DOMAIN-SET` 和 `RULE-SET` 中的纯域名。

## 怎么用

### 修改规则

编辑 [policy.json](../policy.json)，不要手改 `rules/`。常用字段：

| 字段 | 操作 |
|---|---|
| `adds` / `removes` | 补充或排除规则范围 |
| `moves` | 调整仍存在于上游的规则分类 |
| `route_assertions` | 校验指定域名的预期分类 |
| `surge_process_rules` | 维护 Surge macOS 的 AI 进程兜底，附 `reference` 与 `review_date` |
| `cn_direct` | 国内直连来源、类型白名单、ACL 增量、宽后缀复核、补充/排除与规模门槛 |
| `quantity_approvals` | 按完整候选身份批准需人工复核的变化 |
| `publish_hold` | 暂停发布，保留当前规则版本 |

人工补充与上游或其他分类冲突时构建会停止。复核国内直连范围按实际访问和来源意图判断；不要把厂商特例写死在聚合代码中。规则命中决定路由，不保证服务的账号、地区或出口 IP 要求。

### 构建和验证

需要 Python 3，以及 policy 允许的 Mihomo v1.19.17 转换器。安装脚本支持 macOS arm64 和 Linux amd64，下载官方固定资产并核验 SHA-256：

```sh
export MIHOMO_CONVERTER="${TMPDIR:-/tmp}/ruleset-mihomo"
python3 scripts/install_converter.py --output "$MIHOMO_CONVERTER"
python3 -m unittest discover -s tests -v
python3 scripts/build.py update
python3 scripts/build.py validate --offline
```

`update` 抓取上游、生成候选并验证；`validate --offline` 用仓库内快照重放。下载、语法、分类、规模、复核或重放失败时，Actions 保留最后一个可用版本，诊断见 `.build-report/` 或对应工作流的 artifact。

离线重放默认要求原发布平台。需要在另一允许平台验证时使用：

```sh
python3 scripts/build.py validate --offline --allow-cross-platform-replay
```

跨平台检查必须先逐字节重现全部七个国内直连输出，再接受重放；当前执行身份写入诊断，原发布记录不被改写。涉及构建逻辑的 PR 在 Ubuntu 执行此检查。

GitHub Actions 每天北京时间 08:00 检查，也可在 **Update ruleset → Run workflow** 手动触发。远端以一个完整 Git 提交发布；客户端分别下载多个 URL，升级时要把国内直连的路由与 DNS 引用固定到同一提交并一起切换。

### 回滚和清理

回滚需恢复同一版本的代码、policy、全部生成文件和清单，并开启 `publish_hold`，避免自动更新覆盖回滚结果；客户端同步恢复路由和 DNS 引用。构建被强制终止或断电后，从干净 Git 基线重建。

检查结束后可删除 `.build-report/`、`.build-stage-*`、Python 缓存和下载的转换器。保留仓库中的 `upstream/`、`manifest.json` 与第三方许可，它们是离线验证所需的正式发布内容。
