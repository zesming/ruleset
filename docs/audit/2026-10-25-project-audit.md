# ruleset 全面审查报告

- 日期：2026-10-25
- 审查版本：main@8c7172c
- PR/MR：（提交后补）
- 审查维度与范围：产品逻辑（含 CLI / 配置 / 接入文档的易用性；本项目无图形界面，UI 维度并入产品）/ 代码实现 / 测试；全量（`upstream/`、`rules/`、`tests/fixtures/` 等生成或归档数据只抽查）
- 审查手段：静态阅读；运行全部单元测试（196 个）；安装项目固定的 Mihomo v1.19.17 转换器后跑 `build.py validate --offline`（带与不带 `--allow-cross-platform-replay`）、`personal_profile.py validate --offline`、`profile_clients.py render` 与 examples 比对；只读探针；11 个变异验证；查阅 Mihomo / Surge / GitHub Actions 官方文档
- 内部评审：1 轮质证，驳回 0 条，经用户答复定案 9 条，仍需决策 0 条（其中未充分质证 0 条）

## 修复约定

本报告中问题的修复都提交到 `audit/2026-10-25` 分支（及其 PR），不另开分支：
- 每个修复提交在 message 中引用问题编号，如 `fix(CD-03): …`。
- 修完一条：把本报告中该条状态改为"已修复"，并在 PR 描述中勾选对应条目。
- 修复中发现某条判断有误，把该条状态改为"误判"并写明原因；决定不在本 PR 修的，改为"另排"并写明去向（issue / 后续 PR）。不直接删除条目。
- S0 经确认可单独走 hotfix PR，同样在此注明去向。
- 基线分支有更新时用 merge 同步，不 rebase、不 force push。
- S0/S1 全部处理（"接受风险"的除外）后再把 PR 转为 ready for review；合入前决定本报告是否保留在仓库中。
- 每个条目中的"质证"和"决定"两行优先于前面的原始修复建议：前者修正了范围、数字或方案，后者是维护者确认过的方向。

## 一、结论摘要

规则生成本身是可靠的：196 个测试全部通过，归档快照可以跨平台逐字节重放，生成的接入片段与仓库一致，几条规则语义上的疑点（空 provider、reject 别名、no-resolve、通配符跨点）经对照客户端文档和源码都不成立。问题主要集中在三处：一是**发布链路的保护缺乏回归测试**，11 个刻意删除关键校验的变异（接口闸门、转换器 SHA、重放比对、事务回滚）全部没被任何测试发现；二是**个人聚合的接口闸门随上游内容变化**，上游一个规则类型的变化就会让每日发布整体停摆，连旧接口也一起停；三是**体量与重复**，`manifest.json` 41.7MB 且每天变化，`profile_clients.py` 大部分代码只服务已完成的私有迁移，三个脚本各自维护一套抓取 / 域名 / 转换 / 事务写入。另有 1 条 S1 安全类问题，已私下交给维护者。最值得先做的是补上接口闸门的集成测试并解开发布联动。

| 严重度 | 产品 | UI/交互 | 代码 | 测试 | 合计 |
|---|---|---|---|---|---|
| S0 | 0 | — | 0 | 0 | 0 |
| S1 | 0 | — | 1 | 1 | 2 |
| S2 | 3 | — | 6 | 5 | 14 |
| S3 | 8 | — | 7 | 4 | 19 |

（UI 维度并入产品；接受风险 0 条。）

**建议优先处理**：
1. [CD-01] 安全类 —— S1，修复很小，详情见私下渠道。
2. [TS-01] personal_profile.update() 成功路径从未被测试执行 —— 接口闸门是每日无人值守发布中唯一阻止客户端 URL 被改掉的防线，删掉它也没有测试会变红。
3. [CD-06] 上游一次类型变化挡住整份每日发布 —— 已复现；先输出接口差异诊断，再让 personal 失败只冻结 personal。
4. [CD-13] 删除已完成的私有迁移工具 —— `profile_clients.py` 从 3818 行降到约 600 行，同时根除 CD-01 的写入点。
5. [CD-09] 定时发布会被 PR 运行挤掉 —— 改一行 concurrency 组即可。

## 二、项目画像

个人维护的公开分流规则仓库，供 Mihomo / OpenClash 和 Surge 订阅 `main` 上的 raw URL。默认出口 US，明确直连 DIRECT，日本业务 JP（当前为空），拦截 REJECT，测速走 TEST。

- 两套接口：旧细分类（`rules/ai-*`、`rules/us.list`、`rules/surge/`、`rules/mihomo/cn-direct-*`，文档承诺继续有效）；个人聚合（`rules/personal/{mihomo,surge}/route/` 下按出口合并的 compact 聚合，另有按阶段平铺的 v1 细分文件作为兼容接口）。
- 构建：`scripts/build.py`（旧接口与 cn-direct，抓 MetaCubeX、ChinaMax、ACL4SSR、Sukka）、`scripts/cn_direct.py`、`scripts/personal_profile.py`（个人聚合与接口稳定性闸门）、`scripts/profile_clients.py`（渲染接入片段）、`scripts/install_converter.py`；人工策略在 `policy.json`、`profiles/us-primary.json`。
- 发布：`.github/workflows/update.yml` 每天 00:00 UTC 抓上游 → 生成 → 离线重放 → 按白名单提交并 push 到 main；`publish_hold` 冻结发布。
- 核心路径：新用户按 README 合并 examples 片段；每日自动发布；维护者改 policy / profile 后 PR；接口迁移；回滚。
- 测试：unittest 6 个文件约 5200 行，外部网络全部 mock；PR 上额外装转换器跑两个离线重放与片段 diff。

## 三、精简建议汇总

- **删除**：`profile_clients.py` 的 `migrate` / `compare` 及其私有辅助代码、测试和走不到的非 compact 渲染分支（[CD-13]，已决定）；`cn_direct.first_match_assertions`（[CD-08]，已决定）；`profiles/us-primary.json` 的冗余 `routes` 字段和显式默认值（[PD-09]，保留节点名保护）；`validate` 的必填 `--offline` 开关（[PD-12]）。
- **合并**：四个脚本的 HTTP 抓取、域名规范化、MRS 转换、事务写入、DOMAIN-SET 渲染抽到一个公共模块，测试同步合并（[CD-12]）；维护文档两组命令合成一组完整序列（[PD-06]）；统一"细分类 / compact / 兼容接口"术语（[PD-13]）。
- **降级 / 缩减**：manifest 中可从归档推导的 cn 明细改为哈希与计数，输出不变时不发新 release（[CD-10]，已决定）；测试文件移出发布身份（[CD-11]，已决定）；v1 个人细分文件标为兼容接口（[PD-02]，已决定保留）。
- 精简后的核心路径：维护者编辑 policy / profile → 跑一组标准检查（unittest + 两个重放 + render）→ PR → 合入；每日发布只在输出变化时提交，personal 失败只冻结 personal 并留下接口差异诊断。

## 四、问题清单

按维度分节，节内按严重度从高到低排列。

### 4.1 产品逻辑（含 CLI / 配置 / 文档易用性）

#### [PD-03] 接口迁移没有过渡窗口：新资源出现和旧资源删除发生在同一个提交里，文档要求的"先确认新资源可用再切换"做不到
- 维度：产品 | 严重度：S2 | 工作量：M | 置信度：高（机制）/ 中（实际影响） | 状态：已确认
- 位置：scripts/personal_profile.py:1087-1106（`--accept-interface-change` 只是放行）、1776-1783（validate 要求 `rules/personal`、`upstream/personal` 下没有多余文件）；docs/maintenance.md:113-115、123；docs/personal-routing-comparison.md:48
- 现象：接受接口变更后，旧路径在同一次发布中被删除；validate_bundle 会把残留的旧文件判为 `unexpected`，所以无法让旧文件多保留一段时间。文档 123 行说"现用配置只有在引用的远端整版资源已经可用时才切换"，113 行说"不得让日常更新静默删除旧客户端正在订阅的资源"。
- 依据：只要资源是新增的，客户端就做不到先切换；一旦合入，旧客户端立刻拿到 404，而新资源要等合入后才出现。目前唯一的过渡办法是把旧接口永久留在编译器里，也就是 PD-02 的现状。
- 影响：每次迁移，所有旧客户端都会有一段时间 404，或者只能用本地缓存。这条路径对维护者（画像路径 4）不安全，也说明了为什么 v1 文件一直删不掉。
- 修复建议：在 upstream/personal/manifest 里加 `retired_outputs`：accept 之后旧 outputs 按旧内容冻结，保留到写明的日期，或者等第二次显式 `--retire`。validate 把这类文件当作预期集合，并在 docs 中写成三步流程：发布新旧并存 → 切换客户端 → 退役。
- 质证：96031dc（46 个 priority-* → route/* 重命名）和 29e5e57（删除 6 个 route 文件）两次真实发生“新旧同提交”。Mihomo / Surge 更新 provider 失败时保留本地缓存，实际影响是旧客户端停在旧快照，而不是立即失效。

#### [PD-05] README 把 personal 片段列为首要"接入片段"，但片段里没有任何前置条件或合并说明，旧示例反而注释齐全
- 维度：产品 | 严重度：S2 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：README.md:15；examples/personal-mihomo.yaml:1-195、examples/personal-surge.conf:1-50（由 scripts/profile_clients.py:459-534 生成，没有注释输出）；对照 examples/mihomo.yaml:1-4、examples/surge.conf:1-7
- 现象：personal 片段直接引用 `🇺🇸 US` 和 `🇯🇵 JP`，但不定义它们。Mihomo 片段整段覆盖 `dns:`（enable、fake-ip、nameserver），Surge 片段写入 `[General] encrypted-dns-server` 和 `always-real-ip`。fake-ip-filter / always-real-ip 中的 AT&T、Nintendo 条目是作者设备特有的。JP 当前为空，但 Test 组和 DoH 规则仍要求存在 JP 策略。这些前提要到 docs/personal-routing-comparison.md:40 才零星提到（"`🇺🇸 US` / `🇯🇵 JP` 是 TUIC 节点"）。README 也没说明这套片段面向作者本人，第三方应该用细分类。
- 依据：画像路径 1（新用户：README → examples → 合并）走到合并这一步，用户不知道要自备哪些策略名、哪些段会被覆盖；缺少策略时 Mihomo 和 Surge 都会拒绝加载配置。
- 影响：首次接入大概率失败，或者用户自己的 DNS 设置被悄悄覆盖。
- 修复建议：在渲染器里输出头部注释（必需的策略名、会覆盖的段、设备特有条目、JP 为空但仍需要 JP 策略），CI 的 diff 会自动同步。README 用一句话区分"个人完整片段（作者自用）"和"细分类（第三方复用）"。
- 质证：复核确认：personal-mihomo.yaml 0 行注释，引用的 🇺🇸 US / 🇯🇵 JP 未在片段中定义；旧示例有前置注释。

#### [PD-06] 维护文档的两组命令序列互相矛盾且不完整：照"构建和验证"一节操作，在 macOS 上会失败，PR CI 也会失败
- 维度：产品、测试 | 严重度：S2 | 工作量：S | 置信度：中 | 状态：已确认（合并 TS-13）
- 位置：docs/maintenance.md:61-67、71-77、97-105；scripts/build.py:2033-2040；upstream/provenance.json（`cn_direct.converter_execution.platform = "linux-amd64"`）
- 现象：
  - 第 61-67 行只列了 `build.py update` 和 `build.py validate --offline`，没有 `personal_profile.py update / validate` 和 `profile_clients.py render`。按这一节修改 policy.json 后提 PR，PR check 会跑 personal validate 和片段 diff（update.yml:52-58），因为 legacy 输入哈希变了而失败。
  - 第 66 行 `validate --offline` 没带 `--allow-cross-platform-replay`。当前发布平台记录是 linux-amd64，在 macOS arm64（安装脚本支持的另一个平台，也是作者本机）上，只要本地 update 结果是 "unchanged"、provenance 没被改写，就会报 "CN-direct MRS replay requires the published converter platform"。第 102 行的另一组命令带了这个参数。
- 依据：上面列出的行号；build.py:2038-2040 的报错分支。
- 影响：画像路径 3（维护者改人工规则）第一次照文档操作就会遇到失败。
- 修复建议：合并成唯一的一组标准命令序列（最好提供一个 `scripts/check_all.py` 或 Makefile 目标，一次跑完 build update → personal update → 两个 validate → render）。在 macOS 上统一带 `--allow-cross-platform-replay`，或者让 build.py 自动识别"本机不是发布平台"并提示。验证方式（由主 agent 执行）：在 macOS 装好转换器后运行 `python3 scripts/build.py validate --offline`，预期出现上述报错。
- 质证：基线复现：macOS 上 `build.py validate --offline` 报 “requires the published converter platform”（baseline/validate-offline.txt）。范围修正：PR CI 只在改动影响 personal 的 legacy 输入（personal_profile.py:545-567）时失败。修复推荐：把第一组命令换成 99-105 行的完整序列并加参数说明；check 脚本为可选项。

#### [PD-02] 已被 compact 取代的 v1 个人细分文件仍在生成、发布，并被锁成接口；没有示例引用，内容与旧接口重复
- 维度：产品 | 严重度：S3 | 工作量：M | 置信度：中 | 状态：已确认
- 位置：rules/personal/mihomo/*.{mrs,list}（28 个 group）、rules/personal/surge/*（约 37 个文件，含 dns-*）；scripts/personal_profile.py:913-916、963-1020（`_client_interface` 把 `groups` 和 stage 顺序一起列为接口）、1772-1795（validate 要求文件集合完全相等）；docs/maintenance.md:89、111（"原 groups 保留细分类接口"）
- 现象：`git show f3d9c54:examples/personal-mihomo.yaml`（#5，10-20）引用了 32 个 `rules/personal/mihomo/<stage>` 文件，同一天 #6 就改为只引用 `route/`。现在两个 personal 示例只引用 `route/` 下的 16 个（Mihomo）和 18 个（Surge）文件。非 route 文件合计 9.3MB，仍随每日快照更新。其中 `rules/personal/mihomo/cn-direct-domain.mrs` 与 `rules/mihomo/cn-direct-domain.mrs`、`rules/personal/surge/ai-cn.set` 与 `rules/surge/ai-cn.set`、`personal/surge/network-test.set` 与 `rules/surge/network-test.set`、`personal/{mihomo,surge}/ai-global.list` 与 `rules/ai-global.list` 的 sha1 完全相同。
- 依据：实际存在三套接口：旧细分类 `rules/*`、v1 个人细分 `rules/personal/<p>/*`、compact `rules/personal/<p>/route/*`。文档把 `rules/` 和 personal 的 `groups` 都叫"细分类"，同一个词指两样东西。按 code.md 的标准，"没有调用方"的判断要排除外部订阅者：这些是公开 URL，可能仍有 v1 客户端在用，所以置信度只给中。
- 影响：维护者要同时理解三套命名；调整 `stages` 的顺序或组合，会对没人引用的 v1 接口触发 `--accept-interface-change`；仓库体积和每日 diff 增大；第三方看到 `rules/personal/` 下的平铺文件，会误以为是推荐接口。
- 修复建议：（质证时待问用户，已决见下）还有没有客户端订阅 v1 个人细分文件？候选方案：(a) 用一次显式接口迁移退役 v1 groups，只保留 compact 和旧接口；(b) 保留，但在 README 和 maintenance 里标为"冻结的 v1 兼容接口"，并定下退役日期。推荐 (a)，可以配合 PD-03 的过渡窗口。
- 质证：保留 v1 细分文件是 docs/maintenance.md:89、111 声明的取舍，降为 S3；#7（96031dc）、#10（29e5e57）都做过接口迁移，v1 留着是有意的，不是删不掉。
- 决定：用户决定（2026-10-25）：保留，在 README 和 maintenance 中标为“细分类兼容接口，非推荐入口”。

#### [PD-08] 回滚流程要求填写 `publish_hold.rolled_back_release_id`，但文档没提，代码也只校验格式、不核对实际版本
- 维度：产品、代码 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认（合并 CD-07）
- 位置：scripts/build.py:620-629（只在这里出现）；docs/maintenance.md:81-83；policy.json `publish_hold`
- 现象：开启 hold 必须同时给出非空 `reason` 和 64 位 hex（或 EMPTY_RELEASE）的 `rolled_back_release_id`，否则构建失败。docs 只写了"开启 `publish_hold`"，没说要填这两个字段，也没说 release id 从 `manifest.json.release_id` 获取。在全部 scripts 中 grep，这个字段只在 build.py 校验格式的那几行出现，没有任何地方把它和恢复后的 manifest.json release_id 比对。
- 依据：上面的 grep 结果。
- 影响：画像路径 5（回滚）在紧急情况下第一步就可能被校验拦住。这个字段又不做比对，填错也能通过，给人一种不存在的安全感。
- 修复建议：docs 补上"取 manifest.json 的 release_id 填入"。hold 开启时，update 和 validate 都断言它等于当前 manifest.json 的 release_id，不一致时报错并给出正确值。
- 质证：`git grep rolled_back_release_id` 只命中 build.py:621-628、policy.json、tests/test_build.py:1005/1047，没有任何地方与 manifest.release_id 比较；只影响应急路径且报错明确，定 S3。
- 决定：按推荐：保留字段，文档写明取 manifest.json 的 release_id，update/validate 在 hold 开启时断言二者相等。

#### [PD-09] `profiles/us-primary.json` 看起来是配置，实际上大多数字段被校验锁死；文件里有两套顺序，客户端真正使用的不是 `stages` 的顺序
- 维度：产品 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：profiles/us-primary.json:4-10、29-64；scripts/personal_profile.py:575-585（`routes` 必须是恒等映射，`id` 必须是 `us-primary`）、649-667（GEOIP 只能是 CN no-resolve，MATCH 只能走 US）、676-694（每个 Sukka 源和 legacy 源都必须恰好出现一次）
- 现象：`routes` 只有一种合法取值（`"US":"US"`…），纯属冗余。`stages` 中 `att-us` 排在 reject 之前、`ai-cn` 排在 `ai-global` 之前，但客户端顺序由 `compact.slots` 决定（att-us 在 reject/test 之后，ai-cn 在 US 之后）。docs/maintenance.md:26 描述的是 compact 顺序。几乎每个 stage 都显式写了默认值 `"extended_matching": false, "no_resolve": false`。
- 依据：上面列出的行号；PD-02 提到 `stages` 的顺序会进入 v1 接口比较。
- 影响：维护者容易误以为改 `stages` 的顺序就能改客户端优先级，或者以为 `routes` 能改出口名。文件里有效信息和噪音混在一起。
- 修复建议：删掉 `routes`（或改成可选，并给出说明）；flags 省略即取默认值；在 profile 或 docs 中注明"客户端顺序只由 compact.slots 决定，stages 只是来源定义"。
- 质证：复核确认。`routes` 的恒等校验（personal_profile.py:575-585，报错 “must keep the credential-free group name”）是防止真实节点名写入公开 profile 的保护；删除 routes 时要保留这一保证（例如在代码里写死五个名字）。

#### [PD-10] policy.json 中有 25 处复核依据指向仓库外的私有文件；acl_review 证据是嵌在 JSON 里的 JSON 字符串，也没有说明怎么生成
- 维度：产品 | 严重度：S3 | 工作量：M | 置信度：高 | 状态：已确认
- 位置：policy.json（`direct_rules[*].reference` 中有 10 处 `.devflow/actions-network-test/audit-direct-api.json`、15 处 `.devflow/actions-network-test/audit-direct-suffix.json`；`cn_direct.acl_review` 含 `audit_sha256`、`bootstrap_candidate_id` 和 45 条 decisions，`evidence` 字段是转义后的 JSON 字符串）；docs/maintenance.md:42-55
- 现象：这些 `reference` 引用的文件不在仓库里，也不在 .gitignore 管理的产物里，其他人无法核对。maintenance 的字段表没有说明 acl_review 决定和哈希的生成方法。
- 依据：`grep -o '\.devflow/[^";, ]*' policy.json | sort | uniq -c`。
- 影响：复核依据无法复查；新增或修改 ACL 复核只能靠作者私有流程，"编辑 policy.json"的路径对其他维护者实际走不通。
- 修复建议：把需要保留的审计摘要入库（例如 `docs/audit-evidence/`），或者把 reference 改成公开 URL。补一句 acl_review 的生成和更新方法；evidence 改成结构化对象，不再用字符串。
- 质证：复核确认：10 处 audit-direct-api.json、15 处 audit-direct-suffix.json 均不在仓库内；acl_review evidence 只校验非空（cn_direct.py:324）。

#### [PD-11] `rules/direct.list`、`rules/surge/direct.set` 已发布，但示例和 profile 都不引用，内容已合入 cn-direct；`cn-direct-domain.txt` 的用途也没有文档
- 维度：产品 | 严重度：S3 | 工作量：S | 置信度：中 | 状态：已确认
- 位置：scripts/build.py:70-71；rules/direct.list、rules/surge/direct.set、rules/mihomo/cn-direct-domain.txt；scripts/personal_profile.py:688-694（legacy_required 里没有 direct）；docs/maintenance.md:22
- 现象：examples/mihomo.yaml 和 surge.conf 都不引用 direct 文件；docs 说同一份范围已经"合入 cn-direct"，"客户端继续引用现有聚合"。`cn-direct-domain.txt`（MRS 的源文本，带 `+.`）在文档中没有出现。
- 依据：示例 URL 全量核对的结果，以及上面的 grep。
- 影响：多了公开文件和需要解释的概念，第三方可能误用。不过它们也可能是有意提供给第三方单独订阅的细分类。
- 修复建议：（质证时待问用户，已决见下）direct.list/.set 是否打算作为第三方可单独订阅的接口？候选方案：(a) 是：在 README 细分类示例中补一行用法；(b) 否：停止发布（需要按接口迁移处理）。推荐 (a)，成本最低；`.txt` 在 maintenance 文件表中补一句用途。
- 质证：范围收窄：direct 在 docs/maintenance.md:22 已有说明；rules/mihomo/cn-direct-domain.txt 是 personal 的 legacy 输入（personal_profile.py:558），不是无用文件。剩余问题：README 没有给出 direct 的用法，文件表缺 .txt 的用途。
- 决定：用户决定（2026-10-25）：direct 作为可单独订阅的细分类，README 补用法，文件表补 .txt 用途。

#### [PD-12] 三个 CLI 的参数、退出码和自述不一致
- 维度：产品 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/build.py:2400-2424；scripts/personal_profile.py:2518-2550；scripts/profile_clients.py:3749-3814
- 现象：
  - 转换器传入方式不统一：build.py 只认环境变量 `MIHOMO_CONVERTER`，另外两个脚本支持 `--converter`。
  - `validate` 的 `--offline` 是必填的 store_true 开关（build.py 用 `required=True`，personal_profile 用 `parser.error`），只有一种合法取值。
  - 退出码不同：build 和 personal 是 1，profile_clients 是 2。
  - `build.py --help` 写的是 "Build and replay the public AI classical rule providers"，实际还构建 cn-direct、us、direct、network-test。personal_profile 自称编译 "private … profile"，产物却是公开发布的。
  - personal_profile 的子命令和参数大多没有 help 文本。
- 依据：`--help` 的实际输出。
- 影响：维护者在两个脚本之间切换时容易用错；脚本自述误导人对其职责的理解。
- 修复建议：统一用 `--converter` 加环境变量回退；`validate` 默认离线，去掉必填开关或改成可选；统一退出码；更新 docstring 和 help。
- 质证：复核确认；argparse 报错三者都是 2，不一致只在业务错误退出码；personal 的 `update --offline` 是有意义的选项。

#### [PD-13] 概念和命名过载："细分类"指两样东西，"cn-direct"有三种范围，README 链接名、文件名、标题对不上
- 维度：产品 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：README.md:9-17；docs/maintenance.md:89、111；docs/personal-routing-comparison.md 全文
- 现象：
  - "细分类"既指 `rules/*`（旧接口），也指 personal `groups`（maintenance:111）。
  - `cn-direct` 在旧接口中只是国内直连聚合；personal `route/cn-direct` 还包含 ai-cn、apple-services、game-download、download、microsoft、netease（profiles/us-primary.json:19）；personal 平铺目录里还有一份和旧接口字节相同的 `cn-direct-domain.mrs`。
  - README 链接文字是"配置说明"，文件名是 personal-routing-comparison.md，标题是"个人分流与 DNS"。该文件还包含无法从仓库核对的私有环境说明（OpenClash 自定义覆写、CMFA/ClashBox、公司条目、TUIC/Snell 6）。
- 依据：上面列出的行号。
- 影响：第三方和后来的维护者很难判断哪个文件是给谁用的，读文档的成本高。
- 修复建议：README 加三行术语说明（旧接口 / 个人 compact / v1 兼容），统一用词；文档改名为 personal-routing.md 或调整链接文字；私有环境说明集中到一个"作者环境"小节并标注。
- 质证：复核确认。

#### [PD-14] 旧细分类示例按"从作者旧配置迁移"的视角写，国内 DoH 端点在示例之间也不一致
- 维度：产品 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：examples/mihomo.yaml:68-73、84-87；examples/surge.conf:15-16、26-30；examples/personal-*.（国内 DoH）
- 现象：注释写的是 "Replace old direct/domestic DOMAIN providers at their original position"、"Merge at the old direct/domestic DNS selector's position"，假设读者已经有作者的 direct/domestic provider。国内 DoH 方面，Surge 旧示例用 `https://doh.pub/dns-query`（主机名，需要引导解析），Mihomo 旧示例和两个 personal 片段用 `https://1.12.12.12/dns-query`。
- 依据：上面列出的行号。
- 影响：第三方（画像路径 6）不清楚插入位置该相对什么来定；DoH 写法不一致，增加了理解和排障成本。
- 修复建议：注释改成相对通用结构描述插入位置（"放在本地例外之后、广域名/IP/GEOIP 之前"）；国内 DoH 统一用 IP 形式。
- 质证：范围修正：examples/mihomo.yaml 自身也不一致（:83 ai-cn 用 doh.pub，:86-87 用 1.12.12.12），国外侧用主机名 dns.google（mihomo.yaml:80、surge.conf:25）。问题改为：国内外 DoH 在同一文件内和跨文件混用主机名与 IP。

### 4.2 UI 与交互

本项目没有图形界面，接口 / CLI / 配置的易用性并入 4.1。

### 4.3 代码实现

#### [CD-01] 安全类，详情见私下渠道
- 维度：代码、产品 | 严重度：S1 | 状态：已确认（合并 PD-01）
- 说明：仓库公开，本条细节不写入报告和 PR 描述，已私下交给维护者；修复时在提交信息中只引用编号。

#### [CD-03] 未登记 DOMAIN-REGEX 的过滤作用于所有类别，Azure 正则变更后会被静默丢弃，parse_source 的漂移守卫在生产路径上走不到
- 维度：代码 | 严重度：S2 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/build.py:855-872（_combine_source_chunks）、:896-904（fetch_upstream）、:941-943（parse_source 守卫）；tests/test_build.py:930-945
- 现象：`_combine_source_chunks` 会对 global、cn、network-test 三类都删掉"不等于登记正则"的 DOMAIN-REGEX 行。它的说明写着登记正则只在 AI global 里，过滤是针对 Ookla 这类其他上游。实际效果是：上游一旦改了 Azure ChatGPT 正则（哪怕一个字符），这一行在解析前就没了，`parse_source` 里 "unknown or changed DOMAIN-REGEX" 的报错不会触发，`DOMAIN-WILDCARD,chatgpt-async-webps-prod-*-*.webpubsub.azure.com` 从输出里静默消失。route_assertions 共 11 条，没有一条覆盖这个主机。
- 依据：只读探针。`_combine_source_chunks([b"DOMAIN-SUFFIX,openai.com\nDOMAIN-REGEX,^chatgpt-async-webps-prod-\\S+-\\d+\\.webpubsub\\.azure\\.net$\n"], "global")` 返回 `b'DOMAIN-SUFFIX,openai.com\n'`，parse_source 只得到一条规则，不报错。test_build.py:939 的守卫测试 mock 了整个 `fetch_upstream`，绕开了这个过滤，所以测试通过不能证明生产路径有效。
- 影响：旧接口（`rules/ai-global.list`）的消费者会悄悄失去 ChatGPT 异步连接的分流；manifest 只在 adapted_regex_rules 计数上从 1 变成 0，不会让构建失败。个人 profile 的兜底也是 US，所以本人不受影响。
- 修复建议：只在 network-test 这类明确登记"可丢弃正则"的类别上过滤，global 和 cn 保持原样交给 parse_source 去校验。也可以加一条断言：global 必须恰好产出一条登记的 wildcard。
- 质证：复核用只读探针复现：`_combine_source_chunks` 对 global 丢掉变更后的正则，parse_source 只得到 1 条规则且不报错；test_build.py:939-941 mock 了整个 fetch_upstream，绕过了过滤。推荐 global 保留原样交给 parse_source 校验，并断言 global 恰好产出 1 条登记的 wildcard。

#### [CD-06] 个人聚合的"接口稳定性"取决于上游内容，一次上游类型变化会挡住整份每日发布（包括旧接口），而且没有诊断产物
- 维度：代码、产品 | 严重度：S2 | 工作量：M | 置信度：中 | 状态：已确认（合并 PD-04）
- 位置：scripts/personal_profile.py:895-901（_capability 由规则类型推导）、:1597-1600（细分类 group 的 capability 和"无规则即跳过"）、:1087-1106（_require_stable_client_interface）、:2094-2131（update）；profiles/us-primary.json 中 lan、reject、test、cn-direct 这几个 slot 没有固定 format；.github/workflows/update.yml:89-94
- 现象：group 的 capability（domain / domain-special / classical）决定扩展名（.mrs/.set/.list）和 path，path 属于接口字段。上游 Sukka 文件里一旦新增 DOMAIN-KEYWORD、某平台某个阶段变空、或者出现 IP 规则，接口比对就不一致，update 抛出 "client resource interface changed for …" 后停止。工作流里这一步失败会让整个 publish job 失败，build.py 已经通过的旧接口规则、cn-direct 规则也一起不发布，之后每天都失败，直到有人手动用 `--accept-interface-change` 提 PR。报错只列出平台名，不写是哪个 group 的哪个字段变了；personal 只在解析失败时向 .build-report 写东西。
- 依据：上面列出的代码位置；工作流里 personal update 与 build update 在同一步骤，失败即退出。
- 影响：上游的一次格式演进就能让所有订阅者的规则停更，维护者还得在本地重放才能知道原因。
- 修复建议：（1）报错时把 before/after 的接口差异写到 `.build-report/personal-interface-diff.json`，工作流已经会上传这个目录。（2）给个人 slot 和 group 固定 format，或者对 capability 做"只升不降"处理，例如 domain 升级成 classical 时报警但不阻断。（3）（质证时待问用户，已决见下）个人接口变化时，旧接口和 cn-direct 是否应该照常发布？候选方案：a) 维持现在的整体原子发布；b) 把个人部分拆成独立提交或独立 job，失败时只冻结个人部分。推荐 b 加上（1）。
- 质证：复核在临时副本里复现：只在 upstream/personal/surge/lan.conf 加一行 `DOMAIN-KEYWORD,examplelanprobe`，`personal_profile.py update --offline` 就报 “client resource interface changed for surge, surge compact”，细分类和 compact 接口同时变化，且不生成 .build-report。只给 compact slot 固定 format 不够，细分类 group 也要固定 format 或采用“只升不降”。
- 决定：用户决定（2026-10-25）：b。先输出接口差异诊断（.build-report/personal-interface-diff.json），再把 personal 的发布与旧接口解耦，personal 失败时只冻结 personal。

#### [CD-09] 发布工作流和 PR 检查共用同一个 concurrency 组，排队中的定时发布会被后来的 PR 运行取消
- 维度：代码 | 严重度：S2 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：.github/workflows/update.yml:2-30（`concurrency: group: ruleset-publish, cancel-in-progress: false` 写在工作流顶层，pull_request、schedule、push 都适用）
- 现象：GitHub 的并发组里最多一个运行中、一个排队中；新运行进来时会替换并取消原来排队的那个，`cancel-in-progress: false` 只保护正在运行的那个。所以一个 schedule 或 push 发布在排队时，只要来一次 PR 推送（PR 运行同样在这个组里），就会被取消。另外，check 和 publish 之间如果 main 前进了，`Ensure checked main is still current` 会让这次运行显示失败，而不是跳过。
- 依据：工作流 YAML 的写法和 GitHub Actions 文档里关于 concurrency 的说明。
- 影响：当天的上游更新可能不发布，要等到下一次 schedule 或 push；PR 越频繁，越容易出现。
- 修复建议：把 group 改成按事件区分，例如 `group: ${{ github.event_name == 'pull_request' && format('ruleset-pr-{0}', github.event.pull_request.number) || 'ruleset-publish' }}`。main 已前进的情况改成 `echo skip; exit 0`，同时注明由 push 运行接手。
- 质证：已对照 GitHub 文档核实：新运行进入 pending 会取消同组旧的 pending，与 cancel-in-progress 无关；PR 运行在同一常量组里。补充：main 被 push 路径过滤以外的提交（README、docs、examples）推进时，:85 会让当次运行失败，这个提交本身又不触发新运行。修复建议：PR 放进独立的组，发布组加 `queue: max`；main 已前进时以成功退出并记录说明，不要写“由 push 接手”。

#### [CD-10] manifest.json 41.7MB，其中 36.7MB 是可以从归档推导出来的 cn_direct 明细；release 身份绑定 meta_sha，规则没变也每天发一次
- 维度：代码 | 严重度：S2 | 工作量：M | 置信度：高 | 状态：已确认
- 位置：scripts/cn_direct.py:1271-1340（manifest 的 source_rules、domain_rules、rule_origins）；scripts/build.py:1726-1736（release_inputs 含 meta_sha 和原始字节哈希）、:921-940（每条 origin 都带 meta_sha）
- 现象：实测 manifest.json 41,745,269 字节。按顶层键算 JSON 大小：cn_direct 36.7MB，其中 rule_origins 17.5MB、source_rules 8.4MB（就是 upstream/cn-direct/* 解析后的结果）、domain_rules 7.3MB（等于 rules/mihomo/cn-direct-domain.txt）。MetaCubeX meta 分支每天都有新提交，上游文件行序也不稳定，所以 release_id 每天都变。最新提交 8c7172c 里 rules/ai-*.list 都没变，manifest 的 diff 仍有 7072 行（大多是每条 origin 里的 meta_sha）。49 个提交后 pack 已经 72MB。
- 依据：上面的测量和 `git show --stat 8c7172c`。
- 影响：仓库体积持续增长，日常提交 diff 无法审阅，CI 的 checkout（fetch-depth 0）和本地操作都会越来越慢。
- 修复建议：baseline 需要的 cn 规则集合改成从上一版归档文件或 git 历史重新解析，manifest 里只保留哈希和计数；rule_origins 改为按输出规则聚合的计数，或者单独压缩归档。（质证时待问用户，已决见下）"输出没变、只有上游 commit 变了"时，是否还需要发一个新 release？候选方案：a) 维持现状；b) 输出和归档的规则集合都没变时视为 unchanged，只按 30 天节奏更新 CHECKED_AT。推荐 b，但它会改变 release 身份的语义，需要同步调整测试。
- 质证：数字修正（紧凑 JSON 口径）：cn_direct 25.3MB（rule_origins 13.7MB、source_rules 5.9MB、domain_rules 5.7MB），文件 41,745,269 字节；8c7172c 的 manifest diff 7072 行，其中 2329 对是 meta_sha 替换；pack 72.44MiB（49 个提交）。8c7172c 当天个人规则确有变化，不作为“无变化也发布”的例证；这个机制由 release_inputs 包含 meta_sha（build.py:1726-1736）就能看出。
- 决定：用户决定（2026-10-25）：b。输出和归档规则集合都没变时视为 unchanged；manifest 的 cn 明细改为可从归档推导。

#### [CD-12] 四个脚本里有大约 300 行近似重复的基础设施，而且语义已经出现分歧
- 维度：代码、测试 | 严重度：S2 | 工作量：M | 置信度：高 | 状态：已确认（合并 TS-12）
- 位置：
  - HTTP 抓取：build.py:770-847，cn_direct.py:666-731，personal_profile.py:1798-1839，install_converter.py:35-38
  - 域名规范化：build.py:380-399，cn_direct.py:139-165，personal_profile.py:164-182
  - MRS 转换和平台识别：cn_direct.py:968-1023，personal_profile.py:840-892
  - 事务写入：build.py:2071-2122，personal_profile.py:2035-2091
  - DOMAIN-SET 和 Mihomo 域名文本渲染：build.py:95-114，cn_direct.py:938-959，personal_profile.py:816-837
  - direct_rules 校验：build.py:228-256 和 cn_direct.py:1078-1113，两份几乎一样，每次构建都各跑一遍
  - 日期校验：build.py:661-669，cn_direct.py:1101-1108
- 现象，几处已经不一致：
  - 重试：build 3 次（带退避），cn_direct 1 次（ChinaMax 16MB、ACL、Sukka 一共 8 次请求，没有重试），personal 3 轮。
  - build 只捕获 `URLError/TimeoutError/OSError/ValueError`。`http.client.IncompleteRead` 继承自 HTTPException，不是 OSError（已用 `__mro__` 核实），所以不重试，直接变成 "Unexpected build failure"。
  - 重定向：build 允许在两个主机之间跳转，另外两份要求同一主机。
  - 域名：只有 personal 允许 `_`，只有 cn_direct 校验 punycode 是否规范，三份对多余的末尾点处理也不同。
- 依据：docs 和各模块说明表明"模块彼此独立"是有意的设计，但纯函数级的工具复用不会破坏这种独立性。
- 影响：修一份忘了另一份（#11 的令牌逻辑就在两个文件里各加了一遍）；cn-direct 的任何一次瞬时网络错误都会让当天的发布失败。
- 修复建议：新建 `scripts/_common.py`，只放纯工具：有上限、有重试的 HTTPS 获取（可带"令牌只发 api.github.com"选项）、域名规范化（参数控制是否允许 `_`）、转换器调用、事务写入、域名集合渲染。三个脚本改成导入它，并把它加入 TOOL_CONTENT_FILES。短期先给 cn_direct 补上重试，捕获范围补上 `http.client.HTTPException`。
- 质证：复核确认：`http.client.IncompleteRead` 的继承链是 HTTPException→Exception，不在 build.py 的重试捕获范围内，最终落到 :2235 “Unexpected build failure”；cn_direct._http_bytes 只请求 1 次，不重试。测试同样是三套几乎一样的（TS-12）。

#### [CD-13] profile_clients.py 的 3444 行函数体里，大约 2850 行是私有 migrate/compare，不在 CI、发布和文档路径上
- 维度：代码、产品 | 严重度：S2 | 工作量：M | 置信度：中 | 状态：已确认（合并 PD-07）
- 位置：scripts/profile_clients.py:622-3735（SurgeSection、_migrate_*、private_migrate、compare_private 及其辅助函数）、:3778-3814（main 的 migrate/compare 分支）；render 路径在 :110-620、:3736-3747
- 现象：用 AST 统计可达性：从 render_mihomo_snippet、render_surge_snippet、_replay、_validate_base_url 出发能走到 31 个函数、599 行；从 private_migrate 出发 124 个、3245 行；compare_private 77 个、1988 行。CI 和 docs/maintenance.md 只用到 `render`，README 和 docs 都没提 `migrate`/`compare`，它们依赖的私有基线目录在仓库里也不存在。render 路径里还留着非 compact 的分支（`_groups` 的 else、`_candidate_stages`、`_surge_route_lines`/`_mihomo_route_lines` 的 `compact=False`），但 personal_profile.compile 始终会写 manifest["compact"]（:1729），这些分支在生产上走不到。
- 依据：上述统计，并逐个看过这些入口（它们是 CLI 子命令，不是公开库 API）。
- 影响：一个 3800 行的文件里，大部分代码只服务作者一次性的配置迁移，增加了理解成本、测试负担（test_profile_clients.py）和泄露风险（见 CD-01）。
- 修复建议：（质证时待问用户，已决见下）私有配置迁移已经完成了吗？以后还会再用 compare 吗？候选方案：a) 拆到 `scripts/private_migration.py`（或移出仓库），profile_clients.py 只保留 render，约 600 行；b) 全部删除，连同相应测试；c) 维持现状。推荐 a；如果迁移已完成并且确认不再需要，就选 b。非 compact 分支可以连同相关测试一起删掉。
- 质证：复核确认；行号修正：compact 一定会写入的位置是 personal_profile.py:1736。
- 决定：用户决定（2026-10-25）：迁移已完成，删除 migrate / compare 子命令、它们的私有辅助代码和测试，以及 render 路径里走不到的非 compact 分支；profile_clients.py 只保留 render。这样也从根源上去掉了安全类 [CD-01] 的写入点。

#### [CD-02] 安全类，详情见私下渠道
- 维度：代码 | 严重度：S3 | 状态：已确认
- 说明：仓库公开，本条细节不写入报告和 PR 描述，已私下交给维护者；修复时在提交信息中只引用编号。

#### [CD-04] network-test 的两个上游文件拼接后，来源记录的 path 和 line 都错了，归档内容也不是任何上游原文
- 维度：代码 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/build.py:921-940（origins 固定用 `_source_path_list(category)[0]` 和拼接后的行号）、:896-901、:1590-1607（provenance 只有一个 sha256，对应两个 URL）、:1137（source_category 的推断）
- 现象：来自 `category-speedtest.list` 的规则被记成 `category-ip-geo-detect.list`，行号是拼接后的行号。`upstream/network-test.list` 存的是"过滤正则后再拼接"的字节，provenance 里两个 URL 只配一个 sha256。
- 依据：探针中，`parse_source(_combine_source_chunks([b'DOMAIN,a.com\n', b'DOMAIN,b.com\n'], 'network-test'))` 把 b.com 的来源记成 `('category-ip-geo-detect.list', 2)`。
- 影响：manifest 的 rule_origins 和 provenance 不能用来回查上游原文件，审计价值下降。
- 修复建议：按文件分别归档、分别计算哈希，origins 记录真实的 path 和行号。或者在 provenance 里对每个 URL 记录原始字节的哈希，同时注明归档内容经过了过滤。
- 质证：复核用探针复现：b.com 的 origin 被记为 category-ip-geo-detect.list 第 2 行。

#### [CD-05] Sukka 来源没有完整性校验：`# Size:` 头没核对，content-hash 只记录不验证，50 多个文件各自抓取
- 维度：代码 | 严重度：S3 | 工作量：S | 置信度：中 | 状态：已确认
- 位置：scripts/cn_direct.py:777-792（_sukka_header_metadata 只提取字段）；scripts/personal_profile.py:1798-1868（_fetch_one / fetch_sources 完全不看头部）
- 现象：Sukka 文件头的 `# Size: N` 等于非注释行数。实测 `upstream/personal/surge/reject_domains.conf` 的 Size 是 144759，非注释行数也是 144759。cn_direct 把 declared_size 和 content_hash 写进 manifest，但从不比对；personal_profile 不解析头部。字节数校验只能在服务端发了 Content-Length 时发现传输截断。镜像返回的内容只要能解析、非空，就会被发布。cn-direct 的 4 个 Sukka 文件和 personal 的 58 个文件分别抓取，同一批里可能混着不同的 Last Updated 版本。
- 依据：docs/personal-routing-comparison.md 写明"规则数量与变更幅度用于记录差异，不阻止更新"，所以这里不建议加缩量阈值。但完整性校验（文件是否完整）和变化幅度是两回事，前者成本很低。
- 影响：CDN 或镜像返回截断或部分生成的文件时（例如 reject 列表只剩一部分），个人 reject、cdn、direct 聚合会被静默缩小并发布。
- 修复建议：抽一个共用的 Sukka 头部解析函数，强制要求 `Size == 规则行数`，cn_direct 和 personal 都用它。可以再检查同一批文件的 Last Updated 是否落在一个窗口内。content-hash 的算法只有搞清楚后才去校验，否则继续只记录。
- 质证：修正：“Size == 非注释行数”不是恒成立的（upstream/cn-direct/sukka-direct.conf：Size 224，实际 220 行），照原建议会误报；传输截断已由 Content-Length 比对和 IncompleteRead 处理（cn_direct.py:719-727、personal_profile.py:1827-1835）。降为 S3。修复建议改为：62/62 个归档 Sukka 文件末行都是 `################## EOF ##################`，强制检查 EOF 标记和 Last Updated 头，Size 只记录。

#### [CD-08] cn_direct 的 first_match_assertions 整套校验面向一个空列表，结果也只是"仅核对引用"
- 维度：代码 | 严重度：S3 | 工作量：S | 置信度：中 | 状态：已确认
- 位置：scripts/cn_direct.py:1046-1075、:369-370、:1292、:1346-1347；policy.json:521（`"first_match_assertions": []`）
- 现象：大约 35 行校验，带 route_template_sha256、preceding_*_sets 等字段，但没有任何代码拿这些哈希去和实际模板比对，manifest 里固定写 `"first_match_evidence_validation": "references_only"`。policy 里这个列表是空的。
- 影响：看起来像有首匹配保护，其实没有，徒增阅读负担。首匹配的真实验证在 personal_profile 的 RuleIndex 和 profile_clients 的 compare 里。
- 修复建议：（质证时待问用户，已决见下）这个字段还打算用吗？候选方案：a) 删掉字段和校验；b) 接到 personal_profile.RuleIndex 上做真实的首匹配断言。推荐 a。
- 质证：复核确认。
- 决定：用户决定（2026-10-25）：删除 first_match_assertions 字段、校验和相关测试。

#### [CD-11] tool_sha256 把 tests/ 下的文件和 fixtures 算进了 release 身份
- 维度：代码、测试 | 严重度：S3 | 工作量：S | 置信度：中 | 状态：已确认（合并 TS-11）
- 位置：scripts/build.py:284-302（TOOL_CONTENT_FILES 包含 tests/test_*.py 和 fixtures）、:733-743、:2341-2346（离线重放要求 manifest 和重算结果逐字节相等）
- 现象：只改一个测试文件，tool_sha256 就变，release_id 和 candidate_id 也跟着变，PR 里的 `validate --offline` 会因为 manifest 不一致而失败，必须连同 manifest.json 和 CHECKED_AT.json 一起重新生成。#11 就是这样（manifest.json 和 CHECKED_AT.json 各改了 6 行）。
- 影响：改测试也要重新生成发布包，抬高了改动成本；规则内容不变时也会多出一次"发布"。
- 修复建议：（质证时待问用户，已决见下）测试文件是否应该影响发布身份？候选方案：a) 只把 scripts/、PSL 和会影响输出的数据放进 tool 哈希；b) 维持现状。推荐 a。
- 质证：这是从 6a9aae5 起的有意设计（报错文案称之为 “validation input”）。影响修正：纯测试改动不会改变 rules/ 字节，客户端订阅的资源没有实际变化，影响是维护摩擦和多出一个 release_id。
- 决定：用户决定（2026-10-25）：a。tool hash 只包含 scripts 和 PSL 等影响输出的文件；计数类测试断言改为不变量断言。

#### [CD-14] 复杂度热点
- 维度：代码 | 严重度：S3 | 工作量：L | 置信度：高 | 状态：已确认
- 位置（行数/分支数，AST 统计）：personal_profile.py `_compile_compact` 348/110（:1147）、`validate_profile` 206/130（:571）、`compile` 221/68（:1520）；cn_direct.py `build_candidate` 252/72（:1116）；build.py `build_candidate` 146/29、`run_offline_validation` 132/38；profile_clients.py `_groups` 158/86（:135）
- 现象：`_compile_compact` 在一个函数里依次做 IP 规则延后、预留 slot、按 extended-matching 重排、按格式分桶、命名和渲染。`compile` 里还嵌着 DNS selector 的生成，并且为测试保留了 `group["stages"] != ["cn-direct-domain"]` 这个特判（:1636-1638）。
- 影响：#4 到 #11 都集中在这几个函数上，回归风险高。
- 修复建议：`_compile_compact` 按阶段拆成 `_collect_slot_entries`、`_order_semantic_runs`、`_bucket_by_format`、`_name_and_render`。`validate_profile` 拆成 routes、jp_members、stages、slots 四个校验函数。DNS selector 的生成抽出来共用，`compile` 和 `_compile_compact` 现在各写了一套。
- 质证：行号修正：测试特判在 personal_profile.py:1644，相关逻辑在 :1505。CD-13 删除后，profile_clients 的 `_groups` 热点会一起缩小。

#### [CD-15] Mihomo 转换器版本固定在两处，没有交叉校验
- 维度：代码 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/install_converter.py:12-22（VERSION 和 gz 的 SHA）；policy.json 的 cn_direct.converter（version 和解压后二进制的 SHA）
- 现象：升级时要同时改两个文件、四个哈希，代码不检查两边的 version 是否一致。
- 修复建议：install_converter 从 policy.json 读 version，并在写出文件后用 policy 里的 binaries 哈希再核验一次。
- 质证：补充：使用时两处都用 policy 中的二进制 SHA 校验（personal_profile.py:861-863、cn_direct.py:986-990），版本不一致会直接失败，不会静默用错，只影响升级是否方便。

### 4.4 测试

#### [TS-01] personal_profile.update() 成功路径从未被测试执行，接口变更闸门的调用点、陈旧文件删除、整包写入都没有保护
- 维度：测试 | 严重度：S1 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/personal_profile.py:2094-2131（尤其 2126-2128），scripts/personal_profile.py:2518-2550（CLI `--accept-interface-change`）；tests/test_personal_profile.py:703-734，tests/test_priority_profile.py:176-203、519-531
- 现象：测试只在两处调用 `personal_profile.update`（test_personal_profile.py:711、734），而且都走失败分支：publish_hold 开启时拒绝，或旧 manifest 不是对象。闸门 `_require_stable_client_interface` 有 9 处直接单元调用，但没有任何测试经过 `update()` 让闸门在真实流程里触发或放行。`_stale_legacy_compact_paths` 只做了纯函数测试，删除动作和 `write_bundle_transactionally(..., delete_paths=stale)` 都没测。CLI 参数 `--accept-interface-change` 是否真的传到 `update(accept_interface_change=...)`，也没有测试覆盖。
- 依据：`grep -n "update(" tests/*.py` 显示 personal_profile.update 只出现在 711 和 734 两行。update.yml 的 publish job 每天无人值守执行 `personal_profile.py update`（不带 accept 参数），能阻止日常更新静默改掉客户端接口的只有 2126 行这一次调用。docs/maintenance.md 约定"接口变化必须显式接受，不得让日常更新静默删除旧客户端订阅的资源"。
- 影响：2126 行被误删、参数传错（比如 accept_change 被写成 True），或者 2127 行在错误条件下删掉仍被订阅的文件，测试都不会红。下一次定时发布就可能直接 push 一个变了接口或删了资源的 bundle，客户端订阅的 URL 会 404 或语义改变。
- 修复建议：加一个集成测试。临时目录里铺好 policy（hold 关）、profile、`snapshots()` 归档、`legacy_inputs()`，用 `mock.patch.object(personal_profile, "_convert_mrs", ...)` 注入转换器，然后依次验证：(1) 首次 update 写出 manifest 和全部文件；(2) 改 profile 中某个 stage 的 action 后再 update，抛 "client resource interface changed"，且磁盘文件字节不变；(3) 同样的改动加 `accept_interface_change=True` 后成功，上一代 manifest 拥有的旧路径被删除，未被拥有的文件保留；(4) `main(["update","--root",...,"--offline","--accept-interface-change"])` 与 (3) 结果相同。
- 变异验证候选 M1：把 scripts/personal_profile.py:2126 整行删掉。预期现有 196 个测试全部通过（没有测试能发现）；补上 (2) 之后应该失败。
- 质证：变异 M1（删除 personal_profile.py:2126 的闸门调用）后，全量 196 个用例仍全部通过（evidence/mutation-results.json）。validate_bundle 不读上一代 manifest，publish 和 PR 两条路径上没有第二道防线；而接口会随每日上游数据变化（:1612、:1614，见 CD-06 的复现）。修复补充：用例 (2) 要加“上游数据导致接口变化”的场景。

#### [TS-02] build.py 的 update/offline 集成测试把 cn_direct 从 policy 中移除，生产配置下的 CN 直连整包、归档和重放分支没有端到端测试
- 维度：测试 | 严重度：S2 | 工作量：M | 置信度：高 | 状态：已确认
- 位置：tests/test_build.py:113-131（`prepare_temp_root` 中 `copied_policy.pop("cn_direct", None)`）；scripts/build.py:2001-2051（`_fetch_cn_candidate`、`_replay_cn_candidate`）、2125-2141（`_bundle_files` 的 cn 分支）、2330-2332（同平台 cn 输出比对）、2031（归档源哈希校验）、2020-2021
- 现象：FetchAndUpdateTests、SurgeProcessRuleTests、USRuleTests、DirectRuleTests 里所有 `run_update` 和 `run_offline_validation` 用例都基于 `prepare_temp_root`，cn_direct 被关掉，而生产 policy.json 里 cn_direct 是开着的。test_cn_replay.py 只测 `_replay_cn_candidate` 的跨平台分支，而且把 `_build_cn_candidate` 整体 mock 成 SimpleNamespace。test_cn_direct.py 测的是 `cn_direct.build_candidate`，`_convert_mrs` 也被 mock 了。
- 依据：`grep -n "Archived CN-direct source hash\|deterministic CN-direct replay\|missing from the archived" tests/*.py` 没有结果。`_bundle_files` 中 `candidate.cn_direct_candidate is not None` 分支、cn 七个输出与六个归档的写出、同平台重放比对，都只能靠 PR 时带转换器的 CI 步骤用真实数据走一遍成功路径；失败分支在任何地方都没有执行过。
- 影响：cn-direct 是旧接口里承诺仍然有效、而且体量最大的直连规则。如果 cn 输出没写进 bundle、归档哈希校验失效、或者同平台重放不再比对字节，本地和 PR 的单元测试都发现不了；只要 PR 恰好是自洽的，CI 重放也会通过。
- 修复建议：在 test_build.py 里加一个"cn_direct 开启"的 prepare 变体：用 tests/fixtures/cn-direct/* 和 `CnDirectTests.small_policy` 那套方式构造 policy；mock `cn_direct.fetch_sources` 返回 fixture，mock `cn_direct._convert_mrs` 返回固定字节，`MIHOMO_CONVERTER` 设为占位值。然后断言：update 之后 `_cn_allowed_paths()` 里的文件都存在；offline 重放通过；分别篡改一个 cn 输出和一个 cn 归档，各自抛出对应错误。
- 变异验证候选 M3：把 scripts/build.py:2330-2332 的同平台 cn 输出比对整段删掉；M4：把 2030 行的 `!=` 改成 `==` 以外的恒假条件（或直接删掉 2030-2031）。预期两处都不会让现有测试失败。
- 质证：降为 S2：成功路径每天都在 publish 中用真实数据跑一遍。变异 M3（关闭 build.py:2329-2332 的 cn 输出比对）后测试全部通过，是真缺口。M4（关闭归档哈希校验）另有第二道防线：cn_direct.py:1263-1267 逐源比对 source_provenance 的 SHA（主 agent 已核实），所以从本条中去掉，归档篡改用例的断言改为 “source_provenance SHA does not match”。

#### [TS-03] 归档路由用例 fixture（30 条 independent_cases）只在私有 migrate 流程中使用，真实个人聚合的首匹配语义没有任何自动检查
- 维度：测试 | 严重度：S2 | 工作量：M | 置信度：高 | 状态：已确认
- 位置：tests/fixtures/personal-route-cases.json（independent_cases 30 条、expected_changes 8 条、unsupported_cases 5 条）；scripts/profile_clients.py:38、1625-1665（`private_migrate` → `compare_private`）、3362
- 现象：这个 fixture 只通过 `_load_cases(root / CASE_PATH)` 被 `private_migrate` 读取（profile_clients.py:1660），而 `private_migrate` 需要不入库的私有 Clash/Surge 基线（1640-1642 读不到就抛 "private baseline inputs are unavailable"）。unittest 不加载它（IndependentCaseOracleTests 用的是内联的合成 cases）；CI 也不调用 migrate 或 compare。`validate --offline` 只做字节级确定性重放，不检查语义。现有首匹配测试（test_personal_profile.py:365-507、test_priority_profile.py）全部基于 `snapshots()` 合成源，比如 `api.apple.example`。
- 依据：`grep -n "personal-route-cases\|_load_cases\|compare_private" tests/*.py` 没有结果。fixture 说明里写的是 "Independent archive-backed route examples"，例如 `apple-relay.apple.com` 应该是 US、`openaiapi-site.azureedge.net` 应该是 US，这类用例正是规则合并、优先级、首匹配是否正确的回归基准。
- 影响：真实上游数据引起的优先级回归不会被拦住，比如 cn-direct 宽后缀盖过 AI 或 US、REJECT 落到 TEST 之后、CDN 与国内直连重叠的顺序变化。编译器改动同样拦不住，只要它是确定性的，重放就照样通过。这种回归会经每日发布直接进入客户端。
- 修复建议：加一个不需要转换器的集成测试，用仓库里真实的 `upstream/personal/` 归档、`rules/` 旧接口输入和 profiles/us-primary.json 调用 `personal_profile.compile(..., mrs_converter=lambda t: b"MRS\n"+t)`。对每条 `evidence=="archive"` 的 case，在 `RuleIndex(candidate.compact_stages[platform], platform).first_match(**subject)` 上断言 `expected_new_slot/action/dns`；`expected_old_action` 涉及私有基线，跳过。耗时大约等于一次 personal 重放减去转换器部分，偏慢的话可以单独作为 CI 步骤。
- （质证时待问用户，已决见下）这 30 条归档用例是否打算作为发布门槛？候选方案：(a) 放进 unittest；(b) 放进 update.yml 的 check 和 publish 步骤；(c) 维持只在 migrate 时使用。推荐 (b)，或者 (a) 加快速子集。
- 质证：降为 S2：编译器优先级有合成测试（test_priority_profile.py:279 等）。复核探针：用真实归档调 compile，15 条 evidence=="archive" 的用例在两个平台上 slot/action 全部匹配（30/30），可以直接作为门槛。修复建议更正：DNS 期望要用 profile_clients `_dns_match` 的口径（MatchResult.dns 返回的是 stage 标签）；只覆盖这 15 条 archive 用例。CD-13 删除 migrate 时，要把 `_dns_match` 等需要的逻辑保留或移进测试。
- 决定：用户决定（2026-10-25）：a，放进 unittest。

#### [TS-04] 离线重放的篡改检测只覆盖人工产物，主要旧接口输出、cn 输出、provenance、personal 文件集合缺失或多余都没有测试
- 维度：测试 | 严重度：S2 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/build.py:2300-2306（rules/ai-cn.list、ai-global.list、network-test.list）、2308-2314（Surge domain-set）、2333（`_validate_provenance`）；scripts/personal_profile.py:1781-1783（路径集合比对）；tests/test_build.py:1200-1210、1269-1288、1453-1468，tests/test_personal_profile.py:686-701
- 现象：现有篡改测试只改过 ai-process.list、rules/surge/us.set、direct.list/direct.set，以及 personal 的 dns-jp-manual.list 的内容。三个主输出、Surge 的 ai-cn.set 和 network-test.set、upstream/provenance.json 都没有篡改用例；personal 方面"多出一个文件"或"少一个文件"也没有用例。
- 依据：`grep -n "differs from offline replay" tests/test_build.py` 只命中 1208 和 1286 两行；`grep "provenance.json does not match\|paths mismatch" tests/*.py` 没有结果。
- 影响：PR 中对 rules/ 的手工修改（违反"不手改 rules/"的约定）或生成器的半成品输出，要靠这些比对拦截。比对逻辑一旦失效，第三方订阅最多的旧接口文件就失去了保护。
- 修复建议：把 test_offline_replay_detects_corrupt_direct_artifacts 改成参数化的 subTest，遍历 `OUTPUT_PATHS`、`SURGE_DOMAIN_SET_PATHS` 和 provenance。personal 加两个 subTest：在 rules/personal 下新建一个多余文件、删除一个 manifest 里有的文件，都应该抛 "paths mismatch"。
- 变异验证候选 M2：把 build.py:2305 的 `if actual != candidate.outputs[category]:` 改成 `if False:`；M5：删除 build.py:2333；M6：把 personal_profile.py:1782 改成 `if False:`。预期现有测试全部通过。
- 质证：变异 M2（build.py:2305）、M5（删除 :2333 `_validate_provenance`）、M6（personal_profile.py:1782）后全量测试均通过。这些比对只防 PR 手改和 update 漏写；M6 失效时多余的文件会被 `git add rules` 发布出去。

#### [TS-05] "unchanged" 审计路径（上游 30 天无变化时写 CHECKED_AT，重放时以当前 live 版本为基线重建候选）没有测试
- 维度：测试 | 严重度：S2 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/build.py:2207-2212（run_update 的 unchanged 分支）、2351-2368（run_offline_validation 的 unchanged 分支）
- 现象：所有 run_update 测试要么每次都换源（released），要么开着 hold。没有测试产出 `status == "unchanged"`，`CHECKED_AT.result == "unchanged"` 时的重放分支也从来没执行过。
- 依据：`grep -n '"unchanged"' tests/*.py` 没有结果。只读探针 evidence/TS-05-unchanged-probe.py 在临时目录里用 test_build 的辅助函数，用相同的源分别在第 4 天和第 34 天再跑一次 update，结果为 `unchanged False` → `unchanged True`，CHECKED_AT 写成 unchanged，随后 offline 重放通过。也就是说当前实现能工作，只是没有回归保护。
- 影响：上游长时间不变时，每日任务会走这个分支。这里使用的基线与 released 分支不同，改错了会导致定时任务持续失败（不发布），或者让无效的 CHECKED_AT 通过。
- 修复建议：把探针改写成测试 `test_unchanged_due_audit_is_written_and_replays`，并断言 `CHECKED_AT.candidate_id` 不等于首发 candidate_id，同时等于以 live 为基线重建出的 id。
- 变异验证候选 M7：把 build.py:2364 的 `baseline=unchanged_baseline` 改成 `baseline=baseline`。预期现有测试通过；补测后应该失败。
- 质证：变异 M7（build.py:2364）后全量测试通过。回归表现为 unchanged 当天 validate 失败、不发布（安全失败，但会持续不发布）。审查者的探针证明当前实现可以工作（evidence/TS-05-unchanged-probe.py）。

#### [TS-06] Mihomo 转换器的 SHA 白名单和执行失败处理没有测试，安装脚本的归档 SHA 校验也没有
- 维度：测试 | 严重度：S2 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/cn_direct.py:978-1023（989 行 SHA 比对）、scripts/personal_profile.py:849-882（862 行）、scripts/install_converter.py:36-37
- 现象：cn_direct 的测试都在 `_convert_mrs` 这一层 mock；personal 的测试用 `mrs_converter` lambda 或 mock `_convert_mrs`。下面这些行为都没有测试：二进制 SHA 不匹配就拒绝执行、非零退出、空输出、没有产出文件、平台键不受支持。install_converter.py 完全没有测试。
- 依据：`grep -n "does not match the approved\|MRS conversion failed\|empty\|install_converter\|_platform_key" tests/*.py` 没有结果。publish job 会执行这个下载来的二进制，它的产物 .mrs 直接发布给客户端。
- 影响：如果 SHA 校验被误改，比如条件反转或 `.get` 的键名写错，未经核准的二进制就会被执行，产物会被发布。这是供应链闸门，而且依赖转换器的路径在本地单元测试里覆盖为零。
- 修复建议：用临时目录里的一个小 shell 或 python 可执行脚本当作假转换器，把它的 sha256 写进临时 registry，覆盖四种情况：匹配时成功、SHA 不匹配时在执行前就拒绝（用脚本是否写出标记文件来判断有没有被执行）、exit 1、输出为空。install_converter 可以 mock `urlopen` 返回错误字节，断言 SystemExit 并且不写 output。
- 变异验证候选 M8：把 cn_direct.py:989 改成 `if allowed is None:`，把 personal_profile.py:862 改成 `if not expected:`。预期现有测试全部通过。
- 质证：变异 M8a（cn_direct.py:989）、M8b（personal_profile.py:862）后全量测试通过。CI 里是两层纵深防御（install_converter 校验归档 SHA，运行时校验二进制 SHA），单坏一层不会执行未核准的二进制；本地流程里转换器由用户指定，只有运行时这一层。优先补运行时 registry 校验的测试。

#### [TS-07] publish job 最后的发布闸门（hold 期间只允许 CHECKED_AT、路径白名单、base SHA 新鲜度）写成 workflow 内联 Python，没有任何测试
- 维度：测试 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：.github/workflows/update.yml 中 "Build and validate"（hold 时跳过 personal update）、"Check release bundle or held audit"、"Publish one complete bundle" 三个 step 的 heredoc
- 现象：build.py 内部的 hold 逻辑有完整测试（test_build.py:994-1054），但 push 前最后一层判断都内联在 YAML 里，单元测试覆盖不到：`set(changed) - {'CHECKED_AT.json'}`、白名单 `allowed`、`Unexpected staged path`、hold 期间跳过 `personal_profile.py update` 和 validate。这包括 hold 时用的是 `git diff --name-only`（不含未跟踪文件），再由下一步的 `git add` 加 `--cached` 补上这类组合语义。
- 依据：tests/ 下没有任何文件引用 update.yml 或这些逻辑；这些逻辑只会在真实的定时运行里执行。
- 影响：这一层是"发布会不会推送不该推送的东西"的最后防线。改动 workflow 时它是否还成立，只能事后从 main 上的提交里发现。
- 修复建议：把这三段抽成 `scripts/publish_guard.py`，提供 `held_changes_ok(paths)`、`staged_paths_ok(paths, held)` 等纯函数，workflow 改为调用这个脚本；再补单元测试：hold 期间出现 rules/x 变更时拒绝、只有 CHECKED_AT 变更时放行、`examples/` 或 `policy.json` 被暂存时拒绝。
- 质证：降为 S3：workflow 内联闸门是冗余层，build.py 的 hold（已测，对照变异会被抓到）和写入白名单（build.py:2054、personal_profile.py:2056-2059）在前。

#### [TS-08] 整包事务写入的回滚，以及越界路径拒绝，在 build.py 和 personal_profile 中都没有测试
- 维度：测试 | 严重度：S3 | 工作量：S | 置信度：高 | 状态：已确认
- 位置：scripts/build.py:2054-2122（`_ensure_allowed_paths`、`write_bundle_transactionally` 的 except 分支）；scripts/personal_profile.py:2052-2091
- 现象：测试只走过事务写入的成功路径。写到一半失败时恢复旧文件、删掉新建目录，以及 "Refusing to write unexpected bundle paths" 和 "refusing to write outside the personal bundle"，都没有用例。test_parse_failure_keeps_live_bundle_unchanged（test_build.py:919）失败在写入之前，测不到回滚。
- 依据：`grep -n "write_bundle_transactionally\|Atomic bundle write failed\|Refusing to write\|refusing to write outside" tests/*.py` 只命中 personal tamper 测试里的一次成功写入。docs/maintenance.md:103 写的是"失败不会发布部分结果"。
- 影响：回滚失效时，一次中途失败（磁盘、权限、异常）会在工作区留下半新半旧的 bundle。在 CI 里这次 job 会失败，不会 push；但在本地维护流程中，这样的半成品可能被提交进 PR。
- 修复建议：mock `_atomic_file` 或 `_atomic_write`，让它在第 N 个文件抛错，断言所有文件恢复原字节、新建目录被删除；再用 `{"../x": b""}` 和 `{"policy.json": b""}` 断言两个模块都拒绝写入。
- 变异验证候选 M9：把 build.py:2101-2111 和 personal_profile.py:2076-2087 的恢复循环改成 `pass`。预期现有测试全部通过。
- 质证：变异 M9a/M9b 后全量测试通过。降为 S3：CI 中途失败不会 push；本地半成品进了 PR 也会被 PR CI 的重放拦下。

#### [TS-09] personal_profile.compile 的测试注入点在调用方重新写了一遍分支，生产的 `_render_group_file` 在单元测试中被绕过
- 维度：测试 | 严重度：S3 | 工作量：S | 置信度：中 | 状态：已确认
- 位置：scripts/personal_profile.py:1643-1646（对比 1497-1508），1143、1685
- 现象：传入 `mrs_converter` 时，mihomo 的 domain 组不经过 `_render_group_file`，直接按内联条件 `group["stages"] != ["cn-direct-domain"]` 调 lambda。生产路径用的是 `_render_group_file` 里的 `stages == ["cn-direct-domain"]` 特例，以及 `_convert_mrs`。两份条件各自维护。
- 依据：所有 compile 测试都传 `mrs_converter`（test_personal_profile.py:73、test_priority_profile.py:290），所以 `_render_group_file` 的 mihomo domain 分支在单元测试里从没执行过。
- 影响：生产分支一旦改错，比如复用旧 cn-direct .mrs 的条件、或空集合处理，单元测试不会发现，只能等 CI 重放用真实数据发现。
- 修复建议：把注入点下沉到 `_convert_mrs`（比如在模块级加一个可替换的 converter 函数），删掉 1643-1646 的三元分支，让测试和生产走同一条路径。
- 质证：复核确认：两处条件目前互为取反、保持一致，生产分支每天由真实转换器执行。

#### [TS-10] profile_clients 公开片段渲染测试用手工构造的 candidate，元数据与真实编译输出不一致
- 维度：测试 | 严重度：S3 | 工作量：S | 置信度：中 | 状态：已确认
- 位置：tests/test_profile_clients.py:22-73（`_group`、`_candidate`）、564-581；scripts/profile_clients.py:376-381（`_surge_rule_kind`）
- 现象：fixture 里 `domestic-ip` 组装的是 IP-CIDR 规则，但被标成 `behavior: domain-set`、`format: set`。test_surge_emits_doh_node_policy_then_geoip_then_final 断言输出 `DOMAIN-SET,...domestic-ip.set,...`，固化了一个真实编译不会产生的组合：真实的 examples/personal-surge.conf:29-35 里 IP 组都是 RULE-SET。公开片段测试没有一条用 classical/text 组去断言 Surge 输出 RULE-SET。test_profile_clients 里约 200 次对 `clients.` 的引用以私有迁移函数为主（`_old_policy` 26 次），`render_*_snippet` 只有 6 次。
- 依据：见上面的行号；`grep "RULE-SET,https" tests/test_profile_clients.py` 没有结果。
- 影响：公开片段里规则类型和 no-resolve 的选择，在本地只有手工 fixture 保护，真实组合只靠 PR 时的 CI diff（需要转换器）。manifest 结构一变，手工 fixture 就会悄悄过时。
- 修复建议：渲染测试改用 `test_personal_profile.compile_candidate()` 生成的真实 candidate；至少断言 IP 和 classical 组对应 Surge 的 `RULE-SET`、Mihomo 的 `behavior: classical`，并顺手修正 `_candidate()` 的元数据。
- 质证：复核确认；PR 上有 render + diff 兜底。


## 五、需要决策的事项

无。质证中需要业务判断的 9 项已在 2026-10-25 由维护者答复，见附录 A。

## 六、审查范围与局限

- 已覆盖：`scripts/` 全部五个脚本、两个 workflow、`policy.json`、`profiles/`、`examples/`、README 与 `docs/`、`tests/` 全部测试文件。
- 未覆盖：`upstream/`、`rules/`、`tests/fixtures/` 只抽查（manifest 体积、Sukka 头尾、个别重叠检查）；`personal_profile.py` 的 RuleIndex / matching_rules 与 `profile_clients.py` 的 migrate/compare 内部逻辑只做可达性统计与抽读（后者已决定删除）；`test_cn_direct.py` 的 ACL / PSL 用例期望值未逐条核对。
- 局限：
  - 没有在真实客户端（手机、Mihomo 内核常驻运行、Surge）上加载配置；规则语义的判断依据是官方文档和 Mihomo 源码。`mihomo -t` 不加载 provider 内容，不能作为空 provider 可加载的证据。
  - 没有覆盖率工具，测试缺口靠阅读和变异验证定位。
  - 本机是 macOS arm64，发布平台是 linux-amd64；同平台的 cn MRS 字节比对分支只能在 CI 上执行。
  - 没有使用数据，无法判断 v1 个人细分文件、`rules/direct.list` 是否有外部订阅者，相关结论按维护者答复处理。
- 待查线索：
  - 大量删除没有告警：设计上不设数量门槛（docs 明确），上游返回合法但被截断的列表时会照常发布；[CD-05] 的 EOF 检查能覆盖一部分。
  - PR CI 只检查提交的 personal bundle 能否确定性重放，不提示相对 base 分支的接口变化；带 `--accept-interface-change` 的迁移在评审时没有自动提示。
  - 定时发布不重新渲染 examples；某次日常快照若改变片段内容，偏差要到下一个 PR 的 render diff 才暴露。
  - 首匹配测试的期望值与实际值都来自项目自己的 RuleIndex 模型，与真实客户端是否一致没有外部校验。
  - `check_source_migrations`、`validate_wildcard_intersections` 是 O(n²)；当前离线重放整体 37 秒，未单独测量。

## 附录

### A. 内部评审记录

- 轮数：1 轮全范围质证（三个独立 verifier，分别负责产品、代码、测试），无争议条目，未进入复核轮。
- 驳回：无。
- 合并：PD-01→CD-01，PD-04→CD-06，CD-07→PD-08，TS-13→PD-06，PD-07→CD-13，TS-11→CD-11，TS-12→CD-12。
- 定级调整：PD-02 S2→S3，PD-08 S2→S3，CD-05 S2→S3，TS-02 S1→S2，TS-03 S1→S2，TS-07 S2→S3，TS-08 S2→S3。
- 待查线索经质证不成立（不报）：只有注释的空 classical provider 可以加载（Mihomo 源码 rules/provider）；Surge `[Proxy]` 中 `reject-drop` / `reject-no-drop` 别名合法（Surge 手册 Built-in Policies）；`lan-direct-ip`、`us-proxy-ip-late` 不带 no-resolve 忠实于 Sukka 源，是有意的后置 IP 阶段；`cn-direct-extra` 中 `IP-CIDR,17.0.0.0/8,no-resolve` 没有首匹配影响；DOMAIN-WILDCARD 的 `*` 跨点与 Surge 手册、Mihomo 实现一致。
- 用户确认的决策（2026-10-25）：
  - 推送报告到公开仓库并开 draft PR：同意。
  - [CD-13] 私有迁移已完成：删除 migrate / compare。
  - [PD-02] v1 个人细分文件：保留，标为兼容接口。
  - [CD-06] personal 失败时：只冻结 personal，并先输出接口差异诊断。
  - [CD-11] 测试文件不计入发布身份。
  - [CD-10] 输出与归档规则都没变时视为 unchanged。
  - [TS-03] 15 条归档路由用例放进 unittest。
  - [CD-08] 删除 first_match_assertions。
  - [PD-11] direct 作为可单独订阅的细分类，README 补用法。
  - [CD-01] 不走私下修复渠道，在本 PR 修。

### B. 基线数据

- 单元测试：196 个，全部通过，19.8 秒，无 skip（macOS arm64，Python 3.12.0）。
- `build.py validate --offline`：macOS 上按设计拒绝（"CN-direct MRS replay requires the published converter platform"）；加 `--allow-cross-platform-replay` 后通过，37 秒。
- `personal_profile.py validate --offline`：通过，34 秒（58 个来源、34 个阶段、57 个路由组、102 个输出、22,371,578 字节）。
- `profile_clients.py render`：与 `examples/personal-mihomo.yaml`、`examples/personal-surge.conf` 一致。
- 变异验证（临时 worktree，每次一个变异，对照全量 196 通过）：

| 编号 | 变异 | 结果 | 对应条目 |
|---|---|---|---|
| M1 | 删除 personal_profile.py:2126 接口闸门调用 | 196 通过 | TS-01 |
| M2 | build.py:2305 旧接口主输出比对改为 `if False` | 196 通过 | TS-04 |
| M3 | build.py:2329 cn 输出比对关闭 | 196 通过 | TS-02 |
| M4 | build.py:2030 cn 归档哈希校验关闭 | 196 通过（另有 cn_direct.py:1263 防线，不计为缺口） | TS-02 |
| M5 | 删除 build.py:2333 `_validate_provenance` | 196 通过 | TS-04 |
| M6 | personal_profile.py:1782 路径集合比对关闭 | 196 通过 | TS-04 |
| M7 | build.py:2364 unchanged 基线换成 baseline | 196 通过 | TS-05 |
| M8a / M8b | cn_direct.py:989 / personal_profile.py:862 去掉转换器 SHA 比较 | 均 196 通过 | TS-06 |
| M9a / M9b | build.py:2106 / personal_profile.py:2079 回滚恢复循环清空 | 均 196 通过 | TS-08 |
| 对照 | build.py hold 分支改为 `if False` | 1 个失败 | 证明变异方法有效 |

- 热点（近 6 个月，排除生成数据）：tests/test_build.py 10 次、scripts/build.py 9、docs/maintenance.md 8、policy.json 7、scripts/profile_clients.py 与其测试各 6。
- 体积：manifest.json 41,745,269 字节；仓库 pack 72.44MiB（49 个提交）。
