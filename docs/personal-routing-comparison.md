# 个人分流与 DNS

默认 US；明确直连走 DIRECT，已确认的日本业务走 JP，拦截走 REJECT。JP 域名与 IP 集合当前为空，保留远端维护入口。

## 匹配顺序

| 顺序 | 范围 | 出口与 DNS |
|---|---|---|
| 1 | 节点、公司、本地例外与 LAN 域名 | 必要直连；公司与本地域名使用本地解析 |
| 2 | 拦截 | 保留 DROP / REJECT / Surge NO-DROP 区别；DNS 使用 US |
| 3 | 测速与出口检查 | Test，可选 US、JP、Direct；DNS 跟随选择 |
| 4 | 日本业务 | JP；JP DNS |
| 5 | 明确代理业务 | US；US DNS |
| 6 | 普通直连白名单 | DIRECT；国内 DNS |
| 7 | IP 规则 | 保留 LAN、拦截、代理、直连的先后与 no-resolve 标志 |
| 8 | GEOIP CN、兜底 | CN 直连且不主动解析，其余 US |

域名与非 IP 匹配先于会触发解析的 IP 规则，依据 [Sukka 排序说明](https://github.com/SukkaW/Surge/#规则组列表)。US 前置规则保护与直连集合重叠的业务；相同出口的 IP 规则也不能跨优先级合并。

## 聚合与维护

细分类保存在 `rules/`，客户端使用 `rules/personal/{mihomo,surge}/route/` 下的聚合。`profiles/us-primary.json` 定义顺序；`policy.json` 的 `direct_rules` 合入直连，并从 Test 排除对应范围。

Mihomo 使用 MRS 域名表与 classical 补充规则；同动作的混合 REJECT 合为一份。Surge 同一动作、DNS、扩展匹配与解析边界内的混合规则使用一份 RULE-SET，纯域名集合使用 DOMAIN-SET。Surge RULE-SET 的域名会建立索引，并非全部逐项遍历。[格式说明](https://manual.nssurge.com/rules/ruleset.html)

Surge 普通与 extended-matching 规则分开，避免扩大 SNI / HTTP Host 匹配范围。不同拒绝动作与 IP 解析阶段保留独立资源；同一物理集合内的完全重复条目只保留第一次。规则数量与变更幅度用于记录差异，不阻止更新。

规则托管域名在两端统一使用 US。iStat Menus 的 IP 查询、更新等按远端精确规则直连；天气服务与未分类域名按 US 规则处理。旧 Dashboard 不再使用本地专门例外。

## DNS

DNS 复用路由资源的域名部分，按 LAN / 公司、REJECT、Test、JP、US、普通直连的优先级选择。与默认值相同的 US、REJECT DNS 策略仍保护其与后段集合的重叠，不能直接删除。

US 使用 Google / Cloudflare，国内使用阿里 / Tencent。Test 使用 `8.8.4.4`，JP 使用 `1.0.0.1`；Surge 仅保留这两个端点的 `PROTOCOL,DOH` 出口规则，并启用 `encrypted-dns-follow-outbound-mode`。[Surge 加密 DNS](https://manual.nssurge.com/dns/encrypted-dns.html)

节点解析与 DNS 服务器域名的引导解析各有独立职责。进程、协议、IP、SNI 不能直接转换为 DNS 域名条件；本地 DNS 选择不保证等同于代理服务器侧的解析。[Mihomo DNS](https://wiki.metacubex.one/config/dns/)、[Surge Host](https://manual.nssurge.com/dns/local-dns-mapping.html)

## 客户端

Mihomo 的 `🇺🇸 US` / `🇯🇵 JP` 是 TUIC 节点；Surge 每个国家使用 Snell 6 + TUIC Smart。Test 选择国家或 `🚀 Direct`。拒绝与直连别名保留表情名称；Mihomo 的单成员组用于内建策略命名。

保留 fake-IP、AT&T / Nintendo 的真实 IP 兼容项，以及 US QUIC relay / JP native 的差异。CMFA 与 ClashBox 应保留导入的 DNS 配置；启用客户端 DNS 覆写会改变实际行为。

OpenClash 使用一个自定义覆写，移除公司及移动端条目，并在防回环处理后重新建立 LAN DNS 优先级。本地 DNS 区域与公开路由器域名分别处理，不将 system DNS 重新指回 OpenClash。

## 发布与验证

资源地址、格式、动作和匹配标志变化需要显式接口迁移。完整远端资源按哈希确认可用后才替换客户端配置；先备份并核对源文件未被其他设备修改。

验证覆盖冻结输入重放、路由与 DNS、原生内核加载、Test 出口和 OpenClash 最终生成配置。静态见证与客户端检查不代表全部真实流量；Android、Switch 联机和 NAT 行为仍需对应设备验证。私有配置、节点凭据与运行记录仅保存在本地。
