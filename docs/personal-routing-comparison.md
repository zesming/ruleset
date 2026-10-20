# 个人分流与 DNS 对照

客户端使用按优先级与出口组织的 `priority-*` 聚合。原有细分类及旧接口继续发布，便于单独使用；节点、公司内网、DNS 端点和网络接管设置留在客户端。完整配置与原始校验记录包含私有信息，只保存在本地。

## 顺序与含义

| 顺序 | 规则 | 出口与 DNS |
|---|---|---|
| 1 | 节点端点、公司内网、LAN、本地明确例外 | 直连例外走 DIRECT；LAN/公司使用系统 DNS，普通必要直连使用国内 DNS；继承的规则托管基础设施固定 US |
| 2 | 网络测试、出口查询 | TEST；默认 US，DNS 随 TEST 选择 |
| 3 | 拦截 | 保留 DROP / plain / NO-DROP 差异；域名解析采用 US 策略 |
| 4 | 已明确需要日本出口的业务 | JP；当前为空 |
| 5 | 明确 US 与必须代理业务 | US；US DNS |
| 6 | 大陆与普通直连白名单 | DIRECT；国内 DNS |
| 7 | IP 规则 | 保留 LAN、拦截、代理、直连等原先后及各项 no-resolve 语义 |
| 8 | GEOIP CN、最终兜底 | CN → DIRECT，不主动解析；其余 → US |

该顺序遵循 [Sukka 的排序说明](https://github.com/SukkaW/Surge/#规则组列表)：域名及非 IP 匹配先于会触发解析的 IP 规则。必要的节点精确 IP 例外仍放最前。大域名表保留 Mihomo MRS / Surge DOMAIN-SET，不为减少 provider 数而把数十万条域名塞进逐项遍历的 classical 集合。

REJECT 的不同动作、Surge extended-matching、域名格式与解析触发边界是必要的物理拆分。同一业务优先级可能对应多个文件；客户端不再逐项暴露 AT&T、AI、Apple、Microsoft、CDN 分类。远端规则成员改变后客户端可按现有地址刷新；改变地址、格式、动作或匹配标志仍属于需要配套配置的接口迁移。

## 相对上一版的有意变化

所有比较使用同一份冻结输入，不将上游更新与本次重排混在一起。以下是规则推演的见证，不是实际流量统计。

| 变化 | 范围与例子 |
|---|---|
| TEST 提前 | 测速与拦截重叠的 20 个见证仍走 TEST |
| US 先于普通直连 | 15 条被原直连完整覆盖的 CDN 规则，以及 17 个部分重叠的下载主机见证由 DIRECT 变 US；例如 `cdn.nintendo.net`、`time.apple.com`、`objects.githubusercontent.com`、`registry-1.docker.io` |
| REJECT 提前 | 15 个 AI 相关主机见证改为拦截，例如 `r.openai.com`、`statsig.anthropic.com`、`opt.doubao.com`；不据此声称所有子域都改变，也不保证相应应用功能不受影响 |
| 去掉多余代理组 | Mihomo TUIC 节点直接为 US / JP；Surge Snell 6 节点直接为 US / JP，TUIC 留作 TEST 选项；日常 Surge 从 Smart 协议选择变为固定 Snell 6 |

Sukka direct 的关键词、普通业务和进程规则继续归入后段直连；不将整份集合提前，防止 `adp.cnki.net`、`adsp.xunlei.com` 等原拦截项被宽范围直连盖过。

不删除上述重叠源规则。后续若要按具体业务改变选择，应维护远端成员或优先级，并重做对应见证检查。

冻结输入生成的客户端资源数量：Mihomo 从 32（含 4 个专用 DNS 资源）降为 18；Surge 从 36（含 7 个专用 DNS 资源）降为 20。新方案没有专用 DNS 资源。US 在 Mihomo 中为一份集合；Surge 保留普通与 extended-matching 两份，防止扩大 SNI／CNAME 匹配范围。

JP 不通过 `.jp`、日本 GeoIP 或 Nintendo 全平台自动归类。当前没有明确日本出口业务，JP 业务集合保持空；未来只加入有来源与理由的成员。Nintendo STUN 与 AT&T 的真实 IP 兼容例外保留，不因此将 Nintendo 全部导向 JP。

## DNS 与节点

DNS 直接复用路由资源的域名匹配部分，不再为每个业务另建 DNS provider。[Surge Host](https://manual.nssurge.com/dns/local-dns-mapping.html) 的 RULE-SET 忽略 IP 项；Mihomo 的 classical DNS 匹配同样只采用域名规则。进程、IP、UA、URL、SNI 或协议条件不会凭空变成 DNS 域名条件。

LAN 与本地 DNS 映射优先；随后按路由优先级依次绑定 TEST、REJECT、JP、US、普通直连的解析器。相同出口的不同优先级不能跨区段合并，否则会改变重叠域名的 DNS。Mihomo 只把同一区段的 provider 合并成一个 selector；Surge 每个资源一条 Host 引用。

US 保留 Google/Cloudflare 双解析器，国内保留阿里/Tencent 双解析器。TEST 使用 `8.8.4.4` 并绑定 TEST，JP 使用 `1.0.0.1` 并绑定 JP；后两者目前各一个 anycast 地址，故障冗余少于双解析器。Surge 对端点的出口规则限定 PROTOCOL,DOH，同地址普通连接仍按业务规则判断。

DNS 查询只有域名上下文，不能保证进程或 SNI 改写后的每个连接都与该域名 DNS 使用同一出口。Surge 的本地 DNS 选择与 Snell/TUIC 服务器侧解析也不是同一阶段。这里的 DNS 归属指本地配置的解析器及其发送出口。

## 验证与部署边界

本次验收包括：旧细分类字节兼容、完整离线重放、实际客户端语法与资源加载、路由和 DNS 选择、TEST 切换、空 JP、DoH 与普通连接的区分、出站请求和全引用闭包。本版冻结输入的 130 项自动检查、42 个独立路由/DNS 用例均通过，两端各完成约 135 万个代表样本的旧版对照。样本数包含派生与重复探测，不是请求量或独立主机数。

桌面运行验证中，Mihomo 的 24 个路由用例、24 个 DNS 选择用例和 18 个资源加载均通过；这 24 个 DNS 选择用例使用真实 provider 与受控本地 UDP 解析器；真实 US/JP TEST 切换返回对应国家出口，普通域名 fake-IP 与 AT&T 真实 IP 解析符合预期。Surge 的 31 个路由用例、9 个 DNS 选择用例和 20 个资源加载均通过，TEST 的两种节点选择均获得 HTTP 成功响应与真实 DNS 答案；DoH 决策链也随选择切换。DNS 选择用例包含不存在域名的空答案，空答案只证明解析器选择，不算成功解析。两端验证均未抓包断言 DoH 实际出口。Snell 6 的两个现用节点均收到 UDP 测试响应。

现用配置只有在配套 PR 合并、完整远端资源按哈希确认可用后才替换。替换前保存原文件并核验未被其他设备修改；校验失败可恢复同一版配置。一次 Git 提交保证服务端整版发布，不保证客户端同时刷新多个 main URL；接口变更由发布门禁阻止自动迁移。

桌面内核与 Surge CLI 不能代替 OpenClash 覆写、Android/ClashBox 实机、Switch 联机和 NAT 类型验证；这些需要对应设备的运行证据。
