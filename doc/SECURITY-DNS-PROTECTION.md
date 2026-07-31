# 🔒 WattKit-Next · DNS 污染防护专项设计（最高优先级安全能力）

> 背景：Watt Toolkit（SteamTools）官方 Steam 社区加速 / GitHub 加速模块
> 大量依赖 DNS 解析 + Hosts 重写，但无**端到端 DNS 结果验证**机制，
> 在国内运营商/公共 Wi-Fi 环境下极易遭受 **DNS Query ID 猜测注入**、
> **本地 hosts 文件被恶意软件改写**、**中间人篡改 DoH/DoT 返回**等攻击，
> 导致 Steam 登录凭据被窃取 / 下载链接被劫持 / GitHub 2FA 验证码泄露。
>
> 本设计在官方代码基础上新增**5 层 DNS 结果验证 + 2 级告警机制**，
> 保留官方 GPL-3.0 协议公开开源。

---

## 🥅 5 层安全架构（从上到下，越下层越硬核、越抗攻击）

```
┌───────────────────────────────────────────────────────────────┐
│ L1  UI 层：实时可视安全仪表板 + 颜色分级（绿/黄/红）              │
│       每 1 秒刷新 "DNS 健康分 0-100"                             │
├───────────────────────────────────────────────────────────────┤
│ L2  解析策略层：多通道并行解析 + 最快可信胜出                     │
│       （53/UDP Plain + DoH + DoT + DNSCrypt + 官方可信库）× 并行  │
├───────────────────────────────────────────────────────────────┤
│ L3  结果验证层：DNSSEC + 多源多数投票 + 黑名单校验                │
│       RRSIG 验签通过 ＆ 3/5 源一致 → Trusted（绿）                │
├───────────────────────────────────────────────────────────────┤
│ L4  系统保护层：Hosts 文件完整性守护 + 系统 DNS 回滚保护          │
│       SHA-256 链 + 拒绝非本进程写入 hosts                        │
├───────────────────────────────────────────────────────────────┤
│ L5  内核辅助层：（可选）通过 WinDivert 强制把 53/UDP→可信通道      │
│       防止任何第三方进程绕过 Watt Toolkit 直接发 DNS             │
└───────────────────────────────────────────────────────────────┘
```

---

## 🔬 Layer 2 · 解析通道矩阵（默认 5 通道并行，可配置）

| 通道 ID | 类型 | 默认上游服务器（权威、无日志政策） | 用途 |
|---|---|---|---|
| `udp-system` | 53/UDP Plain | 用户当前系统 DNS（兼容性兜底） | 对比基线（通常最容易被污染） |
| `doh-google` | DoH over TLS 1.3 | `https://dns.google/dns-query` | 全球最可信 DoH（IPv4+IPv6） |
| `doh-cloudflare` | DoH over TLS 1.3 + ECH | `https://1.1.1.1/dns-query` | 速度最快，ECH 加密 SNI |
| `dot-quad9` | DoT TCP/853 | `dns.quad9.net:853` (9.9.9.9) | 带威胁情报过滤 |
| `dns-google-public` | DNSSEC 强制 UDP 8.8.8.8 | `8.8.8.8` / `8.8.4.4` + EDNS0-DO 位 | DNSSEC RRSIG 验证 |
| `dns-opennic` | OpenNIC 社区解析 | 官方公布的一组 tier-2 节点 | 去中心化兜底 |

> ✅ 策略：默认并行发起全部 5 通道，L3 多数投票（**≥3/5 同源 IP 判定可信**）；
> 若 5 通道不一致 → 进入 L3.2 DNSSEC 强校验阶段。

---

## 🛡️ Layer 3 · DNS 结果验证三层过滤器

### L3.1 黑名单 / 威胁情报比对（10μs 级别，最前面）
```csharp
// 新建静态类 DnsSecurity.Blacklist.cs（独立 NuGet：MaxMind.GeoIP2 + AB-P 中国 ASN 库）
public static bool IsKnownPollutedIp(IPAddress ip)
{
    // 1) 经典运营商 DNS 污染返回池（硬编码 20+ 条，可云端下发）
    // 2) 国内非 Top-3 云厂商 IDC IP 段突然出现 → 标黄
    // 3) 与历史 30 天解析基线 IP 段不一致 → 标黄
    // 4) 命中 MaxMind 匿名代理/已知 C&C → 直接 RED + 拒绝
    return ThreatIntel.Match(ip, ThreatKind.DnsPollution | ThreatKind.Cnc);
}
```

### L3.2 多数投票 + DNSSEC RRSIG 强校验（100ms 级别，硬核）
```csharp
// 新建 DnsSecurity.Verifier.cs（复用 ARSoft.Tools.Net 或官方 BIND 导出的 RRSIG 验证）
public enum DnsVerdict {
    TrustedGreen,   // ≥4/5 源一致 且 DNSSEC OK（如果有签名）
    LikelyOkYellow, // 3/5 源一致，DNSSEC 无签名
    SuspiciousRed,  // <3/5 源一致，或 DNSSEC RRSIG 验签失败
    MaliciousBlock  // L3.1 黑名单 或 与官方已知签名锚点冲突 → 直接 BLOCK
}

// 投票规则（防 Sybil 攻击）：每个 IP 不能因为某通道返回多次就权重翻倍。
// 只看"去重后的 IP 集合大小"与"权威 DNSSEC 签名"。
```

### L3.3 历史指纹锚点（长期记忆）
```text
对 Steam 社区 / GitHub / Epic / Ubisoft / EA 等 20 个官方域名：
  · 保存近 30 天 RRSIG 公钥 KSK/ZSK 的 KeyTag 指纹 → 突变 = RED
  · 保存近 30 天 IP 返回集合（CIDR 聚合）→ 新段出现需 ≥3/5 源同时出现才接受
```

---

## 🔧 Layer 4 · Hosts + 系统 DNS 保护

### 问题（Watt Toolkit 官方当前的安全盲点）
官方加速模块修改 `C:\Windows\System32\drivers\etc\hosts` 但**不校验其他进程对 hosts 的写入**。
一旦用户安装"破解补丁/游戏修改器"，其可偷偷在 hosts 注入：
```
203.0.113.45  store.steampowered.com   ← 假 Steam 商店，偷登录密码
```

### 修复方案（本项目必须加）
1. **SHA-256 完整性链**：
   ```
   hosts 当前内容 sha256 = H(current)
   若 Watt Toolkit 未在写 hosts，但 H(current) != lastKnownGood → 立即弹系统通知 + 颜色：RED
   可选："一键恢复 hosts 到 Watt Toolkit 最后一次可信版本"
   ```
2. **只允许本进程 PID 对 hosts 的独占写入**：
   - 通过 `FileShare.None` + 文件锁 + 循环检测（间隔 1 秒）
3. **系统 DNS 设置回滚保护**：
   - 若 60 秒内系统 DNS 被改为非白名单服务器 → 自动还原（用户可关）

---

## 🚨 2 级告警 + 用户处置 UI

| 级别 | 触发条件 | UI 表现 | 默认动作 |
|---|---|---|---|
| 🟡 YELLOW WARNING | 3/5 源不一致 / DNSSEC 无签名但投票过 / 陌生 IP 段首次出现 | 顶部条变黄；"DNS 健康分 60-80"；加速按钮提示"可能有污染，建议切换 DoH-only 模式" | 仅提示，不阻断 |
| 🔴 RED BLOCK | <3/5 源一致 / DNSSEC RRSIG 验签失败 / 命中 L3.1 黑名单 / hosts 被篡改 / 系统 DNS 被恶意修改 | 整个左侧导航变红；DNS 健康分 0-59；模态弹窗强制确认 | **默认阻断本次解析，返回 0.0.0.0 + 展示 5 通道对比详情** |

---

## ✅ 验证方法（集成测试必过）

| 用例 ID | 测试场景 | 预期结果 |
|---|---|---|
| T-POL-01 | 正常网络：解析 `store.steampowered.com` | L3 5/5 绿；健康分 100；缓存 60s |
| T-POL-02 | 模拟污染：伪造 53/UDP 返回假 IP（在本机用 dnsmasq 搭建恶意 DNS） | 5 通道：1/5 假 + 4/5 真 → 投票通过；但单源不一致→健康分 85 黄 |
| T-POL-03 | 重度污染：3 个通道同时返回 203.0.113.0/24 假 IP | 3/5 假 = 3/5 源不一致 → RED BLOCK；阻止解析；弹窗展示 5 通道对比表 |
| T-POL-04 | 恶意软件改 hosts：在 steam 域名下塞假 IP | L4 哈希校验 1 秒内检测到 → 系统通知 + 一键恢复 hosts |
| T-POL-05 | 关闭所有通道，仅留 53/UDP（极端恶劣环境） | 自动降级：启用 DNSCrypt + 本地 Hosts 锚点兜底；健康分 60 黄提示 |
| T-INT-01 | 性能：冷启动 DNS 子系统 | < 30 ms；**不阻塞 UI 线程（配合 Task/Lazy<T> 启动优化）** |

---

## 🧩 对应官方 SteamTools 代码改造点（WPF A1 / .NET 8）

```
src/
├── ST.Client.Desktop/
│   ├── ViewModels/
│   │   └── DnsSecurityDashboardViewModel.cs   ← 【新增】健康分 0-100 可视化
│   ├── Views/
│   │   └── DnsSecurityDashboardPage.xaml      ← 【新增】L1 实时仪表板（接入侧边栏）
│   └── Controls/
│       └── DnsHealthIndicatorBadge.xaml       ← 【新增】绿/黄/红 三色徽标（全局复用）
└── ST.Core/
    ├── DnsSecurity/
    │   ├── DnsParallelResolver.cs             ← 【新增】L2 5 通道并行 + 取消令牌
    │   ├── DnsResultVerifier.cs               ← 【新增】L3.1 + L3.2 三层过滤器
    │   ├── DnsFingerprintAnchor.cs            ← 【新增】L3.3 30 天指纹 + 本地 JSON 持久化
    │   ├── HostsIntegrityGuard.cs             ← 【新增】L4 SHA-256 守护 + PID 独占写
    │   └── SystemDnsRollbackGuard.cs          ← 【新增】L4 系统 DNS 60s 回滚保护
    └── ThreatIntel/
        ├── DnsPollutionBlacklist.json         ← 【新增】已知污染 IP/ASN 池（可云端热更新）
        └── ThreatIntelLoader.cs               ← 【新增】每 6 小时拉取签名过的黑名单
```

---

## 📜 法律合规声明（GPL-3.0）

本文件属于 WattKit-Next 项目的二次开发设计文档，
**项目源码整体必须 GPL-3.0 公开开源**，因为基于
[BeyondDimension/SteamTools](https://github.com/BeyondDimension/SteamTools)
（GPL-3.0 License）Fork 并修改。完整协议见仓库根目录 `LICENSE`。
本文档不包含任何绕过合法网络监管的功能设计，所有 DNS 通道均使用
全球主流公开可信 DoH/DoT/DNSCrypt 官方服务，
仅用于**校验 DNS 返回结果完整性与防止中间人篡改**，符合中国法律规定。
