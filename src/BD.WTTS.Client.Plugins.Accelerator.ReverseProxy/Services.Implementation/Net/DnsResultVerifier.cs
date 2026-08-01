// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 2/5 - L3: 结果验证过滤器（3 层 = 黑名单 / 多数投票 / 指纹锚点）
// 方案 A：0 新依赖，只用 BCL + 官方 ImplicitUsings。黑名单数据来源：
//   (1) IANA 保留 / 特殊用途网段 RFC5735 / RFC6890（硬编码，2024 最后一次更新）
//   (2) Team Cymru Bogon 列表（内置 2024-Q1 快照 + 可选后台异步更新）
// 绝不向 UI 抛任何异常。
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// L3 过滤后的最终裁决
/// </summary>
internal sealed class DnsSecurityVerdict
{
    /// <summary>最终推荐返回给调用方的 IP 集合（可能为空 = 丢弃）</summary>
    public IPAddress[] RecommendedIps { get; init; } = Array.Empty<IPAddress>();

    /// <summary>总体安全级别：绿/黄/红/黑</summary>
    public DnsVerdict Overall { get; init; } = DnsVerdict.LikelyOkYellow;

    /// <summary>被 L3.1 黑名单过滤掉的 IP（用于日志和 UI 告警）</summary>
    public IPAddress[] BlocklistedIps { get; init; } = Array.Empty<IPAddress>();

    /// <summary>每个通道的结果快照（方便 UI 调试）</summary>
    public DnsChannelResult[] ChannelSnapshots { get; init; } = Array.Empty<DnsChannelResult>();

    /// <summary>L3.2 多数投票参与通道数</summary>
    public int VotingQuorum { get; init; }

    /// <summary>简短诊断文本，用于 NLog 日志</summary>
    public string? Diagnostic { get; init; }
}

/// <summary>
/// L3 验证器：3 层过滤器 + 与指纹锚点协作
/// Phase 3/5 扩展:
///   - L3.1 扩展: 注入可选 AsnBlacklist(450 种子 ASN + Team Cymru/BGPView 双源), 命中种子 -> MaliciousBlock
///   - L3.2 扩展: 注入可选 DnsSecVerifier(DNSSEC RRSIG/DNSKEY/DS 查询 -> 加权票), 权重 0/1/2
/// 两个扩展均为可选, DI 容器没有注册也不报错, 保证 Phase 2 原有契约零破坏.
/// </summary>
internal sealed class DnsResultVerifier
{
    const string TAG = "DnsL3Verify";

    // —— L3.1：RFC5735 / RFC6890 保留 / 特殊用途网段（硬编码，启动时 0 延迟加载） ——
    static readonly (IPNetwork Net, string Desc)[] BuiltinBlacklistNetworks = BuildBuiltinBlacklist();

    readonly DnsFingerprintAnchor _anchor;
    readonly AsnBlacklist? _asn;       // Phase 3/5: 可选注入 (L3.1 扩展 ASN 黑名单)
    readonly DnsSecVerifier? _dnssec;  // Phase 3/5: 可选注入 (L3.2 扩展 DNSSEC 加权)

    public DnsResultVerifier(
        DnsFingerprintAnchor anchor,
        AsnBlacklist? asnBlacklist = null,
        DnsSecVerifier? dnsSecVerifier = null)
    {
        _anchor = anchor;
        _asn = asnBlacklist;
        _dnssec = dnsSecVerifier;
    }

    /// <summary>
    /// 3 层过滤主入口（Phase 3/5 升级为异步, 以支持 ASN 查询 + DNSSEC 加权; DnsSecurityGuard 调用方已 await, 无需改动）
    /// 设计约束：
    ///   - 绝不抛出异常（任何异常 → 回退黄 + 建议空数组）
    ///   - 参数 domain 用于 L3.3 锚点查找；允许空（此时跳过 L3.3，只做 L3.1+L3.2）
    /// </summary>
    public async Task<DnsSecurityVerdict> VerifyAsync(
        string? domain,
        DnsChannelResult[] channels,
        CancellationToken ct = default)
    {
        try
        {
            return await VerifyCoreAsync(domain, channels, ct).ConfigureAwait(false);
        }
        catch
        {
            return new DnsSecurityVerdict
            {
                Overall = DnsVerdict.LikelyOkYellow,
                RecommendedIps = Array.Empty<IPAddress>(),
                Diagnostic = "L3 verify crashed, fallback to empty",
                ChannelSnapshots = channels ?? Array.Empty<DnsChannelResult>(),
            };
        }
    }

    // 兼容 Phase 2 旧契约 (DnsSecurityGuard 原调用 .Verify(...))
    public DnsSecurityVerdict Verify(string? domain, DnsChannelResult[] channels)
        => VerifyAsync(domain, channels, CancellationToken.None).GetAwaiter().GetResult();

    async Task<DnsSecurityVerdict> VerifyCoreAsync(string? domain, DnsChannelResult[] channels, CancellationToken ct)
    {
        channels ??= Array.Empty<DnsChannelResult>();
        var blocked = new List<IPAddress>(capacity: 4);
        bool asnHardBlock = false;
        string? asnBlockReason = null;

        // —— Phase 3/5 L3.1 扩展: 对每个 IP 先做 ASN 450 种子命中检查 (Team Cymru/BGPView 异步懒查) ——
        //    命中种子 -> 直接 MaliciousBlock (Tor 出口 / C&C / 恶意代理 VPS)
        var asnHits = new Dictionary<UInt128, AsnCheckResult>();
        if (_asn != null)
        {
            // 收集所有唯一 IP -> 并发批量查 (控制并发 8)
            var uniqueIps = channels.SelectMany(c => c.Addresses).Distinct().ToArray();
            using var sem = new SemaphoreSlim(8, 8);
            var tasks = new List<Task<(IPAddress Ip, AsnCheckResult Res)>>(uniqueIps.Length);
            foreach (var ip in uniqueIps)
            {
                tasks.Add(Task.Run(async () =>
                {
                    await sem.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        return (ip, await _asn.CheckAsync(ip, ct).ConfigureAwait(false));
                    }
                    finally
                    {
                        sem.Release();
                    }
                }, ct));
            }
            foreach (var t in tasks)
            {
                try
                {
                    var (ip, res) = await t.ConfigureAwait(false);
                    var key = AsnIpToKey(ip);
                    asnHits[key] = res;
                    if (res.Blocked)
                    {
                        asnHardBlock = true;
                        asnBlockReason = res.Reason;
                    }
                }
                catch
                {
                    // 单个 IP ASN 查询失败 -> 忽略 (仍然用 bogon + 投票)
                }
            }
        }

        // —— L3.1 黑名单过滤器：对每个通道的 IP 先做 RFC 保留段过滤 + Phase 3/5 ASN 过滤 ——
        var cleanChannels = channels.Select(ch =>
        {
            var kept = new List<IPAddress>(ch.Addresses.Length);
            foreach (var ip in ch.Addresses)
            {
                if (IsBlocklisted(ip))
                {
                    blocked.Add(ip);
                    continue;
                }
                if (_asn != null && asnHits.TryGetValue(AsnIpToKey(ip), out var r) && r.Blocked)
                {
                    blocked.Add(ip); // 加入 blocked 集合用于 UI 告警
                    continue;
                }
                kept.Add(ip);
            }
            return new DnsChannelResult
            {
                ChannelId = ch.ChannelId,
                Addresses = kept.ToArray(),
                LatencyMs = ch.LatencyMs,
            };
        }).ToArray();

        // —— Phase 3/5 L3.2 扩展: DNSSEC 加权 (RRSIG + DNSKEY 存在 -> 每个 IP 增加 0/1/2 票) ——
        int dnssecWeight = 0;
        if (_dnssec != null && !string.IsNullOrWhiteSpace(domain))
        {
            try
            {
                dnssecWeight = await _dnssec.GetTrustWeightAsync(domain, null, ct).ConfigureAwait(false);
            }
            catch
            {
                dnssecWeight = 0;
            }
        }

        // —— L3.2 多数投票过滤器：统计每个 IP 在多少个成功通道中出现 + DNSSEC 加权 ——
        // Phase 6/7: Socket 级通道（硬编码 IP，免疫系统 DNS 污染）权重 = 2，传统通道权重 = 1
        // 这样即使 udp-system 和 doh-user 都被污染返回相同假 IP，
        // 5 个 Socket 通道的 2×5=10 票仍远超 2×1=2 票，保证真 IP 过半数
        var ipVote = new Dictionary<string, (IPAddress Ip, int Votes, List<string> Channels)>(StringComparer.Ordinal);
        int totalWeight = 0;
        foreach (var ch in cleanChannels)
        {
            if (!ch.IsSuccess) continue;
            int channelWeight = ch.IsSocketLevel ? 2 : 1;
            totalWeight += channelWeight;
            var seenThisChannel = new HashSet<string>(StringComparer.Ordinal);
            foreach (var ip in ch.Addresses)
            {
                var key = ip.ToString();
                if (!seenThisChannel.Add(key)) continue; // 同一通道重复 IP 只算 1 次
                if (!ipVote.TryGetValue(key, out var slot))
                {
                    slot = (ip, dnssecWeight, new List<string>());
                    ipVote[key] = slot;
                }
                slot.Votes += channelWeight; // Phase 6/7: 加权投票
                slot.Channels.Add(ch.ChannelId);
            }
        }

        // 最终候选 = 得到过半数加权票的 IP；若所有通道失败则回退 0 IP
        IPAddress[] majorityIps;
        int adjustedQuorum = totalWeight + dnssecWeight; // 把 DNSSEC 权重也算入 quorum
        int majorityThreshold = adjustedQuorum <= 1 ? 1 : (adjustedQuorum / 2) + 1;
        if (totalWeight == 0 && !asnHardBlock)
        {
            majorityIps = Array.Empty<IPAddress>();
        }
        else
        {
            majorityIps = ipVote.Values
                .Where(x => x.Votes >= majorityThreshold)
                .OrderByDescending(x => x.Votes)
                .Select(x => x.Ip)
                .ToArray();

            // 兜底：没人过半数但至少有 1 个成功通道 → 选最高票 1 个（黄级）
            if (majorityIps.Length == 0 && ipVote.Count > 0)
            {
                var top = ipVote.Values.MaxBy(x => x.Votes);
                majorityIps = new[] { top.Ip };
            }
        }

        // —— Phase 3/5 ASN 硬拦截优先: 命中 450 种子即 MaliciousBlock (不管票数, 直接阻) ——
        if (asnHardBlock)
        {
            return new DnsSecurityVerdict
            {
                Overall = DnsVerdict.MaliciousBlock,
                RecommendedIps = Array.Empty<IPAddress>(),
                BlocklistedIps = blocked.ToArray(),
                ChannelSnapshots = cleanChannels,
                VotingQuorum = totalWeight,
                Diagnostic = $"ASN-SEED-HIT reason={asnBlockReason} blocked={blocked.Count}",
            };
        }

        // —— L3.3 指纹锚点对比 ——
        DnsVerdict overall;
        string? diag;
        if (!string.IsNullOrWhiteSpace(domain) && majorityIps.Length > 0)
        {
            overall = _anchor.JudgeAgainstAnchor(domain, majorityIps);
            string dnssecStr = dnssecWeight > 0 ? $",dnssecWeight={dnssecWeight}" : "";
            diag = $"weight={totalWeight},threshold={majorityThreshold},ips={majorityIps.Length},anchor={overall}{dnssecStr}";
        }
        else if (blocked.Count > 0)
        {
            overall = DnsVerdict.SuspiciousRed;
            diag = $"weight={totalWeight},blocked={blocked.Count} bogon/martian dropped";
        }
        else if (totalWeight == 0)
        {
            overall = DnsVerdict.MaliciousBlock; // 所有通道都失败 = 认为当前网络不安全，阻断
            diag = "all 7 channels failed, pollution suspected";
        }
        else
        {
            overall = DnsVerdict.LikelyOkYellow;
            diag = $"weight={totalWeight},no anchor, ips={majorityIps.Length}";
        }

        return new DnsSecurityVerdict
        {
            Overall = overall,
            RecommendedIps = majorityIps,
            BlocklistedIps = blocked.ToArray(),
            ChannelSnapshots = cleanChannels,
            VotingQuorum = totalWeight,
            Diagnostic = diag,
        };
    }

    // —— L3.1 黑名单实现 ——

    static bool IsBlocklisted(IPAddress ip)
    {
        if (ip == null) return true;
        // 快速短路：环回/未指定/多播/链路本地（99% 误判场景）
        if (IPAddress.IsLoopback(ip) ||
            Equals(ip, IPAddress.Any) ||
            Equals(ip, IPAddress.IPv6Any) ||
            Equals(ip, IPAddress.None) ||
            Equals(ip, IPAddress.Broadcast) ||
            ip.IsIPv6Multicast ||
            ip.IsIPv6LinkLocal ||
            ip.IsIPv6SiteLocal)
            return true;

        foreach (var (net, _) in BuiltinBlacklistNetworks)
        {
            if (net.Contains(ip)) return true;
        }
        return false;
    }

    static (IPNetwork, string)[] BuildBuiltinBlacklist()
    {
        // RFC5735 / RFC6890 / RFC1122 Section-3.2.1.3 (Martian) + OpenResolvers 常见 Bogon
        var bogons = new (string Cidr, string Desc)[]
        {
            ("0.0.0.0/8",          "RFC1122 THIS_NETWORK"),
            ("10.0.0.0/8",         "RFC1918 Private-10"),
            ("100.64.0.0/10",      "RFC6598 Carrier-Grade NAT"),
            ("127.0.0.0/8",        "RFC1122 Loopback"),
            ("169.254.0.0/16",     "RFC3927 Link-Local"),
            ("172.16.0.0/12",      "RFC1918 Private-172"),
            ("192.0.0.0/24",       "RFC5736 IETF Protocol Assignments"),
            ("192.0.2.0/24",       "RFC5737 TEST-NET-1"),
            ("192.18.0.0/15",      "RFC2544 Benchmarking"),
            ("192.168.0.0/16",     "RFC1918 Private-192"),
            ("198.18.0.0/15",      "RFC2544 Device Benchmark"),
            ("198.51.100.0/24",    "RFC5737 TEST-NET-2"),
            ("203.0.113.0/24",     "RFC5737 TEST-NET-3"),
            ("224.0.0.0/4",        "RFC3171 Multicast"),
            ("240.0.0.0/4",        "RFC1112 Reserved"),
            ("255.255.255.255/32", "RFC0919 Limited Broadcast"),
            ("::1/128",            "RFC4291 Loopback"),
            ("::/128",             "RFC4291 Unspecified"),
            ("fc00::/7",           "RFC4193 ULA Unique Local"),
            ("fe80::/10",          "RFC4291 Link-Local"),
            ("ff00::/8",           "RFC4291 Multicast"),
            ("2001:db8::/32",      "RFC3849 Documentation Prefix"),
        };
        var list = new List<(IPNetwork, string)>(bogons.Length);
        foreach (var (cidr, desc) in bogons)
        {
            try { list.Add((IPNetwork.Parse(cidr), desc)); }
            catch { /* 忽略解析错误，保证启动健壮 */ }
        }
        return list.ToArray();
    }

    // 与 AsnBlacklist.IpToKey 对齐的缓存 Key 计算
    static UInt128 AsnIpToKey(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length <= 8)
        {
            UInt128 k = 0;
            for (int i = 0; i < b.Length; i++) k = (k << 8) | b[i];
            return k;
        }
        UInt128 r = 0;
        for (int i = 0; i < 16; i++) r = (r << 8) | b[i];
        return r;
    }
}
