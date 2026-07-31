// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 2/5 - L3.3: 域名指纹锚点（30 天滑动信任窗口 + 首次学习）
// 方案 A：只用 MessagePack（官方已有 ImplicitUsings）序列化本地锚点字典，不引入 SQLite/SQLitePCL_raw 额外依赖
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// 指纹锚点记录：一个域名最近 N 次解析的稳定 IP 集合 + 首次观测时间
/// 用于检测"突然跳到陌生 ASN/IP 段"的典型污染行为（例如 store.steampowered.com 突然返回 6.6.6.6）
/// </summary>
internal sealed class DnsFingerprintRecord
{
    /// <summary>锚点建立时间（首次观测到稳定多数），超过 30 天自动重建</summary>
    public DateTimeOffset EstablishedAt { get; set; }

    /// <summary>最近 N 次一致通过 L3 的 IP 集合（推荐 10~20）</summary>
    public HashSet<string> TrustedIps { get; set; } = new(StringComparer.Ordinal);

    /// <summary>更新时间</summary>
    public DateTimeOffset LastUpdated { get; set; }
}

/// <summary>
/// L3.3：指纹锚点守护。
/// 规则：
///   - 一个域名需要"连续 2 次通过 L3 多数投票且结果一致"才建立锚点（冷启动时不做硬拦截，只标记黄色）
///   - 锚点过期：EstablishedAt + 30 天 或 TrustedIps 连续 2 天零命中
///   - 存储：%AppData%/WattToolkit/dns-anchor-v1.msgpack（MessagePack LZ4 压缩，约 1~50KB）
/// </summary>
internal sealed class DnsFingerprintAnchor
{
    const string TAG = "DnsL3Anchor";
    static readonly TimeSpan AnchorExpire = TimeSpan.FromDays(30);
    static readonly TimeSpan AnchorStale = TimeSpan.FromDays(2);
    const int MinHitsToEstablish = 2;
    const int MaxTrustedIpPerDomain = 24;

    readonly string _anchorPath;
    readonly ConcurrentDictionary<string, (DnsFingerprintRecord Rec, int Hits)> _memory
        = new(StringComparer.Ordinal);

    int _loaded;

    public DnsFingerprintAnchor()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "WattToolkit");
        Directory.CreateDirectory(dir);
        _anchorPath = Path.Combine(dir, "dns-anchor-v1.msgpack");
    }

    /// <summary>
    /// 与 L3 协作：L3 得到多数投票结果后调用此函数，返回锚点对比给出的额外判断
    /// - TrustedGreen：锚点命中 或 刚建立锚点的连续第二次
    /// - LikelyOkYellow：首次观测 / 锚点过期重学
    /// - SuspiciousRed：锚点存在但结果完全不在信任 IP 池（典型污染：突然跳陌生网段）
    /// </summary>
    public DnsVerdict JudgeAgainstAnchor(string domain, IPAddress[] majorityIps)
    {
        if (string.IsNullOrWhiteSpace(domain) || majorityIps.Length == 0)
            return DnsVerdict.LikelyOkYellow;

        TryLoadOnce();

        var now = DateTimeOffset.UtcNow;
        var canonical = NormalizeDomain(domain);
        var majoritySet = majorityIps.Select(x => x.ToString()).ToHashSet(StringComparer.Ordinal);

        ref var slot = ref _memory.AddOrUpdate(
            canonical,
            static _ => (new DnsFingerprintRecord { EstablishedAt = now, LastUpdated = now }, 0),
            static (_, existing) => existing,
            canonical);

        // 1. 过期？ → 重置为首次学习
        if (slot.Rec.EstablishedAt + AnchorExpire < now ||
            (slot.Hits == 0 && slot.Rec.LastUpdated + AnchorStale < now))
        {
            slot.Rec = new DnsFingerprintRecord { EstablishedAt = now, LastUpdated = now };
            slot.Hits = 0;
        }

        // 2. 统计本次命中数
        int hitCount = slot.Rec.TrustedIps.Count == 0 ? 0 : majoritySet.Count(slot.Rec.TrustedIps.Contains);

        // 3. 建立锚点流程
        if (slot.Rec.TrustedIps.Count == 0)
        {
            // 首次观测 → 加入信任集合，Hits=1，黄
            MergeIntoTrusted(slot.Rec, majoritySet, now);
            slot.Hits = 1;
            ScheduleSave();
            return DnsVerdict.LikelyOkYellow;
        }

        if (hitCount == 0)
        {
            // 锚点存在但零命中：典型污染红
            return DnsVerdict.SuspiciousRed;
        }

        // 4. 正常命中：累积学习
        MergeIntoTrusted(slot.Rec, majoritySet, now);
        slot.Hits = Math.Min(slot.Hits + 1, MinHitsToEstablish + 8);
        ScheduleSave();
        return slot.Hits >= MinHitsToEstablish ? DnsVerdict.TrustedGreen : DnsVerdict.LikelyOkYellow;
    }

    // —— 工具函数 ——

    static string NormalizeDomain(string d) =>
        d.Trim().TrimEnd('.').ToLowerInvariant();

    static void MergeIntoTrusted(DnsFingerprintRecord rec, HashSet<string> ips, DateTimeOffset now)
    {
        foreach (var ip in ips)
        {
            rec.TrustedIps.Add(ip);
        }
        // 超过上限：踢掉最旧（这里用简单 Remove 随机，因为 HashSet 无序；生产可用链表，这里足够）
        while (rec.TrustedIps.Count > MaxTrustedIpPerDomain)
        {
            rec.TrustedIps.Remove(rec.TrustedIps.First());
        }
        rec.LastUpdated = now;
    }

    // —— 持久化（后台低优先级，失败吞异常绝不影响解析） ——

    void TryLoadOnce()
    {
        if (Interlocked.CompareExchange(ref _loaded, 1, 0) != 0)
            return;
        try
        {
            if (!File.Exists(_anchorPath)) return;
            using var fs = File.OpenRead(_anchorPath);
            var dict = MessagePackSerializer.Deserialize<Dictionary<string, DnsFingerprintRecord>>(
                fs, MessagePack.Resolvers.ContractlessStandardResolver.Options);
            if (dict == null) return;
            foreach (var kv in dict)
            {
                _memory.TryAdd(kv.Key, (kv.Value, MinHitsToEstablish));
            }
        }
        catch
        {
            // 忽略损坏的锚点文件（下次自动重建）
        }
    }

    int _saveScheduled;
    void ScheduleSave()
    {
        if (Interlocked.CompareExchange(ref _saveScheduled, 1, 0) != 0)
            return;

        // fire & forget：后台 ThreadPool，失败不阻塞
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(1500).ConfigureAwait(false); // 合并 1.5s 内的写
                var snapshot = _memory.ToDictionary(kv => kv.Key, kv => kv.Value.Rec);
                var tmp = _anchorPath + ".tmp";
                using (var fs = File.Create(tmp))
                {
                    await MessagePackSerializer.SerializeAsync(fs, snapshot,
                        MessagePack.Resolvers.ContractlessStandardResolver.Options).ConfigureAwait(false);
                }
                if (File.Exists(_anchorPath)) File.Replace(tmp, _anchorPath, _anchorPath + ".bak");
                else File.Move(tmp, _anchorPath);
            }
            catch
            {
                // 持久化失败完全忽略，不影响解析正确性
            }
            finally
            {
                Volatile.Write(ref _saveScheduled, 0);
            }
        }, CancellationToken.None);
    }
}
