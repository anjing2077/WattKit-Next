// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 5/5 - UI 告警层: 实时监控数据源
// 线程安全环形缓冲区收集 DnsSecurityGuard 的拦截/告警事件,
// 供 ViewModel 轮询展示. 绝不阻塞 DNS 解析主路径.
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>单条 DNS 安全事件记录</summary>
public sealed class DnsSecurityEvent
{
    public DateTimeOffset Timestamp { get; init; }
    public string Host { get; init; } = "";
    public DnsVerdict Verdict { get; init; }
    public string? Diagnostic { get; init; }
    public string? BlockedIps { get; init; }
    public int VotingQuorum { get; init; }
    public int DnssecWeight { get; init; }

    /// <summary>Phase 7: 每个通道的结果快照（ChannelId + 成功/失败 + 延迟 + IP 摘要）</summary>
    public DnsChannelSnapshot[]? ChannelSnapshots { get; init; }
}

/// <summary>单通道快照（Phase 7）</summary>
public sealed class DnsChannelSnapshot
{
    public required string ChannelId { get; init; }
    public bool IsSocketLevel { get; init; }
    public bool IsSuccess { get; init; }
    public long LatencyMs { get; init; }
    public string? IpSummary { get; init; }
}

/// <summary>DNS 安全实时监控器 (线程安全单例)</summary>
internal sealed class DnsSecurityMonitor
{
    const int MaxEvents = 200;
    readonly ConcurrentQueue<DnsSecurityEvent> _events = new();
    long _totalQueries;
    long _totalBlocked;
    long _totalWarnings;
    DnsVerdict _lastVerdict = DnsVerdict.LikelyOkYellow;
    DateTimeOffset _lastEventTime = DateTimeOffset.MinValue;
    string? _lastHost;
    string? _lastDiagnostic;

    // Phase 7: 通道级统计（ChannelId → (successCount, failCount, totalLatencyMs, lastIpSummary)）
    readonly ConcurrentDictionary<string, (long Success, long Fail, long TotalLatencyMs, string? LastIpSummary, DateTimeOffset LastSeen)> _channelStats = new();

    /// <summary>记录一次 DNS 安全事件 (由 DnsSecurityGuard 调用, 绝不抛异常)</summary>
    public void Record(DnsSecurityEvent evt)
    {
        if (evt == null) return;
        _events.Enqueue(evt);
        while (_events.Count > MaxEvents)
            _events.TryDequeue(out _);

        Interlocked.Increment(ref _totalQueries);
        _lastVerdict = evt.Verdict;
        _lastEventTime = evt.Timestamp;
        _lastHost = evt.Host;
        _lastDiagnostic = evt.Diagnostic;

        if (evt.Verdict == DnsVerdict.MaliciousBlock)
            Interlocked.Increment(ref _totalBlocked);
        else if (evt.Verdict == DnsVerdict.SuspiciousRed)
            Interlocked.Increment(ref _totalWarnings);

        // Phase 7: 聚合通道级统计
        if (evt.ChannelSnapshots != null)
        {
            foreach (var ch in evt.ChannelSnapshots)
            {
                _channelStats.AddOrUpdate(
                    ch.ChannelId,
                    // 新通道首次出现
                    ch.IsSuccess
                        ? (1, 0, ch.LatencyMs, ch.IpSummary, evt.Timestamp)
                        : (0, 1, 0, ch.IpSummary, evt.Timestamp),
                    // 已存在通道：累加
                    (_, existing) => ch.IsSuccess
                        ? (existing.Success + 1, existing.Fail, existing.TotalLatencyMs + ch.LatencyMs, ch.IpSummary, evt.Timestamp)
                        : (existing.Success, existing.Fail + 1, existing.TotalLatencyMs, ch.IpSummary, evt.Timestamp));
            }
        }
    }

    /// <summary>获取最近 N 条事件快照 (线程安全, 返回副本)</summary>
    public List<DnsSecurityEvent> GetRecentEvents(int count = 50)
    {
        return _events.ToArray().Take(count).Reverse().ToList();
    }

    /// <summary>总体统计快照</summary>
    public (long TotalQueries, long TotalBlocked, long TotalWarnings, DnsVerdict LastVerdict,
            DateTimeOffset LastEventTime, string? LastHost, string? LastDiagnostic) GetStats()
    => (Interlocked.Read(ref _totalQueries),
        Interlocked.Read(ref _totalBlocked),
        Interlocked.Read(ref _totalWarnings),
        _lastVerdict, _lastEventTime, _lastHost, _lastDiagnostic);

    /// <summary>清空所有统计 (UI "重置" 按钮调用)</summary>
    public void Reset()
    {
        while (_events.TryDequeue(out _)) { }
        Interlocked.Exchange(ref _totalQueries, 0);
        Interlocked.Exchange(ref _totalBlocked, 0);
        Interlocked.Exchange(ref _totalWarnings, 0);
        _lastVerdict = DnsVerdict.LikelyOkYellow;
        _lastEventTime = DateTimeOffset.MinValue;
        _lastHost = null;
        _lastDiagnostic = null;
        _channelStats.Clear();
    }

    /// <summary>Phase 7: 获取通道级统计快照（按 ChannelId 排序）</summary>
    public List<DnsChannelStat> GetChannelStats()
    {
        return _channelStats
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv =>
            {
                var (success, fail, totalLatency, lastIp, lastSeen) = kv.Value;
                var total = success + fail;
                return new DnsChannelStat
                {
                    ChannelId = kv.Key,
                    IsSocketLevel = kv.Key.StartsWith("doh-", StringComparison.Ordinal)
                                 || kv.Key.StartsWith("dot-", StringComparison.Ordinal),
                    SuccessCount = success,
                    FailCount = fail,
                    AvgLatencyMs = success > 0 ? totalLatency / success : 0,
                    SuccessRate = total > 0 ? (double)success / total : 0,
                    LastIpSummary = lastIp,
                    LastSeen = lastSeen,
                };
            })
            .ToList();
    }
}

/// <summary>Phase 7: 通道级统计快照（供 UI 展示）</summary>
public sealed class DnsChannelStat
{
    public required string ChannelId { get; init; }
    public bool IsSocketLevel { get; init; }
    public long SuccessCount { get; init; }
    public long FailCount { get; init; }
    public long AvgLatencyMs { get; init; }
    public double SuccessRate { get; init; }
    public string? LastIpSummary { get; init; }
    public DateTimeOffset LastSeen { get; init; }
}
