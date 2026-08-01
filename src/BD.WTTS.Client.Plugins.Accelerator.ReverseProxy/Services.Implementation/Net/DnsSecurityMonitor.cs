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
    }
}
