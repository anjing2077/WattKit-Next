// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 5/5 - UI 告警层: ViewModel
// ReactiveUI 属性绑定 + 2 秒定时刷新从 DnsSecurityMonitor 拉取最新状态
using System.Reactive.Linq;
using System.Runtime.CompilerServices;
using ReactiveUI;
using ReactiveUI.Fody.Helpers;

namespace BD.WTTS.UI.ViewModels;

public sealed partial class DnsSecurityStatusViewModel : ViewModelBase, IDisposable
{
    readonly BD.WTTS.Services.Implementation.DnsSecurityMonitor? _monitor;
    readonly IDisposable? _timer;
    bool _disposed;

    public DnsSecurityStatusViewModel()
    {
        // Design-time 用
    }

    public DnsSecurityStatusViewModel(BD.WTTS.Services.Implementation.DnsSecurityMonitor? monitor)
    {
        _monitor = monitor;
        // 2 秒定时刷新 (UI 线程)
        _timer = Observable.Interval(TimeSpan.FromSeconds(2), RxApp.MainThreadScheduler)
            .Subscribe(_ => Refresh());
        Refresh();
    }

    [Reactive] public string StatusText { get; set; } = "等待中…";
    [Reactive] public string StatusColor { get; set; } = "#FFA500"; // 默认黄色
    [Reactive] public string StatusIcon { get; set; } = "🛡️";
    [Reactive] public long TotalQueries { get; set; }
    [Reactive] public long TotalBlocked { get; set; }
    [Reactive] public long TotalWarnings { get; set; }
    [Reactive] public string LastHost { get; set; } = "-";
    [Reactive] public string LastDiagnostic { get; set; } = "-";
    [Reactive] public IReadOnlyList<DnsSecurityEventRow> RecentEvents { get; set; } = Array.Empty<DnsSecurityEventRow>();
    [Reactive] public IReadOnlyList<DnsChannelStatRow> ChannelStats { get; set; } = Array.Empty<DnsChannelStatRow>();

    public void Refresh()
    {
        if (_monitor == null) return;
        var stats = _monitor.GetStats();
        var events = _monitor.GetRecentEvents(30);
        var channelStats = _monitor.GetChannelStats();

        TotalQueries = stats.TotalQueries;
        TotalBlocked = stats.TotalBlocked;
        TotalWarnings = stats.TotalWarnings;
        LastHost = stats.LastHost ?? "-";
        LastDiagnostic = stats.LastDiagnostic ?? "-";

        (StatusText, StatusColor, StatusIcon) = stats.LastVerdict switch
        {
            BD.WTTS.Services.Implementation.DnsVerdict.TrustedGreen => ("安全 (DNSSEC 验签通过)", "#22c55e", "✅"),
            BD.WTTS.Services.Implementation.DnsVerdict.LikelyOkYellow => ("正常 (多数投票通过)", "#3b82f6", "🛡️"),
            BD.WTTS.Services.Implementation.DnsVerdict.SuspiciousRed => ("警告 (疑似污染, 已放行)", "#f59e0b", "⚠️"),
            BD.WTTS.Services.Implementation.DnsVerdict.MaliciousBlock => ("已拦截 (恶意 ASN/Bogon)", "#ef4444", "🚫"),
            _ => ("未知", "#808080", "❓"),
        };

        ChannelStats = channelStats.Select(c => new DnsChannelStatRow
        {
            ChannelId = c.ChannelId,
            IsSocketLevel = c.IsSocketLevel,
            TypeIcon = c.IsSocketLevel ? "🔒" : "🔓",
            SuccessCount = c.SuccessCount,
            FailCount = c.FailCount,
            AvgLatency = c.AvgLatencyMs > 0 ? $"{c.AvgLatencyMs}ms" : "-",
            SuccessRate = c.SuccessRate > 0 ? $"{c.SuccessRate * 100:F0}%" : "-",
            LastIp = c.LastIpSummary ?? "-",
        }).ToList();

        RecentEvents = events.Select(e => new DnsSecurityEventRow
        {
            Time = e.Timestamp.LocalDateTime.ToString("HH:mm:ss"),
            Host = e.Host,
            Verdict = e.Verdict.ToString(),
            VerdictColor = e.Verdict switch
            {
                BD.WTTS.Services.Implementation.DnsVerdict.TrustedGreen => "#22c55e",
                BD.WTTS.Services.Implementation.DnsVerdict.LikelyOkYellow => "#3b82f6",
                BD.WTTS.Services.Implementation.DnsVerdict.SuspiciousRed => "#f59e0b",
                BD.WTTS.Services.Implementation.DnsVerdict.MaliciousBlock => "#ef4444",
                _ => "#808080",
            },
            Diagnostic = e.Diagnostic ?? "-",
            Quorum = e.VotingQuorum,
            BlockedIps = e.BlockedIps ?? "-",
        }).ToList();
    }

    public void Reset() => _monitor?.Reset();

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _timer?.Dispose();
    }
}

public sealed class DnsSecurityEventRow
{
    public string Time { get; set; } = "";
    public string Host { get; set; } = "";
    public string Verdict { get; set; } = "";
    public string VerdictColor { get; set; } = "";
    public string Diagnostic { get; set; } = "";
    public int Quorum { get; set; }
    public string BlockedIps { get; set; } = "";
}

public sealed class DnsChannelStatRow
{
    public string ChannelId { get; set; } = "";
    public bool IsSocketLevel { get; set; }
    public string TypeIcon { get; set; } = "";
    public long SuccessCount { get; set; }
    public long FailCount { get; set; }
    public string AvgLatency { get; set; } = "-";
    public string SuccessRate { get; set; } = "-";
    public string LastIp { get; set; } = "-";
}
