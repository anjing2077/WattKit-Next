// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 2/5 - DnsSecurityGuard：装饰器模式，完整实现 IDnsAnalysisService
// 装饰策略：
//   - AnalysisDomainIpAsync（核心路径）= 先跑 L2 并行 → L3 三层过滤 → 裁决后 yield return
//   - AnalysisHostnameTimeAsync / GetHostByIPAddressAsync / GetIsIpv6SupportAsync = 直接走 inner(原 SwitchImpl)
//   - 红色(MaliciousBlock)直接 yield break（阻断），不把污染 IP 交给 YARP
//   - 永远不抛异常（必要时 NLog.Warn 记录，UI 层无感）
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// DNS 安全守卫：IDnsAnalysisService 装饰器。
/// 零侵入：不修改官方 DnsAnalysisServiceSwitchImpl 任何一行，通过组合来添加 L2+L3+L3.3。
/// </summary>
internal sealed class DnsSecurityGuard : IDnsAnalysisService
{
    const string TAG = "DnsSecGuard";

    readonly IDnsAnalysisService _inner;      // 官方 SwitchImpl（策略: UseDoh? DoH : UDP）
    readonly DnsParallelResolver _parallel;   // L2: 5 通道并行
    readonly DnsResultVerifier _verifier;     // L3: 3 层过滤 + L3.3 锚点
    readonly DnsSecurityMonitor? _monitor;    // Phase 5/5: UI 告警层事件上报
    readonly ILogger? _logger;

    public DnsSecurityGuard(
        IDnsAnalysisService inner,
        DnsParallelResolver parallel,
        DnsResultVerifier verifier,
        DnsSecurityMonitor? monitor = null,
        ILoggerFactory? loggerFactory = null)
    {
        _inner = inner;
        _parallel = parallel;
        _verifier = verifier;
        _monitor = monitor;
        _logger = loggerFactory?.CreateLogger(TAG);
    }

    // —— 核心路径：L2 → L3 → yield ——
    public async IAsyncEnumerable<IPAddress> AnalysisDomainIpAsync(
        string hostNameOrAddress,
        IPAddress[]? dnsServers,
        bool isIPv6,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // 短路：如果用户传入了自定义 dnsServers 或明显是纯 IP 字符串 → 直接走 inner 不做 L2/L3
        if (dnsServers is { Length: > 0 } || IPAddress.TryParse(hostNameOrAddress, out _))
        {
            await foreach (var ip in _inner.AnalysisDomainIpAsync(hostNameOrAddress, dnsServers, isIPv6, cancellationToken)
                               .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                yield return ip;
            }
            yield break;
        }

        DnsSecurityVerdict verdict;
        try
        {
            var channels = await _parallel.QueryAllAsync(hostNameOrAddress, isIPv6, cancellationToken)
                .ConfigureAwait(false);
            // Phase 3/5: 改用 VerifyAsync 以支持 ASN TeamCymru/BGPView 查询 + DNSSEC 权重查询
            // (保留 Verify 同步兼容调用, 这里用 await 版是为了传 ct + 更好的线程切换)
            verdict = await _verifier.VerifyAsync(hostNameOrAddress, channels, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // 用户/系统取消 → 不返回（避免半截数据）
            yield break;
        }
        catch (Exception ex)
        {
            // 任何 L2/L3 异常：回退走 inner 的单通道（黄级），保证基本功能不崩
            _logger?.LogWarning(ex, "L2/L3 failed, fallback to inner for {host}", hostNameOrAddress);
            await foreach (var ip in _inner.AnalysisDomainIpAsync(hostNameOrAddress, null, isIPv6, cancellationToken)
                               .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                yield return ip;
            }
            yield break;
        }

        // 红黑级：直接阻断
        if (verdict.Overall == DnsVerdict.MaliciousBlock)
        {
            _logger?.LogWarning("DNS MALICIOUS BLOCK host={host} diag={diag}",
                hostNameOrAddress, verdict.Diagnostic);
            _monitor?.Record(new DnsSecurityEvent
            {
                Timestamp = DateTimeOffset.UtcNow,
                Host = hostNameOrAddress,
                Verdict = verdict.Overall,
                Diagnostic = verdict.Diagnostic,
                BlockedIps = string.Join(",", verdict.BlocklistedIps.Select(x => x.ToString())),
                VotingQuorum = verdict.VotingQuorum,
                ChannelSnapshots = BuildChannelSnapshots(verdict),
            });
            yield break;
        }

        // 黄色告警记录，但仍放行（非致命：首次锚点 / 票数不够等）
        if (verdict.Overall == DnsVerdict.SuspiciousRed)
        {
            _logger?.LogWarning("DNS SUSPICIOUS host={host} diag={diag} blockedIps={blocked}",
                hostNameOrAddress, verdict.Diagnostic,
                string.Join(",", verdict.BlocklistedIps.Select(x => x.ToString())));
        }
        else
        {
            _logger?.LogDebug("DNS {level} host={host} diag={diag}",
                verdict.Overall, hostNameOrAddress, verdict.Diagnostic);
        }

        // Phase 5/5: 上报到 UI 监控层 (绿/黄也记录, 便于统计)
        _monitor?.Record(new DnsSecurityEvent
        {
            Timestamp = DateTimeOffset.UtcNow,
            Host = hostNameOrAddress,
            Verdict = verdict.Overall,
            Diagnostic = verdict.Diagnostic,
            BlockedIps = verdict.BlocklistedIps.Length > 0
                ? string.Join(",", verdict.BlocklistedIps.Select(x => x.ToString()))
                : null,
            VotingQuorum = verdict.VotingQuorum,
            ChannelSnapshots = BuildChannelSnapshots(verdict),
        });

        foreach (var ip in verdict.RecommendedIps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return ip;
        }

        // 兜底：L3 给了空数组但非阻断 → 再走一次 inner 保证兼容性（例如首次锚点学习空票场景）
        if (verdict.RecommendedIps.Length == 0 && verdict.Overall != DnsVerdict.MaliciousBlock)
        {
            await foreach (var ip in _inner.AnalysisDomainIpAsync(hostNameOrAddress, null, isIPv6, cancellationToken)
                               .WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                yield return ip;
            }
        }
    }

    // —— 非核心路径：直接转发到 inner，不做 L2/L3 ——

    public Task<int> AnalysisHostnameTimeAsync(string url, CancellationToken cancellationToken = default)
        => _inner.AnalysisHostnameTimeAsync(url, cancellationToken);

    public Task<string?> GetHostByIPAddressAsync(IPAddress ip)
        => _inner.GetHostByIPAddressAsync(ip);

    public Task<bool> GetIsIpv6SupportAsync()
        => _inner.GetIsIpv6SupportAsync();

    public Task<IPAddress?> GetHostIpv6AddresAsync()
        => _inner.GetHostIpv6AddresAsync();

    // Phase 7: 构建通道快照供 Monitor 统计
    static DnsChannelSnapshot[]? BuildChannelSnapshots(DnsSecurityVerdict verdict)
    {
        if (verdict.ChannelSnapshots == null || verdict.ChannelSnapshots.Length == 0)
            return null;
        return verdict.ChannelSnapshots.Select(ch => new DnsChannelSnapshot
        {
            ChannelId = ch.ChannelId,
            IsSocketLevel = ch.IsSocketLevel,
            IsSuccess = ch.IsSuccess,
            LatencyMs = ch.LatencyMs,
            IpSummary = ch.Addresses.Length > 0
                ? string.Join(", ", ch.Addresses.Select(a => a.ToString()))
                : null,
        }).ToArray();
    }
}
