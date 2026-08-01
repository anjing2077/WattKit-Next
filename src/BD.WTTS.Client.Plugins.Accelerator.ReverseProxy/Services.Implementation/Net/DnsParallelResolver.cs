// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 2/5 + Phase 6 升级 — L2: 7 通道并行解析器
// 通道 = udp-system(系统DNS基线) + doh-user(用户配置DoH) + 5×Socket级DoH/DoT(硬编码IP,免疫DNS污染)
// Phase 6 核心升级：用 DnsSocketResolver 替换原 HttpClient DoH 通道，解决"鸡生蛋"问题
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// 单通道解析结果
/// </summary>
internal sealed class DnsChannelResult
{
    /// <summary>通道标识，例如 doh-1.1.1.1 / udp-system / doh-user / dot-9.9.9.9</summary>
    public required string ChannelId { get; init; }

    /// <summary>解析耗时毫秒</summary>
    public long LatencyMs { get; init; }

    /// <summary>返回的 IP 集合（失败为空数组，绝不抛异常）</summary>
    public IPAddress[] Addresses { get; init; } = Array.Empty<IPAddress>();

    /// <summary>本通道是否成功（有 IP 且无异常）</summary>
    public bool IsSuccess => Addresses.Length > 0;

    /// <summary>是否为 Socket 级通道（硬编码 IP，免疫系统 DNS 污染）</summary>
    public bool IsSocketLevel => ChannelId.StartsWith("doh-", StringComparison.Ordinal)
                              || ChannelId.StartsWith("dot-", StringComparison.Ordinal);
}

/// <summary>
/// L2：并行解析器编排器。
/// Phase 6 升级后 7 通道：
///   1. udp-system   → 系统 UDP DNS（基线对比，可被 L3 投票否决）
///   2. doh-user     → 用户自定义 DoH（HttpClient，兼容旧配置）
///   3. doh-1.1.1.1  → Cloudflare DoH via Socket（硬编码 IP + TLS SNI）
///   4. doh-8.8.8.8  → Google DoH via Socket
///   5. doh-223.5.5.5→ 阿里 DoH via Socket
///   6. dot-1.1.1.1  → Cloudflare DoT via Socket（TCP 853 + TLS）
///   7. dot-9.9.9.9  → Quad9 DoT via Socket（威胁情报）
/// 设计目标：
///   (1) 任何通道抛异常吞到 Addresses=空数组（绝不冒泡到 UI）
///   (2) 2.2s 硬性超时（CancellationToken）保证不阻塞
///   (3) 返回每个通道的独立结果给 L3 验证器（不在这里做投票）
///   (4) Socket 级通道不依赖系统 DNS，彻底解决"鸡生蛋"问题
/// </summary>
internal sealed class DnsParallelResolver
{
    const string TAG = "DnsL2Parallel";
    static readonly TimeSpan HardTimeout = TimeSpan.FromMilliseconds(2200);

    /// <summary>官方已注册的 UDP DNS 服务（System.Net.DNS / LookupClient）</summary>
    readonly DnsAnalysisServiceImpl _system;

    /// <summary>官方已注册的 DoH 服务（Ae.Dns.Client + 用户配置 DoH 地址）</summary>
    readonly DnsDohAnalysisService _dohUser;

    /// <summary>Phase 6: Socket 级 DoH/DoT 解析器（硬编码 IP, 0 新依赖）</summary>
    readonly DnsSocketResolver _socketResolver = new();

    public DnsParallelResolver(DnsAnalysisServiceImpl system, DnsDohAnalysisService dohUser)
    {
        _system = system;
        _dohUser = dohUser;
    }

    /// <summary>
    /// 7 通道并行查询（推荐调用入口）。
    /// - 2 个传统通道（系统 UDP + 用户 DoH）+ 5 个 Socket 级通道
    /// - CancellationToken 超时统一 2.2s
    /// </summary>
    public async Task<DnsChannelResult[]> QueryAllAsync(
        string hostNameOrAddress,
        bool isIPv6,
        CancellationToken outerToken = default)
    {
        if (string.IsNullOrWhiteSpace(hostNameOrAddress))
            return Array.Empty<DnsChannelResult>();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
        cts.CancelAfter(HardTimeout);
        var ct = cts.Token;

        // —— 传统通道（2 个）——
        var traditionalTasks = new List<Task<DnsChannelResult>>(capacity: 2)
        {
            RunSafe("udp-system", static (self, host, v6, t) =>
                self.RunSystemChannel(host, v6, t), this, hostNameOrAddress, isIPv6, ct),

            RunSafe("doh-user", static (self, host, v6, t) =>
                self.RunDohUserChannel(host, v6, t),
                this, hostNameOrAddress, isIPv6, ct),
        };

        // —— Phase 6: Socket 级通道（5 个 DoH + DoT，硬编码 IP，免疫 DNS 污染）——
        var socketTask = _socketResolver.QueryAllSocketChannelsAsync(hostNameOrAddress, isIPv6, ct);

        // 并行等待所有通道（传统 + Socket）
        var allTasks = traditionalTasks.Cast<Task>().Append(socketTask).ToArray();
        try
        {
            await Task.WhenAll(allTasks).WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* 硬超时：下面收集已完成的结果 */ }

        // 收集结果
        var results = new List<DnsChannelResult>(capacity: 7);

        // 传统通道结果
        foreach (var t in traditionalTasks)
        {
            if (t.IsCompletedSuccessfully)
                results.Add(t.Result);
            else
                results.Add(new DnsChannelResult { ChannelId = "timeout", Addresses = Array.Empty<IPAddress>() });
        }

        // Socket 级通道结果（展开为多个 DnsChannelResult）
        if (socketTask.IsCompletedSuccessfully)
        {
            var sw = ValueStopwatch.StartNew();
            foreach (var (channelId, addresses) in socketTask.Result)
            {
                results.Add(new DnsChannelResult
                {
                    ChannelId = channelId,
                    Addresses = addresses,
                    LatencyMs = sw.ElapsedMilliseconds,
                });
            }
        }
        else
        {
            results.Add(new DnsChannelResult { ChannelId = "socket-all:timeout", Addresses = Array.Empty<IPAddress>() });
        }

        return results.ToArray();
    }

    // —— 私有通道实现：全部 try/catch + Stopwatch ——

    async Task<DnsChannelResult> RunSystemChannel(string host, bool isIPv6, CancellationToken ct)
    {
        var sw = ValueStopwatch.StartNew();
        try
        {
            var list = new List<IPAddress>(capacity: 4);
            await foreach (var ip in _system.AnalysisDomainIpAsync(host, default /* use default dnsServers */,
                               isIPv6, ct).WithCancellation(ct).ConfigureAwait(false))
            {
                list.Add(ip);
            }
            return new DnsChannelResult
            {
                ChannelId = "udp-system",
                Addresses = list.ToArray(),
                LatencyMs = sw.ElapsedMilliseconds,
            };
        }
        catch
        {
            return Fail("udp-system", sw);
        }
    }

    async Task<DnsChannelResult> RunDohUserChannel(string host, bool isIPv6, CancellationToken ct)
    {
        var sw = ValueStopwatch.StartNew();
        try
        {
            var list = new List<IPAddress>(capacity: 4);
            await foreach (var ip in _dohUser.DohAnalysisDomainIpAsync(
                               null /* use user's CustomDohAddres */, host, isIPv6, true, ct)
                               .WithCancellation(ct).ConfigureAwait(false))
            {
                list.Add(ip);
            }
            return new DnsChannelResult
            {
                ChannelId = "doh-user",
                Addresses = list.ToArray(),
                LatencyMs = sw.ElapsedMilliseconds,
            };
        }
        catch
        {
            return Fail("doh-user", sw);
        }
    }

    // —— 工具：安全执行包装 ——

    delegate Task<DnsChannelResult> SafeFunc<in TState>(
        TState state, string host, bool isIPv6, CancellationToken ct);

    static async Task<DnsChannelResult> RunSafe<TState>(
        string chId,
        SafeFunc<TState> func,
        TState state,
        string host,
        bool isIPv6,
        CancellationToken ct)
    {
        try
        {
            return await func(state, host, isIPv6, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return new DnsChannelResult { ChannelId = chId + ":cancel", Addresses = Array.Empty<IPAddress>() };
        }
        catch
        {
            return new DnsChannelResult { ChannelId = chId + ":err", Addresses = Array.Empty<IPAddress>() };
        }
    }

    static DnsChannelResult Fail(string chId, ValueStopwatch sw) => new()
    {
        ChannelId = chId,
        Addresses = Array.Empty<IPAddress>(),
        LatencyMs = sw.ElapsedMilliseconds,
    };
}
