// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 2/5 - L2: 5 通道并行解析器（方案 A，0 新 NuGet 依赖）
// 官方已提供 Ae.Dns.Client(DoH) + DnsAnalysisServiceImpl(System.Net.DNS)，此处为并行编排装饰器
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// 单通道解析结果
/// </summary>
internal sealed class DnsChannelResult
{
    /// <summary>通道标识，例如 doh-cloudflare / udp-system / doh-google / dns-114 / dns-ali</summary>
    public required string ChannelId { get; init; }

    /// <summary>解析耗时毫秒</summary>
    public long LatencyMs { get; init; }

    /// <summary>返回的 IP 集合（失败为空数组，绝不抛异常）</summary>
    public IPAddress[] Addresses { get; init; } = Array.Empty<IPAddress>();

    /// <summary>本通道是否成功（有 IP 且无异常）</summary>
    public bool IsSuccess => Addresses.Length > 0;
}

/// <summary>
/// L2：并行解析器编排器。
/// 5 通道 = 官方 UDP(SystemDns) + 官方 DoH(用户配置 DOH) + 阿里 DoH + 114 DoH + Cloudflare DoH
/// 设计目标：
///   (1) 任何通道抛异常吞到 Addresses=空数组（绝不冒泡到 UI）
///   (2) 2.2s 硬性超时（CancellationToken）保证不阻塞
///   (3) 返回每个通道的独立结果给 L3 验证器（不在这里做投票）
///   (4) 全部走官方已有单例的 DnsAnalysisServiceImpl / DnsDohAnalysisService，不重复 new Socket/HttpClient
/// </summary>
internal sealed class DnsParallelResolver
{
    const string TAG = "DnsL2Parallel";
    static readonly TimeSpan HardTimeout = TimeSpan.FromMilliseconds(2200);

    /// <summary>官方已注册的 UDP DNS 服务（System.Net.DNS / LookupClient）</summary>
    readonly DnsAnalysisServiceImpl _system;

    /// <summary>官方已注册的 DoH 服务（Ae.Dns.Client + 用户配置 DoH 地址）</summary>
    readonly DnsDohAnalysisService _dohUser;

    static readonly (string Id, string DohUrl)[] FixedDohBackends = new[]
    {
        ("doh-ali",        "https://dns.alidns.com/dns-query"),
        ("doh-114",        "https://doh.114dns.com/dns-query"),
        ("doh-cloudflare", "https://1.1.1.1/dns-query"),
    };

    public DnsParallelResolver(DnsAnalysisServiceImpl system, DnsDohAnalysisService dohUser)
    {
        _system = system;
        _dohUser = dohUser;
    }

    /// <summary>
    /// 5 通道并行查询（推荐调用入口）。
    /// - 通道数量动态决定（至少 2 个，最多 2 + FixedDohBackends.Length = 5）
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

        // 任务列表：通道 1 = System(UDP)；通道 2 = 用户自定义 DoH；通道 3..5 = 内置公共 DoH 后备
        var tasks = new List<Task<DnsChannelResult>>(capacity: 2 + FixedDohBackends.Length)
        {
            RunSafe("udp-system", static (self, host, v6, t) =>
                self.RunSystemChannel(host, v6, t), this, hostNameOrAddress, isIPv6, ct),

            RunSafe("doh-user", static (self, host, v6, t) =>
                self.RunDohChannel(null /* use user's CustomDohAddres */, host, v6, t),
                this, hostNameOrAddress, isIPv6, ct),
        };

        foreach (var (id, url) in FixedDohBackends)
        {
            // 闭包捕获安全：拷贝局部变量
            var dohUrl = url;
            var chanId = id;
            tasks.Add(RunSafe(chanId, static (state, host, v6, t) =>
                    state.Self.RunDohChannel(state.Url, host, v6, t),
                (Self: this, Url: dohUrl), hostNameOrAddress, isIPv6, ct));
        }

        DnsChannelResult[] results;
        try
        {
            // WhenAll 永不抛异常（RunSafe 内部吞）
            results = await Task.WhenAll(tasks).WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // 2.2s 硬超时：只拿已跑完的结果
            results = tasks.Where(t => t.IsCompletedSuccessfully).Select(t => t.Result)
                .Concat(tasks.Where(t => !t.IsCompletedSuccessfully).Select(_ =>
                    new DnsChannelResult { ChannelId = "hard-timeout", Addresses = Array.Empty<IPAddress>() }))
                .ToArray();
        }

        return results;
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

    async Task<DnsChannelResult> RunDohChannel(string? dohOverrideUrl, string host, bool isIPv6, CancellationToken ct)
    {
        var sw = ValueStopwatch.StartNew();
        string chId = string.IsNullOrEmpty(dohOverrideUrl) ? "doh-user" :
            FixedDohBackends.FirstOrDefault(x => x.DohUrl == dohOverrideUrl).Id ?? "doh-override";
        try
        {
            var list = new List<IPAddress>(capacity: 4);
            await foreach (var ip in _dohUser.DohAnalysisDomainIpAsync(
                               dohOverrideUrl, host, isIPv6, true /* onlyAandAaaa */, ct)
                               .WithCancellation(ct).ConfigureAwait(false))
            {
                list.Add(ip);
            }
            return new DnsChannelResult
            {
                ChannelId = chId,
                Addresses = list.ToArray(),
                LatencyMs = sw.ElapsedMilliseconds,
            };
        }
        catch
        {
            return Fail(chId, sw);
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
