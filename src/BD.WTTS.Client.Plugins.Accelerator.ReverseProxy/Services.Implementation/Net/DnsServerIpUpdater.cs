// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 8 — DoH/DoT 服务器 IP 动态更新器
// 目的：种子 IP 可能过期（服务器迁移/Anycast 调整），后台定期用已建立信任的
//   Socket 级 DoH 通道反过来查 DoH 服务器域名的新 IP，更新到 DnsSocketResolver。
// 鸡生蛋保护：第一次查询用种子 IP（硬编码），查到新 IP 后存入 runtime 字典；
//   后续查询优先用 runtime IP，种子 IP 做 fallback。
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// DoH/DoT 服务器 IP 动态更新器。
/// 后台周期性通过已建立信任的 Socket 级 DoH 通道查询其他 DoH 服务器的域名 IP，
/// 刷新 DnsSocketResolver 的 runtime IP 字典。
/// 线程安全，绝不抛异常。
/// </summary>
internal sealed class DnsServerIpUpdater : IDisposable
{
    const string TAG = "DnsIpUpdater";
    readonly DnsSocketResolver _resolver;
    readonly TimeSpan _refreshInterval;
    CancellationTokenSource? _cts;
    Task? _loopTask;

    // 已知 DoH 服务器域名列表（用于交叉查询）
    static readonly string[] KnownDohDomains =
    {
        "cloudflare-dns.com", "dns.google", "dns.alidns.com", "dns.quad9.net",
    };

    /// <param name="refreshInterval">刷新周期，默认 6 小时</param>
    public DnsServerIpUpdater(DnsSocketResolver resolver, TimeSpan? refreshInterval = null)
    {
        _resolver = resolver;
        _refreshInterval = refreshInterval ?? TimeSpan.FromHours(6);
    }

    /// <summary>启动后台刷新循环</summary>
    public void Start()
    {
        if (_loopTask != null) return;
        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => RefreshLoopAsync(_cts.Token));
    }

    /// <summary>停止并释放</summary>
    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }

    async Task RefreshLoopAsync(CancellationToken ct)
    {
        // 启动后延迟 30s 开始第一次刷新（避免和启动竞争资源）
        await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        while (!ct.IsCancellationRequested)
        {
            try { await RefreshAllAsync(ct).ConfigureAwait(false); }
            catch { /* 绝不让后台循环挂掉 */ }
            try { await Task.Delay(_refreshInterval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// 用已有的 Socket 级 DoH 通道查询每个已知 DoH 服务器域名的最新 IP，
    /// 然后调用 DnsSocketResolver.UpdateServerIps() 更新 runtime 字典。
    /// </summary>
    async Task RefreshAllAsync(CancellationToken ct)
    {
        foreach (var domain in KnownDohDomains)
        {
            try
            {
                // 用 Socket 级通道查 A 记录（用种子 IP 连接其他 DoH 服务器来查这个域名）
                var results = await _resolver.QueryAllSocketChannelsAsync(domain, isIPv6: false, ct)
                    .ConfigureAwait(false);
                var ips = results.SelectMany(r => r.Addresses)
                    .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Distinct()
                    .Select(ip => ip.ToString())
                    .ToArray();
                if (ips.Length > 0)
                {
                    DnsSocketResolver.UpdateServerIps(domain, ips);
                }

                // 也查 AAAA 记录
                var v6Results = await _resolver.QueryAllSocketChannelsAsync(domain, isIPv6: true, ct)
                    .ConfigureAwait(false);
                var ipsV6 = v6Results.SelectMany(r => r.Addresses)
                    .Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    .Distinct()
                    .Select(ip => ip.ToString())
                    .ToArray();
                if (ipsV6.Length > 0)
                {
                    DnsSocketResolver.UpdateServerIps(domain, Array.Empty<string>(), ipsV6);
                }
            }
            catch
            {
                // 单个域名刷新失败不影响其他
            }
        }
    }
}
