// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 4/5 - L3.2 DNSSEC 真实密码学验签 (0 新依赖)
// Phase 3 占位(仅检查 RR 存在性) → Phase 4 升级为:
//   - DnsSecChainVerifier 完整信任链验签 (DNSKEY + DS SHA256 摘要 + RRSIG RSA/ECDsa.VerifyData)
//   - 权重值:
//       2 = DS 信任锚验证通过 + RRSIG 密码学验签通过 → 最高信任
//       1 = DS 通过 / RRSIG 自签名通过 / 时间有效但验签失败 → 轻度加权
//       0 = 无签名 / 查询失败 / 1.5s 超时 → 不增益也不惩罚
//   - 绝不因为 DNSSEC "无签名" 就拦截 (现实中 60% 的 DoH 缓存不返回 Authority/Additional)
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// DNSSEC 加权验证器.
/// Phase 4: 调用 DnsSecChainVerifier 做完整信任链验签, 产出 0/1/2 三档信任权重.
/// 失败一律 return 0, 永不抛出.
/// </summary>
internal sealed class DnsSecVerifier
{
    const string TAG = "DnsL3Sec";

    static readonly TimeSpan HardTimeout = TimeSpan.FromMilliseconds(1500);

    // Phase 4/5: 完整信任链验证器 (DNSKEY + DS + RRSIG 密码学验签)
    readonly DnsSecChainVerifier? _chainVerifier;

    // Phase 3 兼容: 保留原构造参数 (DnsDohAnalysisService / DnsAnalysisServiceImpl) 不删除
    // 避免破坏 DI 已有注册; DnsSecChainVerifier 通过新增可选参数注入
    readonly DnsDohAnalysisService _doh;
    readonly DnsAnalysisServiceImpl _sys;

    public DnsSecVerifier(
        DnsDohAnalysisService doh,
        DnsAnalysisServiceImpl sys,
        DnsSecChainVerifier? chainVerifier = null)
    {
        _doh = doh;
        _sys = sys;
        _chainVerifier = chainVerifier;
    }

    /// <summary>
    /// 对一个域名获取 DNSSEC 信任权重.
    /// Phase 4: 调用 DnsSecChainVerifier 做完整验签; 失败/超时回退到 Phase 3 占位逻辑.
    /// 参数 ips 仅用于关联日志, 不参与计算 (因为 DNSSEC 是域级不是 IP 级)
    /// </summary>
    public async ValueTask<int> GetTrustWeightAsync(
        string domain,
        IPAddress[]? ips = null,
        CancellationToken outerCt = default)
    {
        if (string.IsNullOrWhiteSpace(domain)) return 0;
        if (IPAddress.TryParse(domain, out _)) return 0;
        if (domain.IndexOf('.') < 0) return 0;

        // Phase 4: 优先走完整信任链验签
        if (_chainVerifier != null)
        {
            try
            {
                var result = await _chainVerifier.VerifyAsync(domain, outerCt).ConfigureAwait(false);
                if (result.TrustWeight > 0)
                    return result.TrustWeight;
                // 完整验签返回 0 时, 降级到 Phase 3 占位 (可能只是 DoH 缓存缺 Authority)
            }
            catch
            {
                // DnsSecChainVerifier 内部已吞异常, 这里再兜一层
            }
        }

        // Phase 3 fallback: 占位检查 (RR 存在性)
        return await Phase3FallbackAsync(domain, outerCt).ConfigureAwait(false);
    }

    // —— Phase 3 占位逻辑 (降级用) ——
    // 当 DnsSecChainVerifier 返回 0 (查询失败/超时) 时, 用 Phase 3 的 RR 存在性检查兜底
    async ValueTask<int> Phase3FallbackAsync(string domain, CancellationToken outerCt)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outerCt);
        cts.CancelAfter(HardTimeout);
        var ct = cts.Token;

        bool hasDnsKey = false;
        bool hasRrSig = false;
        bool hasDs = false;

        try
        {
            var tDnsKey = FallbackQueryAsync(domain, 48, ct);  // DNSKEY
            var tDs = FallbackQueryAsync(domain, 43, ct);      // DS
            var tRrSig = FallbackQueryAsync(domain, 46, ct);   // RRSIG

            await Task.WhenAll(tDnsKey, tDs, tRrSig).WaitAsync(ct).ConfigureAwait(false);

            hasDnsKey = tDnsKey.Result;
            hasDs = tDs.Result;
            hasRrSig = tRrSig.Result;
        }
        catch
        {
            return 0;
        }

        if (hasDnsKey && hasRrSig && hasDs) return 1;
        if (hasDnsKey && hasRrSig) return 1;
        if (hasRrSig || hasDnsKey) return 1;
        return 0;
    }

    /// <summary>Phase 3 降级查询: 用 LookupClient 检查 RR 是否存在</summary>
    async Task<bool> FallbackQueryAsync(string domain, int qtypeInt, CancellationToken ct)
    {
        try
        {
            using var lookup = new DnsClient.LookupClient(new DnsClient.LookupClientOptions
            {
                UseCache = true,
                ExtendedDnsBufferSize = 4096,
                Timeout = TimeSpan.FromSeconds(2),
                Retries = 1,
                Recursion = true,
                UseRandomNameServer = true,
            });
            var qtype = (DnsClient.QueryType)qtypeInt;
            var resp = await lookup.QueryAsync(domain, qtype, DnsClient.QueryClass.IN, ct)
                .ConfigureAwait(false);
            return resp.AllRecords.Any(r => (int)r.RecordType == qtypeInt);
        }
        catch
        {
            return false;
        }
    }
}
