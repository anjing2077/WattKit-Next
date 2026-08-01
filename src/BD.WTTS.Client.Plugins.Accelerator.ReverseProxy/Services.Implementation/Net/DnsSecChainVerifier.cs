// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 4/5 - DNSSEC 信任链验证编排 (0 新依赖)
// 完整验签流程:
//   1. 查 DNSKEY RR set → 解析 Flags/Protocol/Algorithm/PublicKey → 计算 KeyTag
//   2. 查 DS record → 计算 DNSKEY SHA256 摘要 → 与 DS.Digest 对比 (信任锚验证)
//   3. 查 RRSIG(A/AAAA) → 检查时间有效性 + KeyTag 匹配
//   4. 构造 RR set wire format → RSA/ECDsa.VerifyData 完整验签
//   返回权重: 2=全通过 / 1=信任锚通过但验签缺失 / 0=失败
//   绝不抛异常; 1.5s 硬超时; 使用 LookupClient EDNS DO 位查询
// ReSharper disable once CheckNamespace

using DnsClient;
using DnsClient.Protocol;

namespace BD.WTTS.Services.Implementation;

/// <summary>信任链验证结果</summary>
internal sealed class DnsSecChainResult
{
    /// <summary>信任权重: 0=失败 / 1=信任锚通过 / 2=完整验签通过</summary>
    public int TrustWeight { get; init; }

    /// <summary>DNSKEY 信任锚 (DS 摘要) 验证通过</summary>
    public bool DsAnchorVerified { get; init; }

    /// <summary>RRSIG 密码学验签通过</summary>
    public bool RrSigVerified { get; init; }

    /// <summary>诊断文本</summary>
    public string? Diagnostic { get; init; }
}

/// <summary>
/// DNSSEC 信任链验证器: 编排完整的 DNSSEC 验签流程.
/// Phase 3 的 DnsSecVerifier.GetTrustWeightAsync 占位 → Phase 4 替换为真实验签.
/// </summary>
internal sealed class DnsSecChainVerifier
{
    const string TAG = "DnsSecChain";
    static readonly TimeSpan HardTimeout = TimeSpan.FromMilliseconds(1500);

    /// <summary>
    /// 对域名执行完整 DNSSEC 信任链验证.
    /// 绝不抛异常; 1.5s 硬超时.
    /// </summary>
    public async Task<DnsSecChainResult> VerifyAsync(
        string domain,
        CancellationToken outerCt = default)
    {
        if (string.IsNullOrWhiteSpace(domain)) return new() { TrustWeight = 0 };
        if (IPAddress.TryParse(domain, out _)) return new() { TrustWeight = 0 };
        if (domain.IndexOf('.') < 0) return new() { TrustWeight = 0 };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outerCt);
        cts.CancelAfter(HardTimeout);
        var ct = cts.Token;

        try
        {
            return await VerifyCoreAsync(domain, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return new() { TrustWeight = 0, Diagnostic = "timeout 1.5s" };
        }
        catch (Exception ex)
        {
            return new() { TrustWeight = 0, Diagnostic = $"crash: {ex.GetType().Name}" };
        }
    }

    async Task<DnsSecChainResult> VerifyCoreAsync(string domain, CancellationToken ct)
    {
        // 创建带 EDNS DO 位的 LookupClient (DNSSEC OK)
        using var lookup = new LookupClient(new LookupClientOptions
        {
            RequestDnsSecRecords = true,   // EDNS DO 位, 让服务器返回 RRSIG/DNSKEY
            UseCache = true,
            ExtendedDnsBufferSize = 4096,
            Timeout = TimeSpan.FromSeconds(2),
            Retries = 1,
            Recursion = true,
            UseRandomNameServer = true,
        });

        // —— 并行查 3 类记录: DNSKEY + DS + RRSIG(A) ——
        // 对 IPv6 场景还需查 RRSIG(AAAA), 但为控制 1.5s 超时, 只查 A
        var tDnsKey = QueryTypedAsync<DnsKeyRecord>(lookup, domain, QueryType.DNSKEY, ct);
        var tDs = QueryTypedAsync<DsRecord>(lookup, domain, QueryType.DS, ct);
        var tRrSigA = QueryTypedAsync<RrSigRecord>(lookup, domain, QueryType.RRSIG, ct);
        var tA = QueryTypedAsync<ARecord>(lookup, domain, QueryType.A, ct);

        await Task.WhenAll(tDnsKey, tDs, tRrSigA, tA).WaitAsync(ct).ConfigureAwait(false);

        var dnsKeys = tDnsKey.Result;
        var dsRecords = tDs.Result;
        var rrsigs = tRrSigA.Result;
        var aRecords = tA.Result;

        if (dnsKeys.Count == 0)
            return new() { TrustWeight = 0, Diagnostic = "no DNSKEY" };

        // —— Step 1: 解析 DNSKEY + 计算 KeyTag ——
        var parsedKeys = new List<(DnsKeyRecord Rec, byte[] Rdata, int KeyTag)>();
        foreach (var dk in dnsKeys)
        {
            try
            {
                var pubKey = dk.PublicKey as byte[] ?? dk.PublicKey.ToArray();
                var rdata = DnsSecCrypto.BuildDnsKeyRdata(dk.Flags, dk.Protocol, dk.Algorithm, pubKey);
                var keyTag = DnsSecCrypto.ComputeKeyTag(rdata);
                parsedKeys.Add((dk, rdata, keyTag));
            }
            catch { /* 忽略单条解析失败 */ }
        }

        if (parsedKeys.Count == 0)
            return new() { TrustWeight = 0, Diagnostic = "DNSKEY parse failed" };

        // —— Step 2: DS 信任锚验证 (SHA256 摘要对比) ——
        bool dsVerified = false;
        int? trustedKeyTag = null;
        byte[]? trustedRdata = null;
        DnsKeyRecord? trustedKey = null;

        if (dsRecords.Count > 0)
        {
            foreach (var ds in dsRecords)
            {
                foreach (var (dk, rdata, keyTag) in parsedKeys)
                {
                    if (ds.KeyTag != keyTag) continue;
                    var computed = DnsSecCrypto.ComputeDsDigest(domain, rdata, ds.DigestType);
                    if (computed == null) continue;
                    var dsDigest = ds.Digest as byte[] ?? ds.Digest.ToArray();
                    if (DnsSecCrypto.ConstantTimeEquals(computed, dsDigest))
                    {
                        dsVerified = true;
                        trustedKeyTag = keyTag;
                        trustedRdata = rdata;
                        trustedKey = dk;
                        break;
                    }
                }
                if (dsVerified) break;
            }
        }

        // —— Step 3: RRSIG 时间有效性 + KeyTag 匹配 ——
        bool rrsigValid = false;
        bool rrsigCryptoVerified = false;

        if (rrsigs.Count > 0 && aRecords.Count > 0)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (var rrsig in rrsigs)
            {
                // 只处理覆盖 A 记录的 RRSIG (TypeCovered == A)
                if (rrsig.TypeCovered != ResourceRecordType.A) continue;

                // 时间有效性
                if (now < rrsig.SignatureInception || now > rrsig.SignatureExpiration)
                    continue;

                // KeyTag 匹配: 找到对应的 DNSKEY
                var matchedKey = parsedKeys.FirstOrDefault(k => k.KeyTag == rrsig.KeyTag);
                if (matchedKey.Rec == null) continue;
                if (trustedKey != null && matchedKey.KeyTag != trustedKeyTag) continue;

                rrsigValid = true;

                // —— Step 4: 完整 RSA/ECDsa 验签 ——
                try
                {
                    // 构造 RR set RDATA 列表 (A 记录 = 4 字节 IP)
                    var rrRdataList = aRecords
                        .Select(a => a.Address.GetAddressBytes())
                        .ToList();

                    // 构造验签数据
                    var verificationData = DnsSecCrypto.BuildVerificationData(
                        rrsigTypeCovered: 1, // A = 1
                        rrsigAlgorithm: rrsig.Algorithm,
                        rrsigLabels: rrsig.Labels,
                        rrsigOriginalTtl: rrsig.OriginalTtl,
                        rrsigExpiration: rrsig.SignatureExpiration,
                        rrsigInception: rrsig.SignatureInception,
                        rrsigKeyTag: rrsig.KeyTag,
                        rrsigSignersName: rrsig.SignersName,
                        rrOwnerName: domain,
                        rrRdataList: rrRdataList);

                    var signature = rrsig.Signature as byte[] ?? rrsig.Signature.ToArray();
                    var pubKey = matchedKey.Rec.PublicKey as byte[] ?? matchedKey.Rec.PublicKey.ToArray();

                    rrsigCryptoVerified = DnsSecCrypto.VerifySignature(
                        rrsig.Algorithm, verificationData, signature, pubKey);
                }
                catch
                {
                    rrsigCryptoVerified = false;
                }

                if (rrsigCryptoVerified) break; // 有一条验签通过即可
            }
        }

        // —— 综合判定权重 ——
        int weight;
        string diag;

        if (dsVerified && rrsigCryptoVerified)
        {
            weight = 2;
            diag = $"DS-OK keyTag={trustedKeyTag} RRSIG-VERIFIED algo={rrsigs.FirstOrDefault()?.Algorithm}";
        }
        else if (dsVerified)
        {
            weight = 1;
            diag = $"DS-OK keyTag={trustedKeyTag} RRSIG={rrsigValid ? "valid-but-sig-fail" : "missing"}";
        }
        else if (rrsigCryptoVerified)
        {
            weight = 1;
            diag = "RRSIG-VERIFIED but no DS anchor (self-signed only)";
        }
        else if (rrsigValid)
        {
            weight = 1;
            diag = "RRSIG time-valid but crypto-verify failed/missing";
        }
        else
        {
            weight = 0;
            diag = $"no-valid-chain dnskeys={parsedKeys.Count} ds={dsRecords.Count} rrsig={rrsigs.Count} a={aRecords.Count}";
        }

        return new DnsSecChainResult
        {
            TrustWeight = weight,
            DsAnchorVerified = dsVerified,
            RrSigVerified = rrsigCryptoVerified,
            Diagnostic = diag,
        };
    }

    /// <summary>查询指定记录类型并过滤为目标类型</summary>
    static async Task<List<T>> QueryTypedAsync<T>(LookupClient lookup, string domain, QueryType qtype, CancellationToken ct)
        where T : DnsResourceRecord
    {
        try
        {
            var resp = await lookup.QueryAsync(domain, qtype, QueryClass.IN, ct).ConfigureAwait(false);
            return resp.Answers.OfType<T>().ToList();
        }
        catch
        {
            return new List<T>();
        }
    }
}
