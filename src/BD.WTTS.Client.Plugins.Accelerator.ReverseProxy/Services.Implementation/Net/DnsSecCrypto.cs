// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 4/5 - DNSSEC 密码学工具 (0 新依赖, 纯 BCL)
// 提供: KeyTag 计算 / DS 摘要 / RSA+ECDsa 公钥构造 / wire format 编码 / RR set 验签数据构造
// 绝不抛异常; 全部 static 方法; 无状态; 线程安全
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// DNSSEC 密码学工具集 (RFC 4034 + RFC 3110 + RFC 6605)
/// 纯 BCL System.Security.Cryptography 实现, 0 新依赖
/// </summary>
file static class DnsSecCrypto
{
    // —— DNSSEC 算法常量 (RFC 4034 Section A.1) ——
    public const byte RSASHA1 = 5;
    public const byte RSASHA256 = 8;
    public const byte RSASHA512 = 10;
    public const byte ECDSAP256SHA256 = 13;
    public const byte ECDSAP384SHA384 = 14;

    // —— DS 摘要类型 (RFC 4034 Section 5.1.2) ——
    public const byte DS_DIGEST_SHA1 = 1;
    public const byte DS_DIGEST_SHA256 = 2;
    public const byte DS_DIGEST_SHA384 = 4;

    // ========================================================================
    #region Wire Format 编码

    /// <summary>域名编码为 DNS wire format (canonical = 小写, RFC 4034 Section 6.2)</summary>
    public static byte[] EncodeDomainName(string name)
    {
        name = (name ?? "").TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(name)) return new byte[] { 0 };
        var labels = name.Split('.');
        using var ms = new MemoryStream(name.Length + 2);
        foreach (var label in labels)
        {
            if (label.Length == 0) continue;
            var bytes = System.Text.Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0); // 终止符
        return ms.ToArray();
    }

    /// <summary>big-endian uint16</summary>
    public static byte[] U16(ushort v) => new byte[] { (byte)(v >> 8), (byte)v };

    /// <summary>big-endian uint32</summary>
    public static byte[] U32(uint v) => new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };

    /// <summary>构造单个 RR 的 wire format (owner + type + class + ttl + rdatalen + rdata)</summary>
    public static byte[] EncodeRR(string ownerWireName, ushort type, uint ttl, byte[] rdata)
    {
        var name = EncodeDomainName(ownerWireName);
        var result = new byte[name.Length + 2 + 2 + 4 + 2 + rdata.Length];
        int off = 0;
        name.CopyTo(result, off); off += name.Length;
        U16(type).CopyTo(result, off); off += 2;
        U16(1).CopyTo(result, off); off += 2;  // class = IN
        U32(ttl).CopyTo(result, off); off += 4;
        U16((ushort)rdata.Length).CopyTo(result, off); off += 2;
        rdata.CopyTo(result, off);
        return result;
    }

    #endregion

    // ========================================================================
    #region KeyTag 计算 (RFC 4034 Appendix B)

    /// <summary>
    /// 计算 DNSKEY 的 KeyTag (RFC 4034 Appendix B)
    /// 输入: DNSKEY RDATA = Flags(2) + Protocol(1) + Algorithm(1) + PublicKey
    /// </summary>
    public static int ComputeKeyTag(byte[] dnskeyRdata)
    {
        int ac = 0;
        for (int i = 0; i < dnskeyRdata.Length; i++)
        {
            ac += (i & 1) == 0 ? dnskeyRdata[i] << 8 : dnskeyRdata[i];
        }
        ac += (ac >> 16) & 0xFFFF;
        return ac & 0xFFFF;
    }

    /// <summary>从 DNSKEY 字段重建 RDATA bytes</summary>
    public static byte[] BuildDnsKeyRdata(ushort flags, byte protocol, byte algorithm, byte[] publicKey)
    {
        var rdata = new byte[4 + publicKey.Length];
        rdata[0] = (byte)(flags >> 8);
        rdata[1] = (byte)(flags & 0xFF);
        rdata[2] = protocol;
        rdata[3] = algorithm;
        Buffer.BlockCopy(publicKey, 0, rdata, 4, publicKey.Length);
        return rdata;
    }

    #endregion

    // ========================================================================
    #region DS 信任锚摘要 (RFC 4034 Section 5.1.4)

    /// <summary>
    /// 计算 DS 摘要 = hash(owner_name_wire + dnskey_rdata)
    /// 用于验证 DNSKEY 的信任链 (DS record 由父域签发)
    /// </summary>
    public static byte[]? ComputeDsDigest(string ownerName, byte[] dnskeyRdata, byte digestType)
    {
        var nameBytes = EncodeDomainName(ownerName);
        var data = new byte[nameBytes.Length + dnskeyRdata.Length];
        nameBytes.CopyTo(data, 0);
        dnskeyRdata.CopyTo(data, nameBytes.Length);

        return digestType switch
        {
            DS_DIGEST_SHA1 => SHA1.HashData(data),
            DS_DIGEST_SHA256 => SHA256.HashData(data),
            DS_DIGEST_SHA384 => SHA384.HashData(data),
            _ => null, // 不支持的摘要类型
        };
    }

    /// <summary>比较两个 byte[] 是否相等 (常数时间)</summary>
    public static bool ConstantTimeEquals(byte[]? a, byte[]? b)
    {
        if (a == null || b == null) return false;
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    #endregion

    // ========================================================================
    #region RSA / ECDsa 公钥构造 + 验签

    /// <summary>
    /// 解析 RSA 公钥 (RFC 3110)
    /// 格式: exponent_length(1或3字节) + exponent + modulus
    /// </summary>
    public static RSA? CreateRsa(byte[] publicKey)
    {
        try
        {
            if (publicKey.Length < 3) return null;
            int expLen;
            int offset;
            if (publicKey[0] == 0)
            {
                expLen = (publicKey[1] << 8) | publicKey[2];
                offset = 3;
            }
            else
            {
                expLen = publicKey[0];
                offset = 1;
            }
            if (offset + expLen > publicKey.Length) return null;
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Exponent = publicKey.Skip(offset).Take(expLen).ToArray(),
                Modulus = publicKey.Skip(offset + expLen).ToArray(),
            });
            return rsa;
        }
        catch { return null; }
    }

    /// <summary>
    /// 解析 ECDsa 公钥 (RFC 6605)
    /// P-256: 64 bytes (X[32] + Y[32]); P-384: 96 bytes (X[48] + Y[48])
    /// </summary>
    public static ECDsa? CreateECDsa(byte[] publicKey, byte algorithm)
    {
        try
        {
            int halfLen = algorithm == ECDSAP256SHA256 ? 32 : 48;
            if (publicKey.Length < halfLen * 2) return null;
            var curve = algorithm == ECDSAP256SHA256
                ? ECCurve.CreateFromValue("1.2.840.10045.3.1.7")   // P-256
                : ECCurve.CreateFromValue("1.3.132.0.34");          // P-384
            var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = publicKey.Take(halfLen).ToArray(),
                    Y = publicKey.Skip(halfLen).Take(halfLen).ToArray(),
                },
            });
            return ecdsa;
        }
        catch { return null; }
    }

    /// <summary>
    /// DNSSEC 签名验证 (5 种算法)
    /// RSASHA1(5)/RSASHA256(8)/RSASHA512(10) → RSA.VerifyData + Pkcs1
    /// ECDSAP256SHA256(13)/ECDSAP384SHA384(14) → ECDsa.VerifyData + IeeeP1363
    /// </summary>
    public static bool VerifySignature(byte algorithm, byte[] data, byte[] signature, byte[] publicKey)
    {
        try
        {
            // RSA 系列
            if (algorithm == RSASHA1 || algorithm == RSASHA256 || algorithm == RSASHA512)
            {
                using var rsa = CreateRsa(publicKey);
                if (rsa == null) return false;
                var hash = algorithm switch
                {
                    RSASHA1 => HashAlgorithmName.SHA1,
                    RSASHA256 => HashAlgorithmName.SHA256,
                    RSASHA512 => HashAlgorithmName.SHA512,
                    _ => default,
                };
                return rsa.VerifyData(data, signature, hash, RSASignaturePadding.Pkcs1);
            }

            // ECDsa 系列
            if (algorithm == ECDSAP256SHA256 || algorithm == ECDSAP384SHA384)
            {
                using var ecdsa = CreateECDsa(publicKey, algorithm);
                if (ecdsa == null) return false;
                var hash = algorithm == ECDSAP256SHA256
                    ? HashAlgorithmName.SHA256
                    : HashAlgorithmName.SHA384;
                // DNSSEC ECDSA 签名格式 = raw r||s (IEEE P1363)
                return ecdsa.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }

            return false; // 不支持的算法
        }
        catch { return false; }
    }

    #endregion

    // ========================================================================
    #region RRSIG 验签数据构造 (RFC 4034 Section 3.1.8.1)

    /// <summary>
    /// 构造 RRSIG 验签数据 = RRSIG_RDATA(without signature) + RR_set_wire_format
    /// </summary>
    /// <param name="rrsigTypeCovered">RRSIG 覆盖的 RR 类型 (A=1, AAAA=28, DNSKEY=48)</param>
    /// <param name="rrsigAlgorithm">算法</param>
    /// <param name="rrsigLabels">RRSIG Labels 字段 (通配符处理)</param>
    /// <param name="rrsigOriginalTtl">RRSIG Original TTL</param>
    /// <param name="rrsigExpiration">签名过期时间 (Unix 秒)</param>
    /// <param name="rrsigInception">签名起始时间 (Unix 秒)</param>
    /// <param name="rrsigKeyTag">签名者的 KeyTag</param>
    /// <param name="rrsigSignersName">签名者域名</param>
    /// <param name="rrOwnerName">被签名 RR set 的 owner name</param>
    /// <param name="rrRdataList">被签名 RR set 的 RDATA 列表 (已按 canonical order 排序)</param>
    public static byte[] BuildVerificationData(
        ushort rrsigTypeCovered, byte rrsigAlgorithm, byte rrsigLabels,
        uint rrsigOriginalTtl, long rrsigExpiration, long rrsigInception,
        ushort rrsigKeyTag, string rrsigSignersName,
        string rrOwnerName, List<byte[]> rrRdataList)
    {
        using var ms = new MemoryStream(512);

        // 1. RRSIG RDATA (without signature) = 18 bytes + signer name
        ms.Write(U16(rrsigTypeCovered), 0, 2);
        ms.WriteByte(rrsigAlgorithm);
        ms.WriteByte(rrsigLabels);
        ms.Write(U32(rrsigOriginalTtl), 0, 4);
        ms.Write(U32((uint)rrsigExpiration), 0, 4);
        ms.Write(U32((uint)rrsigInception), 0, 4);
        ms.Write(U16(rrsigKeyTag), 0, 2);
        var signerBytes = EncodeDomainName(rrsigSignersName);
        ms.Write(signerBytes, 0, signerBytes.Length);

        // 2. RR set wire format (canonical order)
        // 处理通配符 owner name
        string canonicalOwner = GetCanonicalOwnerName(rrOwnerName, rrsigLabels);

        // 按 RDATA 字节序排序 (canonical ordering for same owner + same type)
        var sorted = rrRdataList.OrderBy(r => r, ByteArrayComparer.Instance).ToList();

        foreach (var rdata in sorted)
        {
            var rr = EncodeRR(canonicalOwner, rrsigTypeCovered, rrsigOriginalTtl, rdata);
            ms.Write(rr, 0, rr.Length);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// 通配符 owner name 处理 (RFC 4034 Section 3.1.3)
    /// 如果 RRSIG Labels < 实际标签数, 用 "*." 替换前面多余标签
    /// </summary>
    static string GetCanonicalOwnerName(string ownerName, byte rrsigLabels)
    {
        ownerName = (ownerName ?? "").TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrEmpty(ownerName)) return ".";
        var labels = ownerName.Split('.');
        if (rrsigLabels >= labels.Length) return ownerName;
        // 通配符: 保留最后 rrsigLabels 个标签, 前面用 "*" 替换
        return "*." + string.Join(".", labels.Skip(labels.Length - rrsigLabels));
    }

    #endregion
}

/// <summary>byte[] 字节序比较器 (canonical ordering)</summary>
file sealed class ByteArrayComparer : IComparer<byte[]>
{
    public static readonly ByteArrayComparer Instance = new();

    public int Compare(byte[]? x, byte[]? y)
    {
        if (x == null && y == null) return 0;
        if (x == null) return -1;
        if (y == null) return 1;
        int len = Math.Min(x.Length, y.Length);
        for (int i = 0; i < len; i++)
        {
            int cmp = x[i].CompareTo(y[i]);
            if (cmp != 0) return cmp;
        }
        return x.Length.CompareTo(y.Length);
    }
}
