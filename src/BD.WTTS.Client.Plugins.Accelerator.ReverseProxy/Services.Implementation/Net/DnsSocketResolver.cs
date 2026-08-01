// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 6 — Socket 级 DoH/DoT 解析器（0 新 NuGet 依赖）
// 核心解决"鸡生蛋"问题：硬编码 DoH/DoT 服务器 IP，不依赖系统 DNS 解析服务器域名
// 协议：DoH=RFC 8484(TCP 443+TLS+HTTP/1.1 POST wireformat) / DoT=RFC 7858(TCP 853+TLS+2字节长度前缀)
// ReSharper disable once CheckNamespace

using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// Socket 级 DNS over HTTPS / DNS over TLS 解析器。
/// 纯 BCL System.Net.Sockets + System.Net.Security 实现，0 新 NuGet 依赖。
/// 线程安全：每个查询独立 TcpClient，无共享可变状态。
/// 绝不抛异常：任何网络/协议错误返回空数组。
/// </summary>
internal sealed class DnsSocketResolver
{
    const string TAG = "DnsSocket";

    // —— DoH 服务器矩阵（硬编码 IP，绕过系统 DNS 鸡生蛋问题）——
    // (IP, SNI 域名, HTTP path)
    static readonly (string Ip, string Sni, string Path)[] DohServers =
    {
        ("1.1.1.1",     "cloudflare-dns.com", "/dns-query"), // Cloudflare
        ("8.8.8.8",     "dns.google",         "/dns-query"), // Google
        ("223.5.5.5",   "dns.alidns.com",     "/dns-query"), // Alibaba
    };

    // —— DoT 服务器矩阵（硬编码 IP）——
    // (IP, SNI 域名)
    static readonly (string Ip, string Sni)[] DotServers =
    {
        ("1.1.1.1", "cloudflare-dns.com"), // Cloudflare DoT
        ("9.9.9.9", "dns.quad9.net"),      // Quad9 DoT (threat intel)
    };

    /// <summary>
    /// 并行查询所有 DoH + DoT 通道，返回每个通道的 IP 结果。
    /// 调用方（DnsParallelResolver）负责超时控制。
    /// </summary>
    public async Task<(string ChannelId, IPAddress[] Addresses)[]> QueryAllSocketChannelsAsync(
        string domain, bool isIPv6, CancellationToken ct)
    {
        var qtype = isIPv6 ? DnsWireCodec.QTYPE_AAAA : DnsWireCodec.QTYPE_A;
        var query = DnsWireCodec.BuildQuery(domain, qtype);

        var tasks = new List<Task<(string, IPAddress[])>>(DohServers.Length + DotServers.Length);

        // DoH 通道
        foreach (var (ip, sni, path) in DohServers)
        {
            var capturedIp = ip; var capturedSni = sni; var capturedPath = path;
            tasks.Add(QueryDohAsync(capturedIp, capturedSni, capturedPath, query, capturedIp, ct));
        }

        // DoT 通道
        foreach (var (ip, sni) in DotServers)
        {
            var capturedIp = ip; var capturedSni = sni;
            tasks.Add(QueryDotAsync(capturedIp, capturedSni, query, $"dot-{capturedIp}", ct));
        }

        // WhenAll 永不抛异常（每个通道内部吞异常）
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        // 如果 IPv6 查询全部为空，自动回退查 A 记录
        if (isIPv6 && results.All(r => r.Addresses.Length == 0))
        {
            var fallbackQuery = DnsWireCodec.BuildQuery(domain, DnsWireCodec.QTYPE_A);
            var fallbackTasks = new List<Task<(string, IPAddress[])>>(DohServers.Length);
            foreach (var (ip, sni, path) in DohServers)
            {
                var cIp = ip; var cSni = sni; var cPath = path;
                fallbackTasks.Add(QueryDohAsync(cIp, cSni, cPath, fallbackQuery, $"{cIp}-fb", ct));
            }
            var fbResults = await Task.WhenAll(fallbackTasks).ConfigureAwait(false);
            return results.Concat(fbResults).ToArray();
        }

        return results;
    }

    // ===== DoH (RFC 8484) =====

    async Task<(string, IPAddress[])> QueryDohAsync(
        string serverIp, string sni, string path, byte[] query, string channelId, CancellationToken ct)
    {
        TcpClient? tcp = null;
        SslStream? ssl = null;
        try
        {
            tcp = new TcpClient();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(3));
            await tcp.ConnectAsync(IPAddress.Parse(serverIp), 443, connectCts.Token).ConfigureAwait(false);

            ssl = new SslStream(tcp.GetStream(), false, ValidateServerCert, null);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni,           // SNI 设为域名，但 TCP 连的是硬编码 IP
                AllowRenegotiation = false,
            }, ct).ConfigureAwait(false);

            // 构造 HTTP/1.1 POST 请求
            var header = $"POST {path} HTTP/1.1\r\n" +
                         $"Host: {sni}\r\n" +
                         "Content-Type: application/dns-message\r\n" +
                         "Accept: application/dns-message\r\n" +
                         $"Content-Length: {query.Length}\r\n" +
                         "Connection: close\r\n\r\n";
            var headerBytes = Encoding.ASCII.GetBytes(header);
            await ssl.WriteAsync(headerBytes.AsMemory(), ct).ConfigureAwait(false);
            await ssl.WriteAsync(query.AsMemory(), ct).ConfigureAwait(false);
            await ssl.FlushAsync(ct).ConfigureAwait(false);

            // 读取完整 HTTP 响应
            var responseBuf = await ReadUntilEndAsync(ssl, ct).ConfigureAwait(false);
            var body = ExtractHttpBody(responseBuf);
            var ips = DnsWireCodec.ParseIPAddresses(body);
            return (channelId, ips);
        }
        catch
        {
            return (channelId + ":err", Array.Empty<IPAddress>());
        }
        finally
        {
            ssl?.Dispose();
            tcp?.Dispose();
        }
    }

    // ===== DoT (RFC 7858) =====

    async Task<(string, IPAddress[])> QueryDotAsync(
        string serverIp, string sni, byte[] query, string channelId, CancellationToken ct)
    {
        TcpClient? tcp = null;
        SslStream? ssl = null;
        try
        {
            tcp = new TcpClient();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(3));
            await tcp.ConnectAsync(IPAddress.Parse(serverIp), 853, connectCts.Token).ConfigureAwait(false);

            ssl = new SslStream(tcp.GetStream(), false, ValidateServerCert, null);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                AllowRenegotiation = false,
            }, ct).ConfigureAwait(false);

            // DoT: 2字节大端长度前缀 + DNS wire format
            Span<byte> lenBuf = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(lenBuf, (ushort)query.Length);
            await ssl.WriteAsync(lenBuf, ct).ConfigureAwait(false);
            await ssl.WriteAsync(query.AsMemory(), ct).ConfigureAwait(false);
            await ssl.FlushAsync(ct).ConfigureAwait(false);

            // 读取响应：先读 2 字节长度，再读对应字节数
            var respLenBuf = new byte[2];
            await ReadExactAsync(ssl, respLenBuf, 2, ct).ConfigureAwait(false);
            var respLen = BinaryPrimitives.ReadUInt16BigEndian(respLenBuf);
            if (respLen == 0 || respLen > 4096) return (channelId + ":badlen", Array.Empty<IPAddress>());

            var respBuf = new byte[respLen];
            await ReadExactAsync(ssl, respBuf, respLen, ct).ConfigureAwait(false);
            var ips = DnsWireCodec.ParseIPAddresses(respBuf);
            return (channelId, ips);
        }
        catch
        {
            return (channelId + ":err", Array.Empty<IPAddress>());
        }
        finally
        {
            ssl?.Dispose();
            tcp?.Dispose();
        }
    }

    // ===== TLS 证书验证 =====

    /// <summary>
    /// 证书验证回调。
    /// SslStream 传入 TargetHost=sni 后，框架自动做 SAN 匹配：
    ///   - SslPolicyErrors.RemoteCertificateNameMismatch → 证书 SAN 不含 SNI 域名
    ///   - SslPolicyErrors.RemoteCertificateChainErrors → 链无效
    /// 只接受 None = 链有效 + 域名匹配，拒绝自签名和 MITM。
    /// </summary>
    static bool ValidateServerCert(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
        => cert != null && errors == SslPolicyErrors.None;

    // ===== HTTP 响应读取与解析 =====

    /// <summary>读取 SslStream 直到对端关闭连接（HTTP/1.1 Connection: close）</summary>
    static async Task<byte[]> ReadUntilEndAsync(SslStream ssl, CancellationToken ct)
    {
        using var ms = new MemoryStream(2048);
        var buf = new byte[2048];
        int n;
        while ((n = await ssl.ReadAsync(buf.AsMemory(), ct).ConfigureAwait(false)) > 0)
        {
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    /// <summary>从 HTTP 响应中提取 body（跳过 headers，找 \r\n\r\n 分界）</summary>
    static byte[] ExtractHttpBody(byte[] httpResponse)
    {
        // 找 \r\n\r\n 分隔头和体
        int bodyStart = -1;
        for (int i = 0; i < httpResponse.Length - 3; i++)
        {
            if (httpResponse[i] == '\r' && httpResponse[i + 1] == '\n' &&
                httpResponse[i + 2] == '\r' && httpResponse[i + 3] == '\n')
            {
                bodyStart = i + 4;
                break;
            }
        }
        if (bodyStart < 0 || bodyStart >= httpResponse.Length) return Array.Empty<byte>();
        var body = httpResponse.AsSpan(bodyStart).ToArray();

        // 检查是否 chunked（DoH 服务器可能用 chunked transfer）
        var headerStr = Encoding.ASCII.GetString(httpResponse, 0, bodyStart);
        if (headerStr.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
        {
            return DecodeChunkedBody(body);
        }
        return body;
    }

    /// <summary>解码 HTTP/1.1 chunked transfer-encoding</summary>
    static byte[] DecodeChunkedBody(byte[] chunked)
    {
        using var ms = new MemoryStream(chunked.Length);
        int pos = 0;
        while (pos < chunked.Length)
        {
            // 读 chunk size 行（hex + \r\n）
            int lineEnd = -1;
            for (int i = pos; i < chunked.Length - 1; i++)
            {
                if (chunked[i] == '\r' && chunked[i + 1] == '\n') { lineEnd = i; break; }
            }
            if (lineEnd < 0) break;
            var sizeStr = Encoding.ASCII.GetString(chunked, pos, lineEnd - pos).TrimEnd(';').Trim();
            // chunk-size 可能带 chunk-ext（;key=val），取分号前
            var semi = sizeStr.IndexOf(';');
            if (semi >= 0) sizeStr = sizeStr.Substring(0, semi);
            if (!int.TryParse(sizeStr, System.Globalization.NumberStyles.HexNumber, null, out var chunkSize))
                break;
            pos = lineEnd + 2; // 跳过 \r\n
            if (chunkSize == 0) break; // 最后一个 chunk
            if (pos + chunkSize > chunked.Length) break;
            ms.Write(chunked, pos, chunkSize);
            pos += chunkSize + 2; // 跳过 chunk data + \r\n
        }
        return ms.ToArray();
    }

    /// <summary>精确读取 n 字节（循环直到读满或流结束）</summary>
    static async Task ReadExactAsync(SslStream ssl, byte[] buf, int count, CancellationToken ct)
    {
        int offset = 0;
        while (offset < count)
        {
            var n = await ssl.ReadAsync(buf.AsMemory(offset, count - offset), ct).ConfigureAwait(false);
            if (n <= 0) throw new EndOfStreamException("TLS stream closed before reading complete DNS response");
            offset += n;
        }
    }
}
