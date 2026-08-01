// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DnsWireCodec 单元测试 — RFC 1035 wire format 编解码往返验证
// 验证 BuildQuery 生成的二进制可以被 DNS 服务器正确理解，
// 以及 ParseIPAddresses 能从响应中正确提取 IP 地址。

using System.Buffers.Binary;
using System.Net;
using System.Text;
using BD.WTTS.Services.Implementation;

namespace BD.WTTS.UnitTest;

public sealed class DnsWireCodecTest
{
    // —— BuildQuery 结构验证 ——

    [Test]
    public void BuildQuery_Header_HasCorrectFlags()
    {
        var query = DnsWireCodec.BuildQuery("example.com", DnsWireCodec.QTYPE_A);

        // Header: 12 bytes
        Assert.That(query.Length, Is.GreaterThanOrEqualTo(12));

        // ID: 2 bytes (random, just check it's readable)
        var id = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(0, 2));
        Assert.That(id, Is.InRange(0, 0xFFFF));

        // Flags: RD=1 (Recursion Desired) → 0x0100
        var flags = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2, 2));
        Assert.That(flags & 0x0100, Is.EqualTo(0x0100), "RD bit should be set");

        // QDCOUNT = 1
        var qdcount = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(4, 2));
        Assert.That(qdcount, Is.EqualTo(1));

        // ANCOUNT = NSCOUNT = ARCOUNT = 0
        Assert.That(BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(6, 2)), Is.EqualTo(0));
        Assert.That(BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(8, 2)), Is.EqualTo(0));
        Assert.That(BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(10, 2)), Is.EqualTo(0));
    }

    [Test]
    public void BuildQuery_QName_EncodesLabelsCorrectly()
    {
        var query = DnsWireCodec.BuildQuery("www.example.com", DnsWireCodec.QTYPE_A);

        // Question starts at offset 12
        // Expected: 3www7example3com0
        int pos = 12;
        Assert.That(query[pos], Is.EqualTo(3), "First label length should be 3");
        Assert.That(Encoding.ASCII.GetString(query, pos + 1, 3), Is.EqualTo("www"));
        pos += 4;

        Assert.That(query[pos], Is.EqualTo(7), "Second label length should be 7");
        Assert.That(Encoding.ASCII.GetString(query, pos + 1, 7), Is.EqualTo("example"));
        pos += 8;

        Assert.That(query[pos], Is.EqualTo(3), "Third label length should be 3");
        Assert.That(Encoding.ASCII.GetString(query, pos + 1, 3), Is.EqualTo("com"));
        pos += 4;

        Assert.That(query[pos], Is.EqualTo(0), "Root terminator should be 0");
        pos += 1;

        // QTYPE = A (1)
        Assert.That(BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(pos, 2)), Is.EqualTo(1));
        pos += 2;

        // QCLASS = IN (1)
        Assert.That(BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(pos, 2)), Is.EqualTo(1));
    }

    [Test]
    public void BuildQuery_QTypeAaaa_SetsCorrectType()
    {
        var query = DnsWireCodec.BuildQuery("example.com", DnsWireCodec.QTYPE_AAAA);

        // Find QTYPE after the QNAME (example.com = 7example3com0 = 12 bytes)
        int qtypeOffset = 12 + 7 + 1 + 3 + 1 + 1; // header(12) + labels + root
        // Actually: 12 (header) + 1+7 (example) + 1+3 (com) + 1 (root) = 25
        qtypeOffset = 12 + 8 + 4 + 1;
        var qtype = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(qtypeOffset, 2));
        Assert.That(qtype, Is.EqualTo(DnsWireCodec.QTYPE_AAAA));
    }

    [Test]
    public void BuildQuery_EmptyDomain_ProducesRootQuery()
    {
        var query = DnsWireCodec.BuildQuery("", DnsWireCodec.QTYPE_A);
        // Should just have root terminator (0) after header
        Assert.That(query[12], Is.EqualTo(0));
    }

    [Test]
    public void BuildQuery_TrailingDot_IsStripped()
    {
        var q1 = DnsWireCodec.BuildQuery("example.com.", DnsWireCodec.QTYPE_A);
        var q2 = DnsWireCodec.BuildQuery("example.com", DnsWireCodec.QTYPE_A);
        Assert.That(q1, Is.EqualTo(q2), "Trailing dot should be stripped");
    }

    [Test]
    public void BuildQuery_DifferentDomains_ProduceDifferentQueries()
    {
        var q1 = DnsWireCodec.BuildQuery("a.com", DnsWireCodec.QTYPE_A);
        var q2 = DnsWireCodec.BuildQuery("b.com", DnsWireCodec.QTYPE_A);
        Assert.That(q1, Is.Not.EqualTo(q2));
    }

    // —— ParseIPAddresses 解析验证 ——

    [Test]
    public void ParseIPAddresses_EmptyInput_ReturnsEmptyArray()
    {
        var result = DnsWireCodec.ParseIPAddresses(Array.Empty<byte>());
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ParseIPAddresses_NullInput_ReturnsEmptyArray()
    {
        var result = DnsWireCodec.ParseIPAddresses(null!);
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ParseIPAddresses_ShortInput_ReturnsEmptyArray()
    {
        var result = DnsWireCodec.ParseIPAddresses(new byte[] { 1, 2, 3 });
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ParseIPAddresses_InvalidRcode_ReturnsEmpty()
    {
        // Build a response with RCODE=3 (NXDOMAIN)
        var response = BuildDnsResponse(rcode: 3, answers: Array.Empty<(ushort, byte[])>());
        var result = DnsWireCodec.ParseIPAddresses(response);
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void ParseIPAddresses_NotResponseFlag_ReturnsEmpty()
    {
        // QR=0 means it's a query, not a response
        var response = BuildDnsResponse(isResponse: false, rcode: 0, answers: Array.Empty<(ushort, byte[])>());
        var result = DnsWireCodec.ParseIPAddresses(response);
        Assert.That(result, Is.Empty);
    }

    // —— 往返测试：BuildQuery → 构造模拟响应 → ParseIPAddresses ——

    [Test]
    public void RoundTrip_SingleARecord_ParsesCorrectly()
    {
        var query = DnsWireCodec.BuildQuery("example.com", DnsWireCodec.QTYPE_A);
        var expectedIp = IPAddress.Parse("93.184.216.34");

        var response = BuildDnsResponse(
            queryId: BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(0, 2)),
            isResponse: true,
            rcode: 0,
            question: ("example.com", DnsWireCodec.QTYPE_A),
            answers: new[] { (DnsWireCodec.QTYPE_A, expectedIp.GetAddressBytes()) });

        var ips = DnsWireCodec.ParseIPAddresses(response);

        Assert.That(ips.Length, Is.EqualTo(1));
        Assert.That(ips[0], Is.EqualTo(expectedIp));
    }

    [Test]
    public void RoundTrip_MultipleARecords_ParsesAll()
    {
        var expectedIps = new[]
        {
            IPAddress.Parse("1.2.3.4"),
            IPAddress.Parse("5.6.7.8"),
            IPAddress.Parse("10.20.30.40"),
        };

        var response = BuildDnsResponse(
            question: ("multi.example.com", DnsWireCodec.QTYPE_A),
            answers: expectedIps.Select(ip => (DnsWireCodec.QTYPE_A, ip.GetAddressBytes())).ToArray());

        var ips = DnsWireCodec.ParseIPAddresses(response);

        Assert.That(ips.Length, Is.EqualTo(3));
        Assert.That(ips, Is.EquivalentTo(expectedIps));
    }

    [Test]
    public void RoundTrip_AaaaRecord_ParsesCorrectly()
    {
        var expectedIp = IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946");

        var response = BuildDnsResponse(
            question: ("ipv6.example.com", DnsWireCodec.QTYPE_AAAA),
            answers: new[] { (DnsWireCodec.QTYPE_AAAA, expectedIp.GetAddressBytes()) });

        var ips = DnsWireCodec.ParseIPAddresses(response);

        Assert.That(ips.Length, Is.EqualTo(1));
        Assert.That(ips[0], Is.EqualTo(expectedIp));
    }

    [Test]
    public void RoundTrip_CNameRecord_SkippedButNotCrashed()
    {
        var cnameTarget = Encoding.ASCII.GetBytes("cdn.example.com");
        var realIp = IPAddress.Parse("1.2.3.4");

        var response = BuildDnsResponse(
            question: ("www.example.com", DnsWireCodec.QTYPE_A),
            answers: new[]
            {
                (DnsWireCodec.QTYPE_CNAME, cnameTarget),
                (DnsWireCodec.QTYPE_A, realIp.GetAddressBytes()),
            });

        var ips = DnsWireCodec.ParseIPAddresses(response);

        // CNAME should be skipped, only A record returned
        Assert.That(ips.Length, Is.EqualTo(1));
        Assert.That(ips[0], Is.EqualTo(realIp));
    }

    [Test]
    public void RoundTrip_MixedAAndAaaa_ReturnsBoth()
    {
        var ipv4 = IPAddress.Parse("1.2.3.4");
        var ipv6 = IPAddress.Parse("::1");

        var response = BuildDnsResponse(
            question: ("dual.example.com", DnsWireCodec.QTYPE_A),
            answers: new[]
            {
                (DnsWireCodec.QTYPE_A, ipv4.GetAddressBytes()),
                (DnsWireCodec.QTYPE_AAAA, ipv6.GetAddressBytes()),
            });

        var ips = DnsWireCodec.ParseIPAddresses(response);

        Assert.That(ips.Length, Is.EqualTo(2));
        Assert.That(ips, Contains.Item(ipv4));
        Assert.That(ips, Contains.Item(ipv6));
    }

    [Test]
    public void RoundTrip_CompressionPointer_InQuestionSection()
    {
        // Use a domain with enough labels to trigger compression pointer in answer NAME
        var query = DnsWireCodec.BuildQuery("a.b.c.d.example.com", DnsWireCodec.QTYPE_A);
        var queryId = BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(0, 2));
        var expectedIp = IPAddress.Parse("99.98.97.96");

        var response = BuildDnsResponse(
            queryId: queryId,
            question: ("a.b.c.d.example.com", DnsWireCodec.QTYPE_A),
            answers: new[] { (DnsWireCodec.QTYPE_A, expectedIp.GetAddressBytes()) },
            useCompressionPointer: true);

        var ips = DnsWireCodec.ParseIPAddresses(response);

        Assert.That(ips.Length, Is.EqualTo(1));
        Assert.That(ips[0], Is.EqualTo(expectedIp));
    }

    [Test]
    public void RoundTrip_NoAnswers_ReturnsEmpty()
    {
        var response = BuildDnsResponse(
            question: ("empty.example.com", DnsWireCodec.QTYPE_A),
            answers: Array.Empty<(ushort, byte[])>());

        var ips = DnsWireCodec.ParseIPAddresses(response);
        Assert.That(ips, Is.Empty);
    }

    [Test]
    public void ParseIPAddresses_CorruptedData_DoesNotThrow()
    {
        // Random garbage bytes (but >= 12 for header)
        var garbage = new byte[] { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
        Assert.DoesNotThrow(() => DnsWireCodec.ParseIPAddresses(garbage));
        Assert.That(DnsWireCodec.ParseIPAddresses(garbage), Is.Empty);
    }

    // —— 辅助方法：构造 DNS 响应二进制 ——

    /// <summary>
    /// 手工构造 DNS 响应报文，用于测试 ParseIPAddresses。
    /// 支持 A/AAAA/CNAME 记录 + 压缩指针。
    /// </summary>
    static byte[] BuildDnsResponse(
        ushort queryId = 0x1234,
        bool isResponse = true,
        byte rcode = 0,
        (string Domain, ushort Qtype)? question = null,
        (ushort Type, byte[] Rdata)[]? answers = null,
        bool useCompressionPointer = false)
    {
        using var ms = new MemoryStream(256);

        // Header (12 bytes)
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], queryId);
        ushort flags = 0;
        if (isResponse) flags |= 0x8000; // QR=1
        flags |= 0x0100; // RD=1
        flags |= 0x8000; // RA=1 (recursion available, typical for real responses)
        flags = (ushort)(isResponse ? 0x8180 : 0x0100); // standard response or query
        flags = (ushort)(flags | (rcode & 0x0F));
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], flags);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], question != null ? 1 : 0); // QDCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], (ushort)(answers?.Length ?? 0)); // ANCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[8..10], 0); // NSCOUNT
        BinaryPrimitives.WriteUInt16BigEndian(header[10..12], 0); // ARCOUNT
        ms.Write(header);

        // Question section
        int questionNameStart = -1;
        if (question != null)
        {
            questionNameStart = (int)ms.Position;
            EncodeDomainName(ms, question.Value.Domain);
            Span<byte> qtail = stackalloc byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(qtail[0..2], question.Value.Qtype);
            BinaryPrimitives.WriteUInt16BigEndian(qtail[2..4], DnsWireCodec.QCLASS_IN);
            ms.Write(qtail);
        }

        // Answer section
        if (answers != null)
        {
            foreach (var (type, rdata) in answers)
            {
                // NAME: use compression pointer to question NAME
                if (useCompressionPointer && questionNameStart >= 0)
                {
                    // Compression pointer: 0xC0 + offset (14-bit)
                    Span<byte> ptr = stackalloc byte[2];
                    ptr[0] = 0xC0;
                    ptr[1] = (byte)questionNameStart;
                    ms.Write(ptr);
                }
                else
                {
                    EncodeDomainName(ms, question?.Domain ?? "example.com");
                }

                // TYPE + CLASS + TTL + RDLENGTH
                Span<byte> fixedFields = stackalloc byte[10];
                BinaryPrimitives.WriteUInt16BigEndian(fixedFields[0..2], type);
                BinaryPrimitives.WriteUInt16BigEndian(fixedFields[2..4], DnsWireCodec.QCLASS_IN);
                BinaryPrimitives.WriteUInt32BigEndian(fixedFields[4..8], 300); // TTL=300s
                BinaryPrimitives.WriteUInt16BigEndian(fixedFields[8..10], (ushort)rdata.Length);
                ms.Write(fixedFields);

                // RDATA
                ms.Write(rdata);
            }
        }

        return ms.ToArray();
    }

    static void EncodeDomainName(MemoryStream ms, string name)
    {
        name = name.TrimEnd('.');
        if (string.IsNullOrEmpty(name))
        {
            ms.WriteByte(0);
            return;
        }
        foreach (var label in name.Split('.'))
        {
            if (label.Length == 0) continue;
            var bytes = Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0);
    }
}
