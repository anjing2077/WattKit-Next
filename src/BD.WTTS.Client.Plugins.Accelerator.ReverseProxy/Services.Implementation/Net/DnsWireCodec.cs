// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 6 — RFC 1035 wire format 编解码（0 新依赖，纯 BCL）
// 用于 Socket 级 DoH/DoT 解析器：构造 DNS 查询二进制 + 解析响应提取 IP
// ReSharper disable once CheckNamespace

using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace BD.WTTS.Services.Implementation;

/// <summary>
/// DNS wire format 编解码器 (RFC 1035 Section 4)
/// 纯 BCL 实现，0 新依赖。线程安全：全部 static 方法，无状态。
/// </summary>
internal static class DnsWireCodec
{
    // —— DNS 记录类型 (RFC 1035 Section 3.2.2) ——
    public const ushort QTYPE_A = 1;
    public const ushort QTYPE_AAAA = 28;
    public const ushort QTYPE_CNAME = 5;
    public const ushort QCLASS_IN = 1;

    /// <summary>
    /// 构造 DNS 查询报文 (RFC 1035 Section 4.1)
    /// Header(12) + Question(NAME + TYPE + CLASS)
    /// RD=1 (Recursion Desired)，让递归 DNS 服务器帮忙查
    /// </summary>
    public static byte[] BuildQuery(string domain, ushort qtype)
    {
        domain = (domain ?? "").TrimEnd('.');
        // Header: ID=随机, Flags=0x0100(RD=1), QDCOUNT=1, AN=NS=AR=0
        Span<byte> header = stackalloc byte[12];
        var id = (ushort)Random.Shared.Next(0, 0xFFFF + 1);
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x0100); // RD=1
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);      // QDCOUNT
        // ANCOUNT/NSCOUNT/ARCOUNT = 0 (已由 stackalloc 零初始化)

        // Question: QNAME(labels) + QTYPE(2) + QCLASS(2)
        using var ms = new MemoryStream(12 + domain.Length + 8);
        ms.Write(header);
        EncodeDomainName(ms, domain);
        Span<byte> tail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(tail[0..2], qtype);
        BinaryPrimitives.WriteUInt16BigEndian(tail[2..4], QCLASS_IN);
        ms.Write(tail);
        return ms.ToArray();
    }

    /// <summary>域名编码为 DNS wire format label 序列</summary>
    static void EncodeDomainName(MemoryStream ms, string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            ms.WriteByte(0);
            return;
        }
        var labels = name.Split('.');
        foreach (var label in labels)
        {
            if (label.Length == 0) continue;
            var bytes = Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0); // 根终止符
    }

    /// <summary>
    /// 解析 DNS 响应报文，提取所有 A/AAAA 记录的 IP 地址。
    /// 跳过 CNAME 记录（不递归，由调用方决定是否追查）。
    /// 绝不抛异常：任何解析错误返回空数组。
    /// </summary>
    public static IPAddress[] ParseIPAddresses(byte[] response)
    {
        try
        {
            if (response == null || response.Length < 12) return Array.Empty<IPAddress>();
            var r = new SpanReader(response);
            // Header
            r.ReadUInt16(); // ID
            var flags = r.ReadUInt16();
            var isResponse = (flags & 0x8000) != 0;
            var rcode = (byte)(flags & 0x000F);
            if (!isResponse || rcode != 0) return Array.Empty<IPAddress>();
            var qdcount = r.ReadUInt16();
            var ancount = r.ReadUInt16();
            r.ReadUInt16(); // NSCOUNT
            r.ReadUInt16(); // ARCOUNT

            // 跳过 Question section
            for (int i = 0; i < qdcount; i++)
            {
                r.SkipDomainName();
                r.Skip(4); // QTYPE + QCLASS
            }

            // 解析 Answer section
            var ips = new List<IPAddress>(ancount);
            for (int i = 0; i < ancount; i++)
            {
                r.SkipDomainName(); // NAME (可能是压缩指针)
                var type = r.ReadUInt16();
                r.ReadUInt16(); // CLASS
                r.ReadUInt32(); // TTL
                var rdlength = r.ReadUInt16();
                if (type == QTYPE_A && rdlength == 4)
                {
                    ips.Add(new IPAddress(r.ReadBytes(4)));
                }
                else if (type == QTYPE_AAAA && rdlength == 16)
                {
                    ips.Add(new IPAddress(r.ReadBytes(16)));
                }
                else
                {
                    // CNAME / 其他：跳过 RDATA
                    r.Skip(rdlength);
                }
            }
            return ips.ToArray();
        }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }

    /// <summary>Span-based 读取器，支持 DNS 压缩指针解析</summary>
    ref struct SpanReader
    {
        readonly byte[] _data;
        int _pos;

        public SpanReader(byte[] data) { _data = data; _pos = 0; }

        public ushort ReadUInt16()
        {
            var v = BinaryPrimitives.ReadUInt16BigEndian(_data.AsSpan(_pos, 2));
            _pos += 2;
            return v;
        }

        public uint ReadUInt32()
        {
            var v = BinaryPrimitives.ReadUInt32BigEndian(_data.AsSpan(_pos, 4));
            _pos += 4;
            return v;
        }

        public byte[] ReadBytes(int count)
        {
            var r = _data.AsSpan(_pos, count).ToArray();
            _pos += count;
            return r;
        }

        public void Skip(int count) => _pos += count;

        /// <summary>跳过域名（处理压缩指针 0xC0）</summary>
        public void SkipDomainName()
        {
            while (_pos < _data.Length)
            {
                var len = _data[_pos];
                if (len == 0) { _pos++; return; }
                if ((len & 0xC0) == 0xC0) // 压缩指针：2 字节
                {
                    _pos += 2;
                    return;
                }
                _pos += 1 + len; // 普通 label
            }
        }
    }
}
