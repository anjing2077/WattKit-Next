// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DnsResultVerifier 单元测试 — L3 加权投票场景验证
// 核心测试目标：Socket 级通道（权重 2）在 DNS 污染场景下能压过传统通道（权重 1）
// 模拟场景：
//   (1) 正常解析：所有通道返回相同 IP → 绿色/黄色
//   (2) DNS 污染：传统通道返回假 IP，Socket 通道返回真 IP → 真 IP 胜出
//   (3) 全部污染：所有通道返回相同假 IP → 红色告警
//   (4) 全部失败：所有通道超时/失败 → 黑色拦截
//   (5) Bogon/Martian IP 被过滤
//   (6) 部分通道失败：Socket 通道存活，传统通道失败 → Socket 通道结果胜出

using System.Net;
using BD.WTTS.Client.Plugins.Accelerator.DnsSecurity;
using BD.WTTS.Services.Implementation;

namespace BD.WTTS.UnitTest;

public sealed class DnsResultVerifierTest
{
    DnsResultVerifier _verifier = null!;
    DnsFingerprintAnchor _anchor = null!;

    [SetUp]
    public void Setup()
    {
        // DnsFingerprintAnchor 无参构造 → 空锚点（不会做 L3.3 硬拦截，只做 L3.1+L3.2）
        _anchor = new DnsFingerprintAnchor();
        // 不注入 ASN 黑名单和 DNSSEC，纯测试加权投票逻辑
        _verifier = new DnsResultVerifier(_anchor, asnBlacklist: null, dnsSecVerifier: null);
    }

    // —— 辅助方法：构造单通道结果 ——

    static DnsChannelResult Channel(string channelId, params string[] ips)
    {
        return new DnsChannelResult
        {
            ChannelId = channelId,
            Addresses = ips.Select(IPAddress.Parse).ToArray(),
            LatencyMs = 50,
        };
    }

    static DnsChannelResult FailedChannel(string channelId)
    {
        return new DnsChannelResult
        {
            ChannelId = channelId,
            Addresses = Array.Empty<IPAddress>(),
            LatencyMs = 2200,
        };
    }

    // ===== 场景 1：正常解析 — 所有通道返回相同 IP =====

    [Test]
    public async Task AllChannelsAgree_ReturnsLikelyOkOrGreen()
    {
        var channels = new[]
        {
            Channel("udp-system", "1.2.3.4"),
            Channel("doh-user", "1.2.3.4"),
            Channel("doh-1.1.1.1", "1.2.3.4"),
            Channel("doh-8.8.8.8", "1.2.3.4"),
            Channel("doh-223.5.5.5", "1.2.3.4"),
            Channel("dot-1.1.1.1", "1.2.3.4"),
            Channel("dot-9.9.9.9", "1.2.3.4"),
        };

        var verdict = await _verifier.VerifyAsync("example.com", channels);

        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse("1.2.3.4")));
        Assert.That(verdict.Overall, Is.EqualTo(DnsVerdict.LikelyOkYellow).Or.EqualTo(DnsVerdict.TrustedGreen),
            "All channels agree should be Green or Yellow");
    }

    // ===== 场景 2：DNS 污染 — 传统通道返回假 IP，Socket 通道返回真 IP =====

    [Test]
    public async Task DnsPollution_TraditionalChannelsReturnFakeIP_SocketChannelsWin()
    {
        var fakeIp = "6.6.6.6";   // 污染 IP
        var realIp = "1.2.3.4";   // 真 IP

        var channels = new[]
        {
            Channel("udp-system", fakeIp),      // 传统通道 权重 1 → 假 IP 得 1 票
            Channel("doh-user", fakeIp),         // 传统通道 权重 1 → 假 IP 得 1 票
            Channel("doh-1.1.1.1", realIp),     // Socket 级 权重 2 → 真 IP 得 2 票
            Channel("doh-8.8.8.8", realIp),     // Socket 级 权重 2 → 真 IP 得 2 票
            Channel("doh-223.5.5.5", realIp),   // Socket 级 权重 2 → 真 IP 得 2 票
            Channel("dot-1.1.1.1", realIp),     // Socket 级 权重 2 → 真 IP 得 2 票
            Channel("dot-9.9.9.9", realIp),     // Socket 级 权重 2 → 真 IP 得 2 票
        };

        var verdict = await _verifier.VerifyAsync("store.steampowered.com", channels);

        // 真 IP 总票数: 5*2=10, 假 IP 总票数: 1*2=2, totalWeight=12
        // majorityThreshold = (12)/2 + 1 = 7, 真 IP 10 > 7 → 胜出
        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse(realIp)),
            "Socket channels with weight 2 should win over traditional channels with weight 1");
        Assert.That(verdict.RecommendedIps, Does.Not.Contain(IPAddress.Parse(fakeIp)),
            "Polluted fake IP should NOT be in recommended IPs");
    }

    // ===== 场景 3：Socket 通道部分失败 + 传统通道被污染 =====

    [Test]
    public async Task PartialSocketFailure_StillWinsOverPollutedTraditional()
    {
        var fakeIp = "10.0.0.1";
        var realIp = "93.184.216.34";

        var channels = new[]
        {
            Channel("udp-system", fakeIp),       // 传统 权重 1
            Channel("doh-user", fakeIp),          // 传统 权重 1
            Channel("doh-1.1.1.1", realIp),      // Socket 权重 2
            Channel("doh-8.8.8.8", realIp),      // Socket 权重 2
            Channel("doh-223.5.5.5", realIp),    // Socket 权重 2
            FailedChannel("dot-1.1.1.1"),         // Socket 失败 → 0 票
            FailedChannel("dot-9.9.9.9"),         // Socket 失败 → 0 票
        };

        var verdict = await _verifier.VerifyAsync("example.com", channels);

        // 真 IP: 3*2=6, 假 IP: 2*1=2, totalWeight=8
        // majorityThreshold = 8/2+1 = 5, 真 IP 6 > 5 → 胜出
        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse(realIp)));
        Assert.That(verdict.RecommendedIps, Does.Not.Contain(IPAddress.Parse(fakeIp)));
    }

    // ===== 场景 4：全部通道失败 → MaliciousBlock =====

    [Test]
    public async Task AllChannelsFail_ReturnsMaliciousBlock()
    {
        var channels = new[]
        {
            FailedChannel("udp-system"),
            FailedChannel("doh-user"),
            FailedChannel("doh-1.1.1.1"),
            FailedChannel("doh-8.8.8.8"),
            FailedChannel("doh-223.5.5.5"),
            FailedChannel("dot-1.1.1.1"),
            FailedChannel("dot-9.9.9.9"),
        };

        var verdict = await _verifier.VerifyAsync("example.com", channels);

        Assert.That(verdict.Overall, Is.EqualTo(DnsVerdict.MaliciousBlock),
            "All channels failed should trigger MaliciousBlock");
        Assert.That(verdict.RecommendedIps, Is.Empty);
    }

    // ===== 场景 5：全部通道返回相同假 IP（疑似全面污染）→ 锚点检查 =====

    [Test]
    public async Task AllChannelsReturnSameSuspiciousIP_StillReturnsIP()
    {
        // 所有通道都返回 6.6.6.6 — L3.1 不会拦截（不是 bogon），L3.2 全票通过
        // 但 L3.3 锚点可能给 SuspiciousRed（新域名无锚点 → 黄色）
        var channels = new[]
        {
            Channel("udp-system", "6.6.6.6"),
            Channel("doh-user", "6.6.6.6"),
            Channel("doh-1.1.1.1", "6.6.6.6"),
            Channel("doh-8.8.8.8", "6.6.6.6"),
            Channel("dot-1.1.1.1", "6.6.6.6"),
        };

        var verdict = await _verifier.VerifyAsync("suspicious.example.com", channels);

        // 6.6.6.6 不是 bogon，全票通过 → 至少返回 IP（颜色可能是黄/红取决于锚点）
        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse("6.6.6.6")));
    }

    // ===== 场景 6：Bogon/Martian IP 被过滤 =====

    [Test]
    public async Task BogonIP_192_168_IsFilteredOut()
    {
        var channels = new[]
        {
            Channel("udp-system", "192.168.1.1", "1.2.3.4"),
            Channel("doh-1.1.1.1", "1.2.3.4"),
            Channel("doh-8.8.8.8", "1.2.3.4"),
        };

        var verdict = await _verifier.VerifyAsync("example.com", channels);

        Assert.That(verdict.RecommendedIps, Does.Not.Contain(IPAddress.Parse("192.168.1.1")),
            "Private IP 192.168.x.x should be filtered by L3.1 bogon/martian blacklist");
        Assert.That(verdict.BlocklistedIps, Contains.Item(IPAddress.Parse("192.168.1.1")));
    }

    [Test]
    public async Task BogonIP_127_0_0_1_IsFilteredOut()
    {
        var channels = new[]
        {
            Channel("udp-system", "127.0.0.1"),
            Channel("doh-1.1.1.1", "127.0.0.1"),
        };

        var verdict = await _verifier.VerifyAsync("localhost.example.com", channels);

        Assert.That(verdict.RecommendedIps, Does.Not.Contain(IPAddress.Parse("127.0.0.1")));
    }

    [Test]
    public async Task BogonIP_0_0_0_0_IsFilteredOut()
    {
        var channels = new[]
        {
            Channel("udp-system", "0.0.0.0"),
            Channel("doh-1.1.1.1", "0.0.0.0"),
        };

        var verdict = await _verifier.VerifyAsync("zero.example.com", channels);

        Assert.That(verdict.RecommendedIps, Does.Not.Contain(IPAddress.Parse("0.0.0.0")));
    }

    // ===== 场景 7：仅传统通道存活，Socket 全部失败 =====

    [Test]
    public async Task OnlyTraditionalChannelsAlive_StillReturnsIP()
    {
        var channels = new[]
        {
            Channel("udp-system", "1.2.3.4"),
            Channel("doh-user", "1.2.3.4"),
            FailedChannel("doh-1.1.1.1"),
            FailedChannel("doh-8.8.8.8"),
            FailedChannel("doh-223.5.5.5"),
            FailedChannel("dot-1.1.1.1"),
            FailedChannel("dot-9.9.9.9"),
        };

        var verdict = await _verifier.VerifyAsync("example.com", channels);

        // 传统通道 2*1=2 票，totalWeight=2, threshold=2
        // IP 得 2 票 >= threshold → 通过
        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse("1.2.3.4")));
    }

    // ===== 场景 8：空通道数组 =====

    [Test]
    public async Task EmptyChannels_ReturnsMaliciousBlock()
    {
        var verdict = await _verifier.VerifyAsync("example.com", Array.Empty<DnsChannelResult>());

        Assert.That(verdict.Overall, Is.EqualTo(DnsVerdict.MaliciousBlock));
        Assert.That(verdict.RecommendedIps, Is.Empty);
    }

    // ===== 场景 9：null 通道数组 =====

    [Test]
    public async Task NullChannels_ReturnsMaliciousBlock()
    {
        var verdict = await _verifier.VerifyAsync("example.com", null!);

        Assert.That(verdict.Overall, Is.EqualTo(DnsVerdict.MaliciousBlock));
    }

    // ===== 场景 10：投票平局（两个不同 IP 票数相同）=====

    [Test]
    public async Task VotingTie_DoesNotCrash()
    {
        // 1 Socket 通道 vs 1 传统通道，各返回不同 IP → 各 2 票 vs 1 票
        // Socket 通道权重 2 > 传统通道权重 1 → Socket IP 胜出
        var channels = new[]
        {
            Channel("udp-system", "1.1.1.1"),
            Channel("doh-1.1.1.1", "2.2.2.2"),
        };

        var verdict = await _verifier.VerifyAsync("tie.example.com", channels);

        // doh-1.1.1.1 权重 2, udp-system 权重 1
        // 2.2.2.2 得 2 票, 1.1.1.1 得 1 票, totalWeight=3, threshold=2
        // 2.2.2.2 得 2 票 >= 2 → 胜出
        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse("2.2.2.2")));
    }

    // ===== 场景 11：Verify 方法（同步版本）与 VerifyAsync 结果一致 =====

    [Test]
    public void SyncVerify_MatchesAsyncVerify()
    {
        var channels = new[]
        {
            Channel("udp-system", "1.2.3.4"),
            Channel("doh-1.1.1.1", "1.2.3.4"),
            Channel("doh-8.8.8.8", "1.2.3.4"),
        };

        var syncResult = _verifier.Verify("example.com", channels);
        var asyncResult = _verifier.VerifyAsync("example.com", channels).GetAwaiter().GetResult();

        Assert.That(syncResult.RecommendedIps, Is.EquivalentTo(asyncResult.RecommendedIps));
        Assert.That(syncResult.Overall, Is.EqualTo(asyncResult.Overall));
    }

    // ===== 场景 12：通道快照被正确保存 =====

    [Test]
    public async Task ChannelSnapshots_ArePreservedInVerdict()
    {
        var channels = new[]
        {
            Channel("udp-system", "1.2.3.4"),
            Channel("doh-1.1.1.1", "1.2.3.4"),
        };

        var verdict = await _verifier.VerifyAsync("example.com", channels);

        Assert.That(verdict.ChannelSnapshots.Length, Is.EqualTo(2));
        Assert.That(verdict.ChannelSnapshots[0].ChannelId, Is.EqualTo("udp-system"));
        Assert.That(verdict.ChannelSnapshots[1].ChannelId, Is.EqualTo("doh-1.1.1.1"));
    }

    // ===== 场景 13：同一通道返回多个 IP，每个 IP 只算 1 票 =====

    [Test]
    public async Task SameChannel_MultipleIPs_EachIPOneVote()
    {
        // udp-system 返回 1.2.3.4 和 5.6.7.8 → 两个 IP 各得 1 票
        // doh-1.1.1.1 只返回 1.2.3.4 → 1.2.3.4 得 2 票
        var channels = new[]
        {
            Channel("udp-system", "1.2.3.4", "5.6.7.8"),
            Channel("doh-1.1.1.1", "1.2.3.4"),
            Channel("doh-8.8.8.8", "1.2.3.4"),
        };

        var verdict = await _verifier.VerifyAsync("multi.example.com", channels);

        // 1.2.3.4: udp(1) + doh-1.1.1.1(2) + doh-8.8.8.8(2) = 5 票
        // 5.6.7.8: udp(1) = 1 票
        // totalWeight = 1+2+2 = 5, threshold = 5/2+1 = 3
        // 1.2.3.4 得 5 >= 3 → 胜出, 5.6.7.8 得 1 < 3 → 不通过
        Assert.That(verdict.RecommendedIps, Contains.Item(IPAddress.Parse("1.2.3.4")));
        Assert.That(verdict.RecommendedIps, Does.Not.Contain(IPAddress.Parse("5.6.7.8")));
    }
}
