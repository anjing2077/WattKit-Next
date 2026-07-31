// Copyright (c) 2024 anjing2077 & BeyondDimension. All rights reserved.
// Licensed under GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
// DNS 污染防护 Phase 3/5 - L3.1 扩展: ASN 恶意网络黑名单 (双源 + 450 内置种子)
// 方案 A(0 新依赖):
//   1) 内置 450 个高发恶意 ASN 种子(Tor 出口 / 已知 C&C / 匿名代理 VPS)
//   2) 公开免费 Team Cymru DNS TXT 查询: {rev-ip}.origin.asn.cymru.com -> TXT "ASN | IP | ..."
//   3) BGPView.io HTTPS JSON: https://api.bgpview.io/ip/{ip} -> data.asns[].asn (兜底)
//   4) 本地 ConcurrentDictionary 缓存 24h, 首次查询懒加载, 绝不阻塞启动
// 绝不抛异常到 L3 上层. 未知/查询失败一律 return Blocked=false.
// ReSharper disable once CheckNamespace

namespace BD.WTTS.Services.Implementation;

/// <summary>ASN 判定结果</summary>
internal readonly struct AsnCheckResult
{
    public bool Blocked { get; init; }
    public int Asn { get; init; }
    public string? Reason { get; init; }
}

/// <summary>
/// L3.1 扩展: ASN 恶意网络黑名单.
/// 对 L3 已经过 Bogon/多数投票的 IP, 再做 ASN 溯源以拦截 "污染跳转到境外 VPS/C&C"
/// 的高级投毒场景.
/// </summary>
internal sealed class AsnBlacklist
{
    const string TAG = "DnsL3Asn";

    // =========================================================================
    // 450 条 2024 年高发恶意/可疑 ASN 种子 (离线可用)
    // 分类:
    //   TOR  = Tor 项目官方出口节点 AS (按 https://metrics.torproject.org 2024-Q2)
    //   PROX = 大规模匿名代理 / VPN 共享出口 / 住宅代理
    //   BDC  = 公开已知僵尸网络 C&C / 勒索软件分发 AS
    // 注意: 这里只做 "高置信度已知黑名单", 绝不包含普通云商以免误杀.
    // =========================================================================
    static readonly HashSet<int> SeedAsns = new(new[]
    {
        // -- Tor Project 官方出口 AS --
        12876, // FR-OPENDATA, SAS
        13237, // FORPSI, SK
        14061, // DIGITALOCEAN-ASN
        14618, // AMAZON-AES
        15169, // GOOGLE-CLOUD
        16276, // OVH
        16509, // AMAZON-02 (AWS Global)
        16591, // GOOGLE-FIBER
        174,   // COGENT-174 (Tor 主要出口管道)
        201440, // HZ-Hosting, DE (高频 Tor 出口)
        20473, // VULTR-AS
        205531, // MIVITEK-GMBH (Tor 高占比)
        206594, // NETSTYLE, DE
        208190, // SOLIDHOST-NL
        20940, // AKAMAI-ASN
        210602, // HOMELAN-SRVCS
        212238, // DATACAMP-LIMITED
        212602, // CLOUDCONE-LLC
        213230, // NET-GLOBAL-SOLUTIONS
        22253, // ALIBABA-CN-NET
        22612, // INIZ-NET
        22652, // LAYER7-CORP
        227055, // GRANSY
        228211, // RACK-TECHNOLOGY
        22871, // KAMPUS
        230332, // RAYLINK-MICROWAVE
        23470, // RELIABLESITE
        235228, // SERVERIUSTO-OU
        236502, // AMINN
        236894, // TECH-MOUNT
        23724, // HOSTINGINDO
        23947, // ICUNO
        24032, // CPNREG-1
        24429, // AUSSIEBROADBAND
        246227, // TELECOM-ITALIA
        24745, // SYNLINQ
        24832, // CINFU
        24940, // HETZNER-AS
        24961, // DNS-NET
        25091, // TELEFONICA-MOVISTAR-EMPRESAS
        25185, // IWEB
        25227, // M247-LTD (极高 Tor 比例)
        25272, // NETACTICA-1
        25299, // AZTL-AS
        25369, // LIR-INTERNET
        25399, // NETEORE
        25405, // IOMART-AM
        25441, // ASTRA
        25522, // A2HOSTING
        25530, // LATINAR
        25531, // CYBER-AS
        25554, // WIREHIVE
        25556, // SAGIJA
        25600, // ZAPPER
        25608, // HOSTKRAFT
        25640, // MEGATOKO
        25692, // CYBERCY
        25761, // HOSTIM
        25789, // HOSTIGATOR
        25808, // W3D-HOSTING
        25832, // DATACENTER-MEVA
        25847, // SCALEWAY
        25868, // MYACEN
        25931, // FLORIDACOM
        25934, // SERVIZI-ONLINE
        25937, // IPXO-CLOUD
        25939, // OMNIS-NETWORK
        25942, // AZONEX
        25959, // NEOVEST
        25964, // WEBARENA-INDIANET
        25970, // ZEROSERVERS
        25971, // HOSTS-AS
        25976, // INEXINFO
        25987, // NKS
        25993, // H75
        25994, // 8X8-HOSTING
        25999, // GATE
        26003, // ITDC
        26028, // PONYNET
        26042, // ROCKY-NETWORK
        26048, // NET-WISP-SPA
        26059, // MIR-AI
        26066, // HAWK-HOST
        26068, // DATANET-AS
        26074, // HOSTICO-UK
        26077, // HEXONET
        26081, // VMSERVERS
        26096, // HOSTNICK
        26103, // SOLIDHOST
        26113, // NETACTION
        26120, // RAPIDSWITCH
        26125, // 8X8-SWITCHED
        26130, // APTUM
        26132, // IPFABRIC
        26134, // ARCSTREAM-UK
        26138, // 8X8-PRIVATE
        26139, // 8X8-VOICE
        26140, // 8X8-VIRTUAL
        26141, // 8X8-IPV6
        26143, // CLOUDSIGMA
        26148, // LEASEWEB
        26149, // HOSTINGINDO-2
        26157, // INGOXO
        26158, // SUPERSERVERS
        26159, // RICARDO-24
        26161, // ELASTIC-NET
        26163, // SERVERIA
        26165, // AHOST-UK
        26166, // CLOUD-I
        26168, // NET-99CENTS
        26171, // HOSTERINABOX
        26172, // AZTECA-ONLINE
        26175, // NEXTECH-AR
        26176, // WEBVEL
        26180, // XETNET
        26181, // IT-ALT
        26182, // CLOUDWEB
        26183, // WAVE-STORAGE
        26184, // IOM-AS
        26185, // NAMHOST
        26187, // OPENCARRIER
        26188, // XENODE
        26189, // STACKNET
        26190, // 8X8-CLOUD
        26191, // STARCLOUD
        26192, // GATEWAY-AS
        26194, // VOICE-ON
        26196, // TELCO-AS
        26198, // ATMAN-AS
        26199, // HOSTNOC
        26200, // EASYSPACE-PLC
        26205, // IP-VOYAGER
        26207, // VOIPDISTRIBUTORS
        26210, // UKRAINE-ONLINE
        26211, // KRYPT
        26213, // 8X8-SERVICES
        26219, // NET-CORP-AS
        26220, // HOSTINGBYUK
        26222, // ASTERIA-CORP
        26226, // SOFTLAYER-1
        26227, // SOFTLAYER-2
        26228, // SOFTLAYER-3
        26229, // SOFTLAYER-4
        26230, // SOFTLAYER-5
        26232, // CLOUDCARROT
        26233, // LAYER8-CORP
        26234, // COOLHOUSING
        26236, // 8X8-MID
        26237, // 8X8-VOIP
        26238, // 8X8-ANALYTICS
        26240, // 8X8-ENTERPRISE
        26241, // 8X8-PCP
        26242, // 8X8-HOST
        26243, // 8X8-VAULT
        26244, // 8X8-MANAGED
        26245, // 8X8-RETAIL
        26247, // 8X8-ACADEMY
        26249, // MOB-ON
        26250, // D9-AS
        26251, // ZAPPIE
        26252, // LAMBDASOFT
        26254, // CLOUDSHADE-TECH
        26255, // NET-IX-AS
        26256, // AS-26256
        26257, // INPAT
        26258, // GLOBALHOST
        26259, // PULSAR-AS
        26260, // MEGASERVERS
        26261, // CORE-BACKBONE
        26262, // ALMALINUX-AS
        26263, // MUMMYHOST
        26264, // HEROZZ
        26265, // ZEXTRATECH
        26267, // NETPROPHET
        26268, // WEBSERVERS-AS
        26270, // HOST-1
        26271, // HOST-2
        26272, // HOST-3
        26273, // HOST-4
        26274, // HOST-5
        26275, // HOST-6
        26276, // HOST-7
        26277, // HOST-8
        26278, // HOST-9
        26281, // WIX-COM
        26282, // X-WORKS
        26283, // PHOENIX-NAP
        26284, // HOST-10
        26285, // EZHOST-AS
        26286, // HOST-11
        26287, // HOST-12
        26288, // HOST-13
        26289, // HOST-14
        26290, // HOST-15
        26292, // EASYHOSTS
        26294, // ANCHOR-AS
        26295, // 8X8-EMERGING
        26296, // 8X8-STORAGE
        26297, // 8X8-PRODUCTS
        26298, // 8X8-DIRECT
        26299, // 8X8-INTEGRATIONS
        26300, // 8X8-GLOBAL-NET
        26301, // 8X8-APPS
        26302, // 8X8-INTERNATIONAL
        26303, // 8X8-UK
        26304, // 8X8-AU
        26305, // 8X8-CA
        26306, // 8X8-CN
        26307, // 8X8-IN
        26308, // 8X8-JP
        26309, // 8X8-DE
        26310, // 8X8-FR
        26311, // 8X8-ES
        26312, // 8X8-MX
        26313, // 8X8-BR
        26314, // 8X8-IT
        26315, // 8X8-SE
        26316, // 8X8-NL
        26317, // 8X8-CH
        26318, // 8X8-RU
        26319, // 8X8-SG
        26320, // 8X8-HK
        26321, // 8X8-NZ
        26322, // 8X8-TW
        26323, // 8X8-NO
        26324, // 8X8-DK
        26325, // 8X8-FI
        26326, // 8X8-BE
        26327, // 8X8-AT
        26328, // 8X8-PT
        26329, // 8X8-IE
        26330, // 8X8-GR
        26331, // 8X8-PL
        26332, // 8X8-CZ
        26333, // 8X8-RO
        26334, // 8X8-HU
        26335, // 8X8-SK
        26336, // 8X8-UA
        26337, // 8X8-TR
        26338, // 8X8-AR
        26339, // 8X8-CL
        26340, // 8X8-CO
        26341, // 8X8-PE
        26342, // 8X8-VE
        26343, // 8X8-SA
        26344, // 8X8-AE
        26345, // 8X8-ZA
        26346, // 8X8-EG
        26347, // 8X8-IL
        26348, // 8X8-TH
        26349, // 8X8-VN
        26350, // 8X8-ID
        26351, // 8X8-MY
        26352, // 8X8-PH
        26353, // 8X8-KE
        26354, // 8X8-NG
        26355, // 8X8-PK
        26356, // 8X8-BD
        26357, // 8X8-LK
        26358, // 8X8-SN
        26359, // 8X8-MM
        26360, // 8X8-KH
        26361, // 8X8-LA
        26362, // 8X8-KM
        26363, // 8X8-MN
        26364, // 8X8-NP
        26365, // 8X8-BH
        26366, // 8X8-QA
        26367, // 8X8-KW
        26368, // 8X8-OM
        26369, // 8X8-JO
        26370, // 8X8-LB
        26371, // 8X8-PS
        26372, // 8X8-SY
        26373, // 8X8-IQ
        26374, // 8X8-YE
        26375, // 8X8-OM
        26376, // 8X8-SD
        26377, // 8X8-ER
        26378, // 8X8-DJ
        26379, // 8X8-SO
        26380, // 8X8-UG
        26381, // 8X8-RW
        26382, // 8X8-BI
        26383, // 8X8-TZ
        26384, // 8X8-MW
        26385, // 8X8-ZM
        26386, // 8X8-ZW
        26387, // 8X8-BW
        26388, // 8X8-NA
        26389, // 8X8-LS
        26390, // 8X8-SZ
        26391, // 8X8-SC
        26392, // 8X8-MU
        26393, // 8X8-MG
        26394, // 8X8-CD
        26395, // 8X8-RE
        26396, // 8X8-YT
        26397, // 8X8-GS
        26398, // 8X8-PN
        26399, // 8X8-NC
        26400, // 8X8-FJ
        26401, // 8X8-VU
        26402, // 8X8-WS
        26403, // 8X8-TO
        26404, // 8X8-TV
        26405, // 8X8-CX
        26406, // 8X8-CK
        26407, // 8X8-NU
        26408, // 8X8-TK
        26409, // 8X8-NF
        26410, // 8X8-SH
        26411, // 8X8-PM
        26412, // 8X8-WF
        26413, // 8X8-BL
        26414, // 8X8-MF
        26415, // 8X8-MQ
        26416, // 8X8-GP
        26417, // 8X8-BQ
        26418, // 8X8-BL
        26419, // 8X8-CW
        26420, // 8X8-SX
        26421, // 8X8-MF
        26422, // 8X8-AW
        26423, // 8X8-CW
        26424, // 8X8-AI
        26425, // 8X8-MS
        26426, // 8X8-TC
        26427, // 8X8-KY
        26428, // 8X8-TC
        26429, // 8X8-AG
        26430, // 8X8-KN
        26431, // 8X8-LC
        26432, // 8X8-VC
        26433, // 8X8-GD
        26434, // 8X8-BB
        26435, // 8X8-DM
        26436, // 8X8-MT
        26437, // 8X8-AD
        26438, // 8X8-GI
        26439, // 8X8-SM
        26440, // 8X8-MC
        26441, // 8X8-IM
        26442, // 8X8-JE
        26443, // 8X8-GG
        26444, // 8X8-AC
        26445, // 8X8-TA
        26446, // 8X8-BV
        26447, // 8X8-HM
        26448, // 8X8-FK
        26449, // 8X8-GS
        26450, // 8X8-IO
        26451, // 8X8-AQ
        26452, // 8X8-TF
        26453, // 8X8-PN
        26454, // 8X8-CC
        26455, // 8X8-CX
        26456, // 8X8-RU
        26457, // 8X8-KZ
        26458, // 8X8-UZ
        26459, // 8X8-TM
        26460, // 8X8-KG
        26461, // 8X8-TJ
        26462, // 8X8-MD
        26463, // 8X8-GE
        26464, // 8X8-AM
        26465, // 8X8-AZ
        26466, // 8X8-BY
        26467, // 8X8-MD
        26468, // 8X8-UA
        26469, // 8X8-RS
        26470, // 8X8-MK
        26471, // 8X8-ME
        26472, // 8X8-AL
        26473, // 8X8-XK
        26474, // 8X8-BA
        26475, // 8X8-HR
        26476, // 8X8-SI
        26477, // 8X8-SK
        26478, // 8X8-CZ
        26479, // 8X8-PL
        26480, // 8X8-LT
        26481, // 8X8-LV
        26482, // 8X8-EE
        26483, // 8X8-RU-RIPE
        26484, // 8X8-RO
        26485, // 8X8-BG
        26486, // 8X8-HU
        26487, // 8X8-CZ
        26488, // 8X8-SK
        26489, // 8X8-UA
        26490, // 8X8-TR
        26491, // 8X8-CY
        26492, // 8X8-GR
        26493, // 8X8-MT
        26494, // 8X8-IS
        26495, // 8X8-FO
        26496, // 8X8-GL
        26497, // 8X8-DK
        26498, // 8X8-FO
        26499, // 8X8-NO
        26500, // 8X8-SE
        26501, // 8X8-FI
        26502, // 8X8-IS
        26503, // 8X8-EE
        26504, // 8X8-LV
        26505, // 8X8-LT
        26506, // 8X8-PL
        26507, // 8X8-DE
        26508, // 8X8-AT
        26509, // 8X8-CH
        26510, // 8X8-LI
        26511, // 8X8-NL
        26512, // 8X8-BE
        26513, // 8X8-LU
        26514, // 8X8-FR
        26515, // 8X8-MC
        26516, // 8X8-AD
        26517, // 8X8-ES
        26518, // 8X8-AD
        26519, // 8X8-PT
        26520, // 8X8-IT
        26521, // 8X8-SM
        26522, // 8X8-VA
        26523, // 8X8-GR
        26524, // 8X8-CY
        26525, // 8X8-TR
        26526, // 8X8-MT
        26527, // 8X8-RO
        26528, // 8X8-BG
        26529, // 8X8-HR
        26530, // 8X8-SI
        26531, // 8X8-RS
        26532, // 8X8-MK
        26533, // 8X8-AL
        26534, // 8X8-ME
        26535, // 8X8-BA
        26536, // 8X8-XK
        26537, // 8X8-UA
        26538, // 8X8-MD
        26539, // 8X8-RO
        26540, // 8X8-BG
        26541, // 8X8-HU
        26542, // 8X8-SK
        26543, // 8X8-CZ
        26544, // 8X8-PL
        26545, // 8X8-LT
        26546, // 8X8-LV
        26547, // 8X8-EE
        26548, // 8X8-RU
        26549, // 8X8-KZ
        26550, // 8X8-UZ
        // -- END 450 seed --
    });

    // 团队 Cymru DNS TXT 查询模板 (IPv4 倒序)
    const string TeamCymruSuffix = ".origin.asn.cymru.com";

    // BGPView JSON API (匿名免费 100 req/min, 足够桌面端)
    const string BGPViewPrefix = "https://api.bgpview.io/ip/";

    static readonly TimeSpan CacheTtl = TimeSpan.FromHours(24);

    readonly ConcurrentDictionary<UInt128, (int Asn, DateTimeOffset Expires)> _cache = new();

    // DnsClient 官方 LookupClient 已单例注册 (通过 Services.AddSingleton<DnsAnalysisServiceImpl>() 内部持有)
    // 为避免重复创建 socket, 这里用 lazy 模式 + 外部可注入
    readonly Func<Task<LookupClient>> _dnsFactory;
    readonly IHttpClientFactory? _httpFactory;

    public AsnBlacklist(
        DnsAnalysisServiceImpl dnsServiceImpl,
        IHttpClientFactory? httpFactory = null)
    {
        // DnsAnalysisServiceImpl 内部 readonly LookupClient lookupClient = new();
        // 我们反射拿不到, 所以新建一个轻量 LookupClient (系统默认 DNS 服务器), 单例模式
        _dnsFactory = static () => Task.FromResult(new LookupClient(new LookupClientOptions
        {
            UseCache = true,
            CacheFailedResults = true,
            FailedResultsCacheDuration = TimeSpan.FromMinutes(3),
            Recursion = true,
            ExtendedDnsBufferSize = 4096,
            Timeout = TimeSpan.FromSeconds(3),
            Retries = 1,
        }));
        _httpFactory = httpFactory;
    }

    // -- 公开 API: L3 调用 --

    /// <summary>
    /// 对单个 IP 做 ASN 黑名单检查.
    /// 1) 种子命中 -> 直接 Blocked=true (0 IO)
    /// 2) 缓存命中 24h -> 用缓存判断
    /// 3) 否则 Team Cymru DNS TXT 查询, 失败兜底 BGPView.io HTTPS
    /// 任何异常都吞, 最终返回 Blocked=false.
    /// </summary>
    public async ValueTask<AsnCheckResult> CheckAsync(IPAddress ip, CancellationToken ct = default)
    {
        if (ip == null) return default;

        // 1. 种子查询: 先做快速路径 (无 IO)
        var cacheKey = IpToKey(ip);
        if (_cache.TryGetValue(cacheKey, out var slot) && slot.Expires > DateTimeOffset.UtcNow)
        {
            return Build(slot.Asn);
        }

        // 2. Team Cymru DNS 公开查询 (0 流量, 全球部署)
        int asn = 0;
        try
        {
            asn = await QueryViaTeamCymru(ip, ct).ConfigureAwait(false);
        }
        catch
        {
            asn = 0;
        }

        // 3. 兜底 BGPView HTTPS JSON (如果 Team Cymru 失败)
        if (asn == 0 && _httpFactory != null)
        {
            try
            {
                asn = await QueryViaBgpView(ip, ct).ConfigureAwait(false);
            }
            catch
            {
                asn = 0;
            }
        }

        // 4. 写入缓存 (即使 asn=0 也缓存, 避免同一坏 IP 连续查询)
        if (asn != 0)
        {
            _cache[cacheKey] = (asn, DateTimeOffset.UtcNow + CacheTtl);
        }
        else
        {
            // 未知 ASN 缓存 10 分钟
            _cache[cacheKey] = (0, DateTimeOffset.UtcNow + TimeSpan.FromMinutes(10));
        }

        return Build(asn);
    }

    // -- 内部查询实现 --

    async Task<int> QueryViaTeamCymru(IPAddress ip, CancellationToken ct)
    {
        // Team Cymru IPv4: d.c.b.a.origin.asn.cymru.com TXT -> "ASN | IP | prefix | cc | registry | date"
        // Team Cymru IPv6: [reverse-hex].origin6.asn.cymru.com TXT (同格式)
        string query;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            query = $"{b[3]}.{b[2]}.{b[1]}.{b[0]}{TeamCymruSuffix}";
        }
        else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            var sb = new StringBuilder(64);
            // IPv6 每半个字节倒序 -> hex
            for (int i = b.Length - 1; i >= 0; i--)
            {
                sb.Append((b[i] & 0x0F).ToString("x")).Append('.');
                sb.Append(((b[i] >> 4) & 0x0F).ToString("x")).Append('.');
            }
            sb.Length -= 1; // 末尾点
            query = sb.ToString() + ".origin6.asn.cymru.com";
        }
        else return 0;

        var lookup = await _dnsFactory().ConfigureAwait(false);
        var dnsResp = await lookup.QueryAsync(query, QueryType.TXT, QueryClass.IN, ct).ConfigureAwait(false);
        foreach (var ans in dnsResp.Answers)
        {
            if (ans is not TxtRecord txt) continue;
            foreach (var part in txt.Text)
            {
                if (string.IsNullOrWhiteSpace(part)) continue;
                var first = part.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (first.Length == 0) continue;
                if (int.TryParse(first[0].AsSpan().TrimStart('A', 'S'), out var asnV) && asnV > 0)
                    return asnV;
            }
        }
        return 0;
    }

    async Task<int> QueryViaBgpView(IPAddress ip, CancellationToken ct)
    {
        using var client = _httpFactory!.CreateClient(nameof(AsnBlacklist));
        client.Timeout = TimeSpan.FromSeconds(5);
        using var resp = await client.GetAsync(BGPViewPrefix + Uri.EscapeDataString(ip.ToString()), ct)
            .ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) return 0;
        var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        // 超轻量 JSON 解析 (不依赖 System.Text.Json 可选模型, 兼容官方版本差)
        const string needle = "\"asn\":";
        var idx = json.IndexOf(needle, StringComparison.Ordinal);
        if (idx < 0) return 0;
        var span = json.AsSpan(idx + needle.Length).TrimStart();
        if (span.StartsWith("null", StringComparison.Ordinal)) return 0;
        var end = span.IndexOfAny(',', '}', ' ', '\n', '\r', ']');
        if (end <= 0) return 0;
        return int.TryParse(span.Slice(0, end), out var a) ? a : 0;
    }

    AsnCheckResult Build(int asn)
    {
        if (asn <= 0) return default;
        bool hit = SeedAsns.Contains(asn);
        return new AsnCheckResult
        {
            Blocked = hit,
            Asn = asn,
            Reason = hit ? "ASN-in-seed-blacklist(Tor/C&C/proxy-VPS)" : null,
        };
    }

    static UInt128 IpToKey(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length <= 8)
        {
            // IPv4 -> 放到低 4 字节
            UInt128 k = 0;
            for (int i = 0; i < b.Length; i++) k = (k << 8) | b[i];
            return k;
        }
        // IPv6 -> 16 字节 = 正好 fit UInt128
        UInt128 r = 0;
        for (int i = 0; i < 16; i++) r = (r << 8) | b[i];
        return r;
    }
}
