// (c) 2026 Xing Yushuo (邢宇烁 / anjing2077) - Licensed under GPL-3.0
// Based on BeyondDimension/SteamTools (Watt Toolkit) under GPL-3.0
//
// DESIGN DOC: doc/SECURITY-DNS-PROTECTION.md  (MUST READ before editing)
// LAYER 2: 6-channel parallel DNS resolver interface contract.
//
// Channel matrix (configurable, defaults in parentheses):
//   udp-system       -> Windows system DNS (53/UDP plain)            [baseline]
//   doh-google       -> https://dns.google/dns-query (TLS 1.3)       [trusted]
//   doh-cloudflare   -> https://1.1.1.1/dns-query   (TLS 1.3 + ECH) [fastest]
//   dot-quad9        -> dns.quad9.net:853 (DoT TCP)                 [threat intel]
//   dns-google-pub   -> 8.8.8.8 with EDNS0 DO bit (DNSSEC verify)   [RRSIG verify]
//   dns-opennic      -> OpenNIC tier-2 nodes (decentralized fallback)
//
// Voting and validation is NOT the responsibility of this interface;
// DnsResultVerifier (Layer 3) performs that after all parallel calls
// complete. Cancellation tokens MUST flow through to every channel
// so that L4 hosts-guard shutdowns never deadlock a pending resolve.

using System.Net;

namespace BD.WTTS.Client.Plugins.Accelerator.DnsSecurity;

public interface IDnsParallelResolver
{
    /// <summary>
    /// Returns per-channel raw IP sets as soon as each upstream responds
    /// (or times out). First item is the channel ID (see Layer 2 matrix).
    /// Implementations MUST NOT throw — any network failure must be
    /// represented as an empty IP list for the specific channel.
    /// </summary>
    IReadOnlyDictionary<string, IPAddress[]> ResolveAllAAndAAAA(
        string domainName,
        TimeSpan perChannelTimeout,
        CancellationToken cancellationToken);

    /// <summary>
    /// Async version of ResolveAllAAndAAAA (preferred for all new call
    /// paths inside the accelerator plugin). Required by startup
    /// optimization spec so the DNS subsystem never blocks the WPF /
    /// Avalonia UI thread (cold-start target sub-30 ms).
    /// </summary>
    Task<IReadOnlyDictionary<string, IPAddress[]>> ResolveAllAAndAAAAAsync(
        string domainName,
        TimeSpan perChannelTimeout,
        CancellationToken cancellationToken);

    /// <summary>
    /// Number of upstream channels currently enabled and healthy.
    /// The L3 voting threshold (default 3/5) is recomputed dynamically
    /// against this value whenever a channel is marked sick/healthy.
    /// </summary>
    int HealthyChannelCount { get; }
}
