// (c) 2026 Xing Yushuo (邢宇烁 / anjing2077) - Licensed under GPL-3.0
// Based on BeyondDimension/SteamTools (Watt Toolkit) under GPL-3.0
//
// Design doc: doc/SECURITY-DNS-PROTECTION.md
// This is LAYER 3.2 verdict enum. See DnsResultVerifier.cs for full voting logic.
//
// NOTE: This file is a SKELETON (phase 1 of 5). The full voting + DNSSEC RRSIG
// signature verification + 5-channel parallel resolver will be implemented in
// phases 2-5. Any exception here MUST NOT crash the accelerator plugin.
// The resolver MUST fall back to last known-good fingerprint anchors on error.

namespace BD.WTTS.Client.Plugins.Accelerator.DnsSecurity;

/// <summary>
/// Verdict output for a single DNS resolve operation through the
/// WattKit-Next DNS Pollution Protection (Layer 3 filter chain).
/// Consumer code MUST NEVER use SuspiciousRed/MaliciousBlock IP addresses.
/// </summary>
public enum DnsVerdict : byte
{
    /// <summary>
    /// ≥4/5 upstream channels agreed AND (if the zone is signed)
    /// DNSSEC RRSIG validation passed. Green badge in the UI dashboard.
    /// Result is 100% safe and cacheable for TTL duration.
    /// </summary>
    TrustedGreen = 0,

    /// <summary>
    /// ≥3/5 upstreams agreed, zone has no DNSSEC signature (common for
    /// many Steam community CDN zones). No threat-intel blacklist hit.
    /// Yellow badge, cacheable but fingerprint should be re-checked
    /// on every next resolve.
    /// </summary>
    LikelyOkYellow = 1,

    /// <summary>
    /// Less than 3/5 upstreams agreed OR DNSSEC RRSIG signature
    /// verification failed OR the returned IP belongs to a CIDR block
    /// that has NEVER appeared in the 30-day fingerprint anchor history.
    /// Red badge. Consumer MUST either BLOCK, or require explicit user
    /// confirmation via an Application-level modal dialog.
    /// </summary>
    SuspiciousRed = 2,

    /// <summary>
    /// Direct L3.1 threat-intel hit (known DNS-pollution IP pool,
    /// MaxMind anonymous proxy, known C&C ASN, or official signature
    /// anchor mismatch). RED BLOCK badge, consumer MUST return 0.0.0.0
    /// (or ::0 for IPv6) and NEVER actually initiate a socket connection
    /// to the returned IP set.
    /// </summary>
    MaliciousBlock = 3,
}
