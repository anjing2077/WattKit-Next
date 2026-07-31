# WattKit-Next · DNS Pollution Protection Feature Overview

This folder contains **Phase 1 / 5 of the DNS-pollution protection subsystem**
designed and implemented on top of the upstream BeyondDimension/SteamTools
(Watt Toolkit) develop branch (fork).

The full end-to-end design lives at
**[doc/SECURITY-DNS-PROTECTION.md](../doc/SECURITY-DNS-PROTECTION.md)** —
any engineer editing files in this directory MUST read the doc FIRST.

## 5-layer architecture (quick reference)

| Layer | Name                              | Implementation status               |
|-------|-----------------------------------|-------------------------------------|
| L1    | UI dashboard + health score badge | Phase 4 (planned after L2/L3 ship)  |
| L2    | 6-channel parallel resolver       | `IDnsParallelResolver.cs` (contract) Phase 1 / concrete Phase 2 |
| L3.1  | Blacklist / threat intel match    | Phase 2 / `DnsResultVerifier.cs`    |
| L3.2  | Majority vote + DNSSEC verify    | `DnsVerdict.cs` (enum) / `DnsResultVerifier.cs` (Phase 2) |
| L3.3  | 30-day fingerprint anchors       | Phase 3                             |
| L4.1  | Hosts SHA-256 integrity guard    | `HostsIntegrityGuard.cs` (Phase 1 skeleton) |
| L4.2  | System-DNS rollback protection   | Phase 3                             |
| L5    | (optional) WinDivert 53/UDP trap | Phase 5 (reuses existing WinDivert helpers in the plugin) |

## Namespace & project location

All source files:

    src/BD.WTTS.Client.Plugins.Accelerator/DnsSecurity/
    ├── DnsVerdict.cs               # L3.2 verdict enum (public surface)
    ├── IDnsParallelResolver.cs     # L2 6-channel resolver contract
    ├── HostsIntegrityGuard.cs      # L4.1 SHA-256 hosts integrity chain
    └── README.md                   # this file

Design + validation matrix:

    doc/SECURITY-DNS-PROTECTION.md  # MUST READ — full architecture,
                                      threat model, integration test
                                      cases T-POL-01..T-POL-05 and
                                      T-INT-01 (cold-start latency).

## Coding rules enforced across all 5 phases

1. **No throw on any DNS resolution path** — any channel failure must
   degrade to an empty IP set; upper layers still run majority vote on
   the remaining healthy channels.
2. **No blocking of the UI (WPF / Avalonia) thread.** All new public
   entry points expose a `*Async(CancellationToken)` overload, required
   by the parallel cold-start startup optimization.
3. **All code in this directory inherits GPL-3.0 from upstream
   BeyondDimension/SteamTools.** Full license text is in the
   repository root `LICENSE` file.
