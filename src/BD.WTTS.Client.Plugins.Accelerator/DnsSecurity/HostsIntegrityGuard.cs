// (c) 2026 Xing Yushuo (邢宇烁 / anjing2077) - Licensed under GPL-3.0
// Based on BeyondDimension/SteamTools (Watt Toolkit) under GPL-3.0
//
// LAYER 4.1 / Hosts file integrity guard (SHA-256 chain).
// Problem statement (from doc/SECURITY-DNS-PROTECTION.md):
//   The original Watt Toolkit edits %WINDIR%\System32\drivers\etc\hosts,
//   but never OBSERVES other processes (game "cracks", cheat tools,
//   browser search-hijackers, adware installers) silently appending
//   forged entries like:
//     203.0.113.45   store.steampowered.com    <- fake phishing store
//   Any user that launches Steam through a modified desktop shortcut
//   (another common infection vector) then enters credentials into
//   a pixel-perfect fake page.
//
// Solution: maintain lastKnownGoodSha256 written ONLY by our own
// accelerator plugin when it performs its own legal hosts rewrite
// (ProxyService.ApplyScript()). Every 1 second, a long-running
// background task re-hashes the current hosts bytes on disk.
// If SHA mismatch and we are NOT currently inside an in-flight
// write operation (guarded by _currentWritePid + timestamp window),
// we MUST fire the system-level toast notification + offer one-click
// "Restore last trusted hosts" action through INotificationService.

using System.Security.Cryptography;

namespace BD.WTTS.Client.Plugins.Accelerator.DnsSecurity;

/// <summary>
/// Phase 1 skeleton. Full implementation in follow-up commits will:
///   - write the SHA chain into %APPDATA%\WattToolkit\hosts_trust.json
///   - register a FileSystemWatcher on drivers\etc in addition to
///     the 1s periodic rehash
///   - expose a RollbackToLastTrusted() helper that re-writes hosts
///     atomically with the same elevated token the script engine uses.
/// </summary>
public sealed class HostsIntegrityGuard : IDisposable
{
    private readonly byte[] _lastKnownGoodSha256;
    private readonly CancellationTokenSource _cts;
    private Task? _loop;
    private bool _disposed;

    public HostsIntegrityGuard(string hostsFilePath)
    {
        HostsFilePath = hostsFilePath ?? throw new ArgumentNullException(nameof(hostsFilePath));

        // Phase 1 only: record initial SHA. Phase 2 wires this into
        // BD.WTTS.Client.Plugins/Accelerator Plugin.cs lifecycle so the
        // App.axaml.cs entry point starts the guard immediately after
        // DI container is built (after startup perf optimized Lazy<T>).
        if (File.Exists(hostsFilePath))
        {
            _lastKnownGoodSha256 = SHA256.HashData(File.ReadAllBytes(hostsFilePath));
        }
        else
        {
            _lastKnownGoodSha256 = new byte[32];
        }

        _cts = new CancellationTokenSource();
    }

    public string HostsFilePath { get; }

    /// <summary>True when the current on-disk hosts SHA-256 matches the
    /// last-known-good anchor. False = UI dashboard turns RED badge.</summary>
    public bool CurrentIntegrityMatches => ComputeCurrentSha()
        .SequenceEqual(_lastKnownGoodSha256);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
    }

    private byte[] ComputeCurrentSha()
    {
        if (!File.Exists(HostsFilePath)) return new byte[32];
        using var fs = new FileStream(HostsFilePath, FileMode.Open,
            FileAccess.Read, FileShare.ReadWrite);
        return SHA256.HashData(fs);
    }
}
