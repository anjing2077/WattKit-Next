# WattKit-Next · Cold-Startup Performance Optimization Plan (priority #1)

Goal (official develop baseline = 3~5s cold start on mid-range Win11):
  * Target:  < 1.0 s  cold-start -> MainWindow rendered + interactive
  * Target:  < 50 ms plugin subsystem initialized (no DNS/network on UI thread)
  * Target:  -30% private bytes at idle compared to upstream develop baseline

Top 5 concrete items tracked in this branch:
  1. [ ] Split BD.WTTS.Client `IApplication.Program.cs` sync single-lock init -> AsyncLazy<T> per heavyweight service
  2. [ ] Move hosts script scan + WinDivertInitHelper out of App.xaml.cs ctor into Task.Run (background)
  3. [ ] Use Avalonia compiled bindings (XamlCompile) across 7 most-visited Pages
  4. [ ] Defer plugin DI container scan (PluginStorePage assets) until user first opens Plugin tab
  5. [ ] Remove 4 unnecessary synchronous WMI/DeviceIdHelper calls in startup path -> cached + lazy

Measurement:
  * Use dotnet-trace collect --process-id <pid> --providers Microsoft-Windows-DotNETRuntime:0x40002001:5
  * Compare flamegraphs before/after each PR merged to develop branch.

---
Legal: This repository is a fork of BeyondDimension/SteamTools (Watt Toolkit)
licensed GPL-3.0, see /LICENSE file in repository root.
