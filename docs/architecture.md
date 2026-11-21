# Architecture

```text
HHJ Remote Manager (Administrator Laptop, e.g. Singapore)
    |
    |  Authenticated SSH (SSH.NET, public-key + pinned host key)
    |  over Tailscale WireGuard tunnel (CGNAT traversal / DERP relay)
    v
Managed Windows PC (e.g. Sri Lanka)
    +-- Tailscale Windows Service (unattended mode)
    +-- Windows OpenSSH Server (sshd service, Automatic startup)
    +-- Windows Defender Firewall ("HHJ Remote Manager - OpenSSH (Tailscale only)")
    +-- Windows PowerShell 5.1 (-EncodedCommand, structured JSON output)
    +-- Windows CIM / Performance Counters / Service Control Manager
```

## Design Principles

1. **No custom privileged daemon**: The managed PC runs only Microsoft's `sshd` and Tailscale's official Windows service.
2. **Structured JSON telemetry**: PowerShell scripts emit compact JSON (`ConvertTo-Json -Compress`) using raw `Win32_PerfRawData_*` counters. CPU utilization and network throughput are computed client-side from consecutive counter deltas—never from localized console tables or cumulative process CPU time.
3. **Host-key pinning & explicit trust**: The desktop app refuses to connect to an unpinned host key until the administrator inspects and approves its SHA-256 fingerprint.
4. **Non-overlapping polling**: `TelemetryPoller` awaits each SSH command before scheduling the next interval (`2`, `5`, `10`, or `30` seconds), preventing request pile-ups on slow or relayed links.
