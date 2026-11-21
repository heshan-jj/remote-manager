# HHJ Remote Manager

A personal, transparent, consent-based Remote Monitoring and Management (RMM) system for authorized Windows 10/11 computers.

HHJ Remote Manager uses **Windows OpenSSH Server** (`sshd`) over a **Tailscale** private network—no custom privileged daemon, no public IPv4 or router port forwarding, no covert persistence.

## Applications

1. **`HHJ-Agent-Setup.exe`** (`src/HHJ.Agent.Setup`)
   - Self-contained Windows x64 UAC-elevated wizard that configures native Windows OpenSSH Server, guides official Tailscale installation & enrollment, authorizes your SSH public key with strict Windows ACLs, and creates a Tailscale-only Windows Defender Firewall rule.
   - Exits after configuration, leaving only standard Windows services (`sshd` and `Tailscale`) running.
   - Supports `--disable` and `--status` CLI modes.
2. **`HHJ-Remote-Manager.exe`** (`src/HHJ.RemoteManager.Desktop`)
   - Dark-themed WPF desktop control panel for monitoring and administering multiple authorized endpoints.
   - Live CPU, RAM, disk, and network charts (calculated from raw CIM performance counter deltas), system inventory, process manager, service manager with critical-service safeguards, embedded WebView2 + xterm.js SSH terminal, event log summary, installed software inventory, and connection diagnostics.

## Solution Structure

- `src/HHJ.Shared.Contracts` — JSON telemetry DTOs shared between PowerShell scripts and Core.
- `src/HHJ.RemoteManager.Core` — Connection state machine, device validation, counter math, safe `-EncodedCommand` PowerShell builder, typed RPC client, non-overlapping poller.
- `src/HHJ.RemoteManager.Infrastructure` — SSH.NET session factory with host-key pinning, DPAPI + Windows Credential Manager key store, atomic JSON device repository, diagnostics, file logger.
- `src/HHJ.RemoteManager.Desktop` — WPF desktop application (`HHJ-Remote-Manager.exe`).
- `src/HHJ.Agent.Setup.Engine` — Platform-neutral, unit-tested installer logic (public key validation, `sshd_config` parser, firewall reconciler, Tailscale status parser, state & rollback).
- `src/HHJ.Agent.Setup` — WPF UAC-elevated endpoint installer (`HHJ-Agent-Setup.exe`).
- `tests/` — `HHJ.Core.Tests`, `HHJ.Infrastructure.Tests`, `HHJ.Setup.Tests`.
- `docs/` — [architecture.md](docs/architecture.md), [installation.md](docs/installation.md), [networking.md](docs/networking.md), [security.md](docs/security.md), [troubleshooting.md](docs/troubleshooting.md).

## Building & Testing

```powershell
# Build entire solution
.\scripts\build.ps1

# Run all automated tests
.\scripts\test.ps1

# Publish self-contained win-x64 single-file executables
.\scripts\publish.ps1
```
