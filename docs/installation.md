# Endpoint Installation & Enrollment Guide

## Prerequisites

- **Managed PC**: Windows 10 (Build 17763 / 1809 or newer) or Windows 11, x64, with an Administrator account.
- **Admin Laptop**: Windows 10/11 x64 running `HHJ-Remote-Manager.exe` (and Tailscale signed into the same tailnet).

## Step 1: Generate an SSH Key on the Admin Laptop

1. Launch `HHJ-Remote-Manager.exe`.
2. Go to **Devices & Keys** -> **Generate ECDSA Key** (or **Import Existing Key**).
3. Click **Copy Public Key** on the generated key.

## Step 2: Run `HHJ-Agent-Setup.exe` on the Managed PC

1. Run `HHJ-Agent-Setup.exe` and accept the Windows UAC Administrator prompt.
2. **Stage 0 (Consent)**: Review the summary of changes and check the explicit authorization & consent box.
3. **Stage 1 (Pre-Checks)**: Verify Windows build, x64 architecture, elevation, and network/firewall state.
4. **Stage 2 (OpenSSH)**: Installs `OpenSSH.Server` capability if missing, sets `sshd` to `Automatic`, starts `sshd`, verifies TCP listener + SSH banner, and optionally sets `HKLM\SOFTWARE\OpenSSH\DefaultShell` to PowerShell. Existing `sshd_config` is never overwritten.
5. **Stage 3 (Tailscale)**: Downloads the official Tailscale MSI, verifies its Authenticode signature (`O=Tailscale Inc.`), installs it (with `TS_UNATTENDEDMODE=always` if consented), and guides browser login or one-time auth key enrollment. Confirm the displayed tailnet name before proceeding.
6. **Stage 4 (SSH Authentication)**: Select the authorized Windows account, paste your public key from Step 1, verify the SHA-256 fingerprint, and apply.
   - Admin accounts use `C:\ProgramData\ssh\administrators_authorized_keys` with strict `Administrators` + `SYSTEM` ACLs.
   - Standard accounts use `C:\Users\<user>\.ssh\authorized_keys`.
7. **Stage 5 (Firewall)**: Creates `HHJ Remote Manager - OpenSSH (Tailscale only)` scoped to `100.64.0.0/10`, `fd7a:115c:a1e0::/48`, and the Tailscale interface, and offers to disable broad `Any`-IP OpenSSH rules.

## CLI Options

- `HHJ-Agent-Setup.exe --disable`: Stops `sshd`, restores its original startup type, removes the HHJ firewall rule, revokes HHJ-added authorized keys, and restores `DefaultShell`.
- `HHJ-Agent-Setup.exe --status`: Writes a JSON status summary to `C:\ProgramData\HHJ\AgentSetup\status.json`.
