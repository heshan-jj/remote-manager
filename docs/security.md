# Security Architecture

## Authentication & Key Handling

- **Public-Key SSH Only**: `HHJ-Remote-Manager` uses SSH public-key authentication (`ecdsa-sha2-nistp256` generated in-process via .NET `ECDsa` + OS CSPRNG, or an existing OpenSSH key imported by the administrator).
- **At-Rest Protection**: Generated private keys are encrypted with Windows DPAPI (`ProtectedData`, `DataProtectionScope.CurrentUser`). Passphrases for imported external keys are stored in Windows Credential Manager (`CredWriteW` / `CredReadW`), never in plain JSON.
- **Host-Key Pinning**: First-time connections probe the server's SSH host key and display its `SHA256:` fingerprint for explicit administrator approval. Subsequent connections fail with `HostKeyMismatch` if the key changes.
- **No Plaintext Passwords**: Windows passwords are never stored or transmitted by HHJ Remote Manager.

## Endpoint Hardening

- **Firewall Isolation**: `HHJ Remote Manager - OpenSSH (Tailscale only)` restricts inbound SSH to Tailscale peers (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) and the Tailscale interface. Broad pre-existing rules (such as `OpenSSH-Server-In-TCP` with `RemoteAddress = Any`) are flagged and optionally disabled.
- **Authorized Keys ACLs**: Administrator keys are written to `C:\ProgramData\ssh\administrators_authorized_keys` with inheritance disabled and FullControl granted exclusively to `BUILTIN\Administrators` and `SYSTEM`.
- **Signed Installer Verification**: When `HHJ-Agent-Setup.exe` downloads Tailscale, it verifies the Authenticode chain via `WinVerifyTrust` (`WTD_REVOKE_WHOLECHAIN`) and checks that the signer subject contains `O=Tailscale Inc.` before running `msiexec`.
- **No Shell Injection**: Remote commands are never concatenated into `cmd.exe`. All PowerShell scripts are sent via `-EncodedCommand` (UTF-16LE Base64) with strict input validation and single-quote literal escaping (`PowerShellCommand.Literal`).
- **Transparency & Revocation**: No hidden accounts, no UAC bypass, no Defender/Firewall disabling. Access can be revoked at any time via SSH key revocation, Tailscale admin console, or `HHJ-Agent-Setup.exe --disable`.
