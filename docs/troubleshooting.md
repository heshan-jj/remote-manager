# Troubleshooting Guide

## Common Connection States

| State | Meaning | What to Check |
|---|---|---|
| `VpnUnreachable` | Hostname did not resolve or TCP timed out | Ensure Tailscale is running on both machines; check `tailscale status` and MagicDNS. |
| `SshUnavailable` | Endpoint is reachable on Tailscale, but TCP port 22 refused the connection | On the managed PC, verify `sshd` service is `Running` and the HHJ firewall rule is enabled. |
| `AuthenticationFailed` | SSH server rejected the key/account | Verify the Windows username matches the account whose `authorized_keys` (or `administrators_authorized_keys` for admins) contains the matching public key, and check file ACLs. |
| `HostKeyUntrusted` / `HostKeyMismatch` | Host key not yet pinned or changed | Verify the `SHA256:` fingerprint with the managed PC before approving/updating the pinned key. |
| `PermissionDenied` | Authenticated, but Windows denied the action | Certain actions (stopping services, flushing DNS, rebooting) require an Administrator account. |

## Logs & Diagnostics

- **Desktop App Logs**: `%LOCALAPPDATA%\HHJ\RemoteManager\logs\` (also viewable live in the **Logs** tab).
- **Endpoint Installer Logs**: `C:\ProgramData\HHJ\AgentSetup\logs\`.
- **Endpoint State**: `C:\ProgramData\HHJ\AgentSetup\state.json` (or run `HHJ-Agent-Setup.exe --status`).
- **In-App Diagnostics**: Select a device on the **Devices & Keys** tab and click **Test / Diagnostics** to test local Tailscale, DNS/MagicDNS, TCP reachability, SSH banner, and host-key match.
