# `hhj-ssh-setup`

A lightweight, pure-Rust Windows CLI installer (~2 MB) that sets up **Windows OpenSSH Server** (`sshd`) + **Tailscale** + **Tailscale-only Windows Firewall** + your **SSH public key**, then exits—so you can SSH into the target Windows PC with admin privileges from any terminal.

No custom daemon. No GUI bloat. No public IPv4 or router port forwarding required.

## Usage on the Target Windows PC (Run as Administrator)

### Interactive setup (double-click or run with no arguments)
```powershell
.\hhj-ssh-setup.exe
```

### Non-interactive setup
```powershell
.\hhj-ssh-setup.exe install --yes --user <windows-username> --pubkey-file C:\path\to\id_ed25519.pub
```

### Other commands
```powershell
.\hhj-ssh-setup.exe status
.\hhj-ssh-setup.exe revoke
.\hhj-ssh-setup.exe disable
```

## Connecting from Your Computer

Connect from any terminal (Windows Terminal, PowerShell, Linux, macOS):
```bash
ssh <windows-username>@<tailscale-hostname-or-ip>
```
If `<windows-username>` is a Windows Administrator, your SSH session runs with full administrative privileges in PowerShell.

## Building from Source

```bash
cargo test
cargo build --release --target x86_64-pc-windows-gnu
```

## Docs

- [architecture.md](docs/architecture.md)
- [installation.md](docs/installation.md)
- [networking.md](docs/networking.md)
- [security.md](docs/security.md)
- [troubleshooting.md](docs/troubleshooting.md)
