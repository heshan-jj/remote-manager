# `hhj-ssh-setup` (Rust CLI)

A minimal, no-GUI Windows service installer that sets up **Windows OpenSSH Server** (`sshd`) + **Tailscale** + **Tailscale-only Windows Firewall** + your **SSH public key**, then exits—so you can SSH into the target Windows PC with admin privileges from any terminal.

## Usage on the Target Windows PC (Run as Administrator)

### Interactive setup (double-click or run with no arguments)
```powershell
.\hhj-ssh-setup.exe
```

### Non-interactive / scripted setup
```powershell
.\hhj-ssh-setup.exe install --yes --user heshan --pubkey-file C:\path\to\id_ed25519.pub
```

### Check status
```powershell
.\hhj-ssh-setup.exe status
```

### Revoke HHJ-managed SSH keys
```powershell
.\hhj-ssh-setup.exe revoke
```

### Disable & roll back all HHJ changes
```powershell
.\hhj-ssh-setup.exe disable
```

## Connecting from Your Laptop

Once setup finishes, connect from any terminal (Windows Terminal, PowerShell, Linux, macOS):
```bash
ssh <windows-username>@<tailscale-hostname-or-ip>
```
If `<windows-username>` is a Windows Administrator, your SSH session runs with full administrative privileges in PowerShell.

## Building from Source

```bash
cargo test
cargo build --release --target x86_64-pc-windows-gnu
```
