# `hhj-ssh-setup`

A lightweight, pure-Rust Windows installer (~730 KB) that configures **Windows OpenSSH Server** (`sshd`) + an auto-reconnecting **VPS reverse-tunnel Windows service** (`hhj-tunnel`) in seconds—no Tailscale, no GUI, and no inbound firewall ports needed on the target PC.

---

## 1. One-Time VPS Setup (Ubuntu/Debian)

Run once on your VPS as `root` (or with `sudo`):

```bash
# 1. Create restricted tunnel-only user (no shell access)
sudo adduser --disabled-password --gecos "" --shell /usr/sbin/nologin hhj-tunnel 2>/dev/null || true
sudo mkdir -p /home/hhj-tunnel/.ssh

# 2. Configure sshd for reverse-tunnel only & fast reconnects
sudo tee /etc/ssh/sshd_config.d/99-hhj-tunnel.conf >/dev/null <<'EOF'
Match User hhj-tunnel
    AllowTcpForwarding remote
    GatewayPorts no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
    ClientAliveInterval 30
    ClientAliveCountMax 3
EOF

sudo sshd -t && (sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd)

# 3. Generate one shared tunnel key & authorize it (port-forwarding only)
sudo ssh-keygen -t ed25519 -N "" -C "hhj-tunnel" -f /root/hhj_tunnel_key
echo "restrict,port-forwarding $(cat /root/hhj_tunnel_key.pub)" | sudo tee /home/hhj-tunnel/.ssh/authorized_keys >/dev/null
sudo chmod 700 /home/hhj-tunnel/.ssh
sudo chmod 600 /home/hhj-tunnel/.ssh/authorized_keys
sudo chown -R hhj-tunnel:hhj-tunnel /home/hhj-tunnel/.ssh
```

> **Firewall note**: Only port `22` needs to be open on your VPS. Keep `2222`+ closed to the public internet—tunnels bind strictly to `127.0.0.1` on the VPS.

---

## 2. One-Shot Target Windows PC Setup (~3 seconds)

Run in **PowerShell as Administrator** on each Windows PC you want to manage (increment `$Port` for each machine: `2222` for PC1, `2223` for PC2, etc.):

```powershell
$VpsHost = "YOUR_VPS_IP"
$Port    = 2222   # 2222 for PC1, 2223 for PC2, 2224 for PC3, etc.

$WorkDir = Join-Path $env:TEMP "hhj-setup"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

Invoke-WebRequest "https://github.com/heshan-jj/remote-manager/releases/latest/download/hhj-ssh-setup.exe" -OutFile "$WorkDir\hhj-ssh-setup.exe"
scp "root@${VpsHost}:/root/hhj_tunnel_key" "$WorkDir\hhj_tunnel_key"
& "$WorkDir\hhj-ssh-setup.exe" install --yes --vps-host $VpsHost --tunnel-key "$WorkDir\hhj_tunnel_key" --remote-port $Port

Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
```

*(Optional: pass `--pubkey-file path\to\admin.pub` to `hhj-ssh-setup.exe` if you prefer key-based auth instead of Windows password auth.)*

---

## 3. Connect from Your Laptop

```bash
ssh -J root@YOUR_VPS_IP WINDOWS_USER@127.0.0.1 -p 2222
```

Or save aliases in `~/.ssh/config`:
```sshconfig
Host pc1
    HostName 127.0.0.1
    Port 2222
    User WINDOWS_USER
    ProxyJump root@YOUR_VPS_IP

Host pc2
    HostName 127.0.0.1
    Port 2223
    User WINDOWS_USER
    ProxyJump root@YOUR_VPS_IP
```
Then connect with `ssh pc1` or `ssh pc2`.

---

## 4. Status & Uninstall

Check status on the Windows PC:
```powershell
C:\ProgramData\HHJ\SshSetup\hhj-ssh-setup.exe status
```

Full uninstall on the Windows PC (PowerShell **as Administrator**):
```powershell
C:\ProgramData\HHJ\SshSetup\hhj-ssh-setup.exe disable
Remove-Item -Recurse -Force C:\ProgramData\HHJ -ErrorAction SilentlyContinue
```

---

## Building from Source

```bash
cargo test
cargo build --release --target x86_64-pc-windows-gnu
```
