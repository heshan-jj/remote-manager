# `hhj-ssh-setup`

A fast, zero-bloat Rust Windows installer that sets up **Windows OpenSSH Server** (`sshd`) + an auto-reconnecting **VPS reverse-tunnel Windows service** (`hhj-tunnel`) in seconds—no Tailscale, no GUI, no inbound firewall ports on the target PC.

## 1. One-Time VPS Setup (30 seconds)

```bash
sudo adduser --disabled-password --gecos "" --shell /usr/sbin/nologin hhj-tunnel
sudo mkdir -p /home/hhj-tunnel/.ssh
sudo touch /home/hhj-tunnel/.ssh/authorized_keys
sudo chmod 700 /home/hhj-tunnel/.ssh && sudo chmod 600 /home/hhj-tunnel/.ssh/authorized_keys
sudo chown -R hhj-tunnel:hhj-tunnel /home/hhj-tunnel/.ssh

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
sudo sshd -t && sudo systemctl reload ssh
```
Generate one shared tunnel keypair once (`ssh-keygen -t ed25519 -N "" -f hhj_tunnel_key`) and add its `.pub` line to `/home/hhj-tunnel/.ssh/authorized_keys` prefixed with `restrict,port-forwarding `.

## 2. On the Target Windows PC (~3 seconds, Run as Administrator)

```powershell
.\hhj-ssh-setup.exe install --yes `
  --vps-host YOUR_VPS_IP `
  --tunnel-key .\hhj_tunnel_key `
  --user YOUR_WINDOWS_USER `
  --pubkey-file .\your_admin_key.pub
```
*(Or run `.\hhj-ssh-setup.exe` with no arguments for interactive prompts.)*

Other commands:
```powershell
.\hhj-ssh-setup.exe status
.\hhj-ssh-setup.exe revoke
.\hhj-ssh-setup.exe disable
```

## 3. Connect from Your Laptop

```bash
ssh -J YOUR_VPS_USER@YOUR_VPS_IP YOUR_WINDOWS_USER@127.0.0.1 -p 2222
```
Or add to `~/.ssh/config`:
```sshconfig
Host target-pc
    HostName 127.0.0.1
    Port 2222
    User YOUR_WINDOWS_USER
    ProxyJump YOUR_VPS_USER@YOUR_VPS_IP
```
Then simply run `ssh target-pc`.
