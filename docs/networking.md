# Networking & Cross-Country Connectivity

HHJ Remote Manager is designed to operate across different countries, ISPs, and carrier-grade NAT (CGNAT) without requiring a public IPv4 address, Dynamic DNS, or manual router port forwarding.

## How Connectivity Works

1. Both the administrator's laptop (e.g. Singapore) and the managed PC (e.g. Sri Lanka) join the same **Tailscale** tailnet.
2. Tailscale establishes an encrypted WireGuard tunnel—using direct UDP NAT traversal when possible, or Tailscale's DERP relay fallback when behind strict CGNAT or symmetric NAT.
3. `HHJ-Agent-Setup.exe` configures Windows Defender Firewall so that inbound TCP on the OpenSSH port (default `22`) is permitted **only** from Tailscale IPv4 (`100.64.0.0/10`) and IPv6 (`fd7a:115c:a1e0::/48`) ranges and the Tailscale network adapter.
4. `HHJ-Remote-Manager.exe` connects via SSH to the endpoint's MagicDNS hostname (e.g. `brother-pc.tailnet-name.ts.net`) or private Tailscale IP (`100.x.y.z`).

## Unattended Operation

When the administrator checks **Enable unattended Windows mode** during Tailscale enrollment, Tailscale runs as a Windows service (`TS_UNATTENDEDMODE=always` / `tailscale up --unattended`). The managed PC remains reachable after normal Windows restarts as long as it is powered on, connected to the internet, and its Tailscale node key has not expired.
