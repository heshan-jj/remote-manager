using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using HHJ.RemoteManager.Core.Connections;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Core.Ssh;

namespace HHJ.RemoteManager.Infrastructure.Diagnostics;

public enum DiagnosticStatus { Pass, Warn, Fail, Info }

public sealed record DiagnosticStep(string Name, DiagnosticStatus Status, string Summary, string? Detail = null);

public sealed record DiagnosticsReport(
    DeviceProfile Device,
    DateTimeOffset CompletedUtc,
    IReadOnlyList<DiagnosticStep> Steps);

/// <summary>
/// Runs non-destructive connectivity checks against a managed endpoint (DNS, TCP reachability,
/// SSH banner, host-key match, local Tailscale status) to help distinguish VPN vs SSH vs auth issues.
/// </summary>
public sealed class ConnectionDiagnosticsService(ISshSessionFactory sshFactory)
{
    public async Task<DiagnosticsReport> RunAsync(DeviceProfile device, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(device);
        var steps = new List<DiagnosticStep>
        {
            await CheckLocalTailscaleAsync(ct),
        };

        IPAddress[] addresses = [];
        var dnsSw = Stopwatch.StartNew();
        try
        {
            if (IPAddress.TryParse(device.Address, out var literal))
            {
                addresses = [literal];
                steps.Add(new DiagnosticStep("Address Resolution", DiagnosticStatus.Pass,
                    $"Using literal IP {literal}", null));
            }
            else
            {
                addresses = await Dns.GetHostAddressesAsync(device.Address, ct);
                dnsSw.Stop();
                var ipList = string.Join(", ", addresses.Select(a => a.ToString()));
                steps.Add(addresses.Length > 0
                    ? new DiagnosticStep("DNS / MagicDNS Resolution", DiagnosticStatus.Pass,
                        $"Resolved {device.Address} in {dnsSw.ElapsedMilliseconds} ms", ipList)
                    : new DiagnosticStep("DNS / MagicDNS Resolution", DiagnosticStatus.Fail,
                        $"No addresses returned for {device.Address}"));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            steps.Add(new DiagnosticStep("DNS / MagicDNS Resolution", DiagnosticStatus.Fail,
                $"Could not resolve '{device.Address}' — check MagicDNS and Tailscale.", ex.Message));
        }

        if (addresses.Length > 0)
        {
            var tcpSw = Stopwatch.StartNew();
            try
            {
                using var tcp = new TcpClient();
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(8));
                await tcp.ConnectAsync(device.Address, device.Port, timeoutCts.Token);
                tcpSw.Stop();

                var banner = await ReadSshBannerAsync(tcp.GetStream(), timeoutCts.Token);
                steps.Add(new DiagnosticStep("TCP & SSH Banner",
                    banner.StartsWith("SSH-", StringComparison.Ordinal) ? DiagnosticStatus.Pass : DiagnosticStatus.Warn,
                    $"Connected to {device.Address}:{device.Port} in {tcpSw.ElapsedMilliseconds} ms",
                    string.IsNullOrWhiteSpace(banner) ? "No SSH banner received." : banner));

                try
                {
                    var hostKey = await sshFactory.ProbeHostKeyAsync(device.Address, device.Port, TimeSpan.FromSeconds(8), ct);
                    if (device.HostKey is null)
                    {
                        steps.Add(new DiagnosticStep("SSH Host Key", DiagnosticStatus.Warn,
                            "Host key is not yet pinned for this device.", hostKey.Display));
                    }
                    else if (string.Equals(device.HostKey.FingerprintSha256, hostKey.FingerprintSha256, StringComparison.Ordinal) &&
                             string.Equals(device.HostKey.Algorithm, hostKey.Algorithm, StringComparison.OrdinalIgnoreCase))
                    {
                        steps.Add(new DiagnosticStep("SSH Host Key", DiagnosticStatus.Pass,
                            "Presented host key matches the pinned fingerprint.", hostKey.Display));
                    }
                    else
                    {
                        steps.Add(new DiagnosticStep("SSH Host Key", DiagnosticStatus.Fail,
                            "Presented host key DOES NOT match the pinned fingerprint!",
                            $"Pinned: {device.HostKey.Display}\nPresented: {hostKey.Display}"));
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    steps.Add(new DiagnosticStep("SSH Host Key", DiagnosticStatus.Fail,
                        "Failed to negotiate SSH host key.", ex.Message));
                }
            }
            catch (SocketException sock)
            {
                var summary = sock.SocketErrorCode == SocketError.ConnectionRefused
                    ? $"Port {device.Port} refused the connection (host is reachable, but sshd or firewall blocked it)."
                    : $"Could not reach {device.Address}:{device.Port} ({sock.SocketErrorCode}).";
                steps.Add(new DiagnosticStep("TCP & SSH Banner", DiagnosticStatus.Fail, summary, sock.Message));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                steps.Add(new DiagnosticStep("TCP & SSH Banner", DiagnosticStatus.Fail,
                    $"Timed out connecting to {device.Address}:{device.Port} (device offline or VPN blocked)."));
            }
        }

        return new DiagnosticsReport(device, DateTimeOffset.UtcNow, steps);
    }

    private static async Task<string> ReadSshBannerAsync(NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[256];
        var read = await stream.ReadAsync(buf, ct);
        return read <= 0 ? "" : Encoding.ASCII.GetString(buf, 0, read).Trim();
    }

    private static async Task<DiagnosticStep> CheckLocalTailscaleAsync(CancellationToken ct)
    {
        var candidates = new[]
        {
            @"C:\Program Files\Tailscale\tailscale.exe",
            "tailscale",
        };
        var exe = candidates.FirstOrDefault(p => p == "tailscale" || File.Exists(p));
        if (exe is null)
        {
            return new DiagnosticStep("Local Tailscale", DiagnosticStatus.Info, "Tailscale CLI not found.");
        }

        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("status");
            psi.ArgumentList.Add("--json");

            using var proc = Process.Start(psi);
            if (proc is null)
                return new DiagnosticStep("Local Tailscale", DiagnosticStatus.Info, "Could not launch tailscale status.");

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            var json = await proc.StandardOutput.ReadToEndAsync(timeout.Token);
            await proc.WaitForExitAsync(timeout.Token);
            if (proc.ExitCode != 0 || string.IsNullOrWhiteSpace(json))
                return new DiagnosticStep("Local Tailscale", DiagnosticStatus.Warn, "Tailscale CLI returned an error.");

            using var doc = JsonDocument.Parse(json);
            var state = doc.RootElement.TryGetProperty("BackendState", out var bs) ? bs.GetString() : "Unknown";
            var selfDns = doc.RootElement.TryGetProperty("Self", out var self) && self.TryGetProperty("DNSName", out var d)
                ? d.GetString()?.TrimEnd('.')
                : null;
            var status = string.Equals(state, "Running", StringComparison.OrdinalIgnoreCase)
                ? DiagnosticStatus.Pass
                : DiagnosticStatus.Warn;
            return new DiagnosticStep("Local Tailscale", status, $"BackendState: {state}", selfDns);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new DiagnosticStep("Local Tailscale", DiagnosticStatus.Info,
                "Tailscale CLI is not installed on this computer (another VPN or direct route may be in use).", ex.Message);
        }
    }
}
