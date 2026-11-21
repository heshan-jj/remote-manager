using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using HHJ.Agent.Setup.Engine.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace HHJ.Agent.Setup.Windows;

public sealed class WindowsProcessRunner : IProcessRunner
{
    public async Task<ProcessRunResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var arg in arguments) psi.ArgumentList.Add(arg);

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start '{fileName}'.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
        var stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);

        try
        {
            await proc.WaitForExitAsync(cts.Token);
            return new ProcessRunResult(proc.ExitCode, await stdoutTask, await stderrTask, TimedOut: false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return new ProcessRunResult(-1, "", $"Process '{fileName}' timed out after {timeout.TotalSeconds:0}s.", TimedOut: true);
        }
    }
}

public sealed class PhysicalFileSystem : IFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public bool DirectoryExists(string path) => Directory.Exists(path);
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public Task<string> ReadAllTextAsync(string path, CancellationToken ct = default) => File.ReadAllTextAsync(path, ct);
    public Task WriteAllTextAsync(string path, string content, CancellationToken ct = default) => File.WriteAllTextAsync(path, content, new UTF8Encoding(false), ct);
    public void DeleteFile(string path) => File.Delete(path);
}

public sealed class WindowsRegistryReader : IRegistryReader
{
    private static RegistryKey OpenRoot(RegistryHiveKind hive) => hive switch
    {
        RegistryHiveKind.LocalMachine => Registry.LocalMachine,
        RegistryHiveKind.CurrentUser => Registry.CurrentUser,
        _ => throw new ArgumentOutOfRangeException(nameof(hive)),
    };

    public string? GetString(RegistryHiveKind hive, string subKey, string valueName)
    {
        using var k = OpenRoot(hive).OpenSubKey(subKey, writable: false);
        return k?.GetValue(valueName)?.ToString();
    }

    public int? GetDword(RegistryHiveKind hive, string subKey, string valueName)
    {
        using var k = OpenRoot(hive).OpenSubKey(subKey, writable: false);
        var val = k?.GetValue(valueName);
        return val is int i ? i : null;
    }

    public bool ValueExists(RegistryHiveKind hive, string subKey, string valueName)
    {
        using var k = OpenRoot(hive).OpenSubKey(subKey, writable: false);
        if (k is null) return false;
        if (string.IsNullOrEmpty(valueName)) return true;
        return k.GetValue(valueName) is not null;
    }

    public void SetString(RegistryHiveKind hive, string subKey, string valueName, string value)
    {
        using var k = OpenRoot(hive).CreateSubKey(subKey, writable: true);
        k.SetValue(valueName, value, RegistryValueKind.String);
    }

    public void DeleteValue(RegistryHiveKind hive, string subKey, string valueName)
    {
        using var k = OpenRoot(hive).OpenSubKey(subKey, writable: true);
        k?.DeleteValue(valueName, throwOnMissingValue: false);
    }
}

public sealed class WindowsServiceManager(IProcessRunner process) : IServiceManager
{
    public ServiceSnapshot GetService(string serviceName)
    {
        try
        {
            using var sc = new ServiceController(serviceName);
            var status = sc.Status.ToString();
            var startType = sc.StartType.ToString();
            return new ServiceSnapshot(true, status, startType);
        }
        catch (InvalidOperationException)
        {
            return new ServiceSnapshot(false, null, null);
        }
    }

    public async Task SetStartTypeAsync(string serviceName, string startType, CancellationToken ct = default)
    {
        var scMode = startType.ToLowerInvariant() switch
        {
            "automatic" => "auto",
            "manual" => "demand",
            "disabled" => "disabled",
            _ => throw new ArgumentException($"Unsupported start type '{startType}'.", nameof(startType)),
        };
        var res = await process.RunAsync("sc.exe", ["config", serviceName, $"start={scMode}"], TimeSpan.FromSeconds(15), ct);
        if (res.ExitCode != 0)
            throw new InvalidOperationException($"sc.exe config failed ({res.ExitCode}): {res.StdOut} {res.StdErr}".Trim());
    }

    public Task StartAsync(string serviceName, CancellationToken ct = default) => Task.Run(() =>
    {
        using var sc = new ServiceController(serviceName);
        if (sc.Status != ServiceControllerStatus.Running)
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
        }
    }, ct);

    public Task StopAsync(string serviceName, CancellationToken ct = default) => Task.Run(() =>
    {
        using var sc = new ServiceController(serviceName);
        if (sc.Status != ServiceControllerStatus.Stopped && sc.CanStop)
        {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
        }
    }, ct);
}

public sealed class WindowsNetworkProbe : INetworkProbe
{
    public bool IsNetworkAvailable() => NetworkInterface.GetIsNetworkAvailable();

    public async Task<bool> CanResolveDnsAsync(string hostName, CancellationToken ct = default)
    {
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(hostName, ct);
            return addrs.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyCollection<int> GetActiveTcpListenerPorts() =>
        IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(ep => ep.Port).ToHashSet();

    public async Task<string?> ProbeSshBannerAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            await tcp.ConnectAsync(host, port, cts.Token);
            var buf = new byte[256];
            var n = await tcp.GetStream().ReadAsync(buf, cts.Token);
            return n > 0 ? Encoding.ASCII.GetString(buf, 0, n).Trim() : null;
        }
        catch
        {
            return null;
        }
    }
}

public sealed class WindowsPrivilegeChecker : IPrivilegeChecker
{
    public bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public string GetOsArchitecture() => RuntimeInformation.OSArchitecture.ToString();
    public string GetComputerName() => Environment.MachineName;
    public string GetCurrentUsername() => Environment.UserName;

    public IReadOnlyList<LocalUserAccount> GetLocalUsers()
    {
        var result = new List<LocalUserAccount>();
        try
        {
            using var ctx = new PrincipalContext(ContextType.Machine);
            using var adminGroup = GroupPrincipal.FindByIdentity(ctx, IdentityType.Sid, "S-1-5-32-544");
            var adminSids = adminGroup?.GetMembers(recursive: true)
                .Select(m => m.Sid)
                .Where(s => s is not null)
                .ToHashSet() ?? [];

            using var searcher = new PrincipalSearcher(new UserPrincipal(ctx));
            foreach (var p in searcher.FindAll())
            {
                if (p is not UserPrincipal u) continue;
                if (u.Enabled != true) continue;
                var isAdmin = u.Sid is not null && adminSids.Contains(u.Sid);
                result.Add(new LocalUserAccount(u.SamAccountName, isAdmin, true));
            }
        }
        catch
        {
            result.Add(new LocalUserAccount(Environment.UserName, IsAdministrator(), true));
        }

        return result.OrderByDescending(u => u.IsAdministrator).ThenBy(u => u.Username, StringComparer.OrdinalIgnoreCase).ToList();
    }
}

public sealed class HttpPackageDownloader : IPackageDownloader
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromMinutes(10) };

    public async Task DownloadFileAsync(string url, string destinationPath, IProgress<double>? progress, CancellationToken ct = default)
    {
        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();

        var total = resp.Content.Headers.ContentLength;
        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        var tmp = destinationPath + ".part";
        await using (var dst = File.Create(tmp))
        {
            var buf = new byte[81920];
            long readTotal = 0;
            int read;
            while ((read = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, read), ct);
                readTotal += read;
                if (total is > 0) progress?.Report((double)readTotal / total.Value * 100.0);
            }
        }
        File.Move(tmp, destinationPath, overwrite: true);
        progress?.Report(100.0);
    }
}

public sealed class WinVerifyTrustAuthenticodeVerifier : IAuthenticodeVerifier
{
    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public SignatureCheckResult VerifySignedByPublisher(string filePath, string expectedOrganization)
    {
        if (!File.Exists(filePath))
            return new(false, null, "Downloaded file does not exist.");

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
        };
        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            var trustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2, // WTD_UI_NONE
                fdwRevocationChecks = 1, // WTD_REVOKE_WHOLECHAIN
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = fileInfoPtr,
                dwStateAction = 1, // WTD_STATEACTION_VERIFY
            };

            var action = ActionGenericVerifyV2;
            var hr = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            // Clean up state
            trustData.dwStateAction = 2; // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            if (hr != 0)
                return new(false, null, $"WinVerifyTrust failed with HRESULT 0x{hr:X8}.");
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }

        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            var subject = cert.Subject;
            var match = subject.Contains($"O={expectedOrganization}", StringComparison.OrdinalIgnoreCase) ||
                        subject.Contains($"O=\"{expectedOrganization}\"", StringComparison.OrdinalIgnoreCase);
            return match
                ? new(true, subject, null)
                : new(false, subject, $"Signer '{subject}' does not match expected organization '{expectedOrganization}'.");
        }
        catch (Exception ex)
        {
            return new(false, null, $"Could not inspect signer certificate: {ex.Message}");
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
}

public sealed class WindowsAclManager : IAclManager
{
    public void ApplyAdministratorsAuthorizedKeysAcl(string filePath)
    {
        var fi = new FileInfo(filePath);
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        fi.SetAccessControl(sec);
    }

    public void ApplyUserAuthorizedKeysAcl(string filePath, string username)
    {
        var fi = new FileInfo(filePath);
        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var user = (SecurityIdentifier)new NTAccount(username).Translate(typeof(SecurityIdentifier));
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        sec.SetOwner(user);
        sec.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, AccessControlType.Allow));
        fi.SetAccessControl(sec);
    }

    public void ApplyAdminOnlyDirectoryAcl(string directoryPath)
    {
        var di = new DirectoryInfo(directoryPath);
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        di.SetAccessControl(sec);
    }
}

public sealed class SetupLogSink : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly Lock _gate = new();
    private readonly ConcurrentQueue<string> _lines = new();

    public string LogFilePath { get; }
    public event Action<string>? LineLogged;

    public SetupLogSink(string logDirectory)
    {
        Directory.CreateDirectory(logDirectory);
        LogFilePath = Path.Combine(logDirectory, $"setup-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        _writer = new StreamWriter(new FileStream(LogFilePath, FileMode.Create, FileAccess.Write, FileShare.Read),
            new UTF8Encoding(false))
        {
            AutoFlush = true,
        };
    }

    public ILogger CreateLogger(string categoryName) => new SetupLogger(this, categoryName);

    internal void Write(LogLevel level, string category, string message, Exception? ex)
    {
        var shortCat = category.Contains('.') ? category[(category.LastIndexOf('.') + 1)..] : category;
        var line = string.Create(CultureInfo.InvariantCulture,
            $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} [{level}] {shortCat}: {message}");
        lock (_gate)
        {
            _writer.WriteLine(line);
            if (ex is not null) _writer.WriteLine(ex);
        }
        _lines.Enqueue(line);
        while (_lines.Count > 300 && _lines.TryDequeue(out _)) { }
        LineLogged?.Invoke(line);
    }

    public void Dispose()
    {
        lock (_gate) _writer.Dispose();
    }

    private sealed class SetupLogger(SetupLogSink sink, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel)) sink.Write(logLevel, category, formatter(state, exception), exception);
        }
    }
}
