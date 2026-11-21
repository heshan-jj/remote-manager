namespace HHJ.Agent.Setup.Engine.Abstractions;

public sealed record ProcessRunResult(int ExitCode, string StdOut, string StdErr, bool TimedOut = false);

public interface IProcessRunner
{
    Task<ProcessRunResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

public interface IFileSystem
{
    bool FileExists(string path);
    bool DirectoryExists(string path);
    void CreateDirectory(string path);
    Task<string> ReadAllTextAsync(string path, CancellationToken cancellationToken = default);
    Task WriteAllTextAsync(string path, string content, CancellationToken cancellationToken = default);
    void DeleteFile(string path);
}

public enum RegistryHiveKind { LocalMachine, CurrentUser }

public interface IRegistryReader
{
    string? GetString(RegistryHiveKind hive, string subKey, string valueName);
    int? GetDword(RegistryHiveKind hive, string subKey, string valueName);
    bool ValueExists(RegistryHiveKind hive, string subKey, string valueName);
    void SetString(RegistryHiveKind hive, string subKey, string valueName, string value);
    void DeleteValue(RegistryHiveKind hive, string subKey, string valueName);
}

public sealed record ServiceSnapshot(bool Exists, string? Status, string? StartType);

public interface IServiceManager
{
    ServiceSnapshot GetService(string serviceName);
    Task SetStartTypeAsync(string serviceName, string startType, CancellationToken cancellationToken = default);
    Task StartAsync(string serviceName, CancellationToken cancellationToken = default);
    Task StopAsync(string serviceName, CancellationToken cancellationToken = default);
}

public interface INetworkProbe
{
    bool IsNetworkAvailable();
    Task<bool> CanResolveDnsAsync(string hostName, CancellationToken cancellationToken = default);
    IReadOnlyCollection<int> GetActiveTcpListenerPorts();
    Task<string?> ProbeSshBannerAsync(string host, int port, TimeSpan timeout, CancellationToken cancellationToken = default);
}

public sealed record LocalUserAccount(string Username, bool IsAdministrator, bool IsEnabled);

public interface IPrivilegeChecker
{
    bool IsAdministrator();
    string GetOsArchitecture();
    string GetComputerName();
    string GetCurrentUsername();
    IReadOnlyList<LocalUserAccount> GetLocalUsers();
}

public interface IPackageDownloader
{
    Task DownloadFileAsync(string url, string destinationPath, IProgress<double>? progress, CancellationToken cancellationToken = default);
}

public sealed record SignatureCheckResult(bool IsValid, string? Publisher, string? Error);

public interface IAuthenticodeVerifier
{
    SignatureCheckResult VerifySignedByPublisher(string filePath, string expectedOrganization);
}

public interface IAclManager
{
    void ApplyAdministratorsAuthorizedKeysAcl(string filePath);
    void ApplyUserAuthorizedKeysAcl(string filePath, string username);
    void ApplyAdminOnlyDirectoryAcl(string directoryPath);
}
