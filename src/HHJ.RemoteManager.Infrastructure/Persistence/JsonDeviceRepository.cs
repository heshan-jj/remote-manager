using System.Text.Json;
using HHJ.RemoteManager.Core.Devices;
using HHJ.RemoteManager.Core.Security;

namespace HHJ.RemoteManager.Infrastructure.Persistence;

public sealed class JsonDeviceRepository(string filePath) : IDeviceRepository
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<IReadOnlyList<DeviceProfile>> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(filePath)) return [];
            await using var stream = File.OpenRead(filePath);
            return await JsonSerializer.DeserializeAsync<List<DeviceProfile>>(stream, JsonOptions, cancellationToken) ?? [];
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(IEnumerable<DeviceProfile> devices, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(devices);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = filePath + ".tmp";
            await using (var stream = File.Create(tmp))
            {
                await JsonSerializer.SerializeAsync(stream, devices.ToList(), JsonOptions, cancellationToken);
            }
            File.Move(tmp, filePath, overwrite: true);
        }
        finally
        {
            _gate.Release();
        }
    }
}
