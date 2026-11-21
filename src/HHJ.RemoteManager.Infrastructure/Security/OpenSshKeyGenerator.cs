using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HHJ.RemoteManager.Infrastructure.Security;

/// <summary>
/// Generates ECDSA P-256 (<c>ecdsa-sha2-nistp256</c>) SSH key pairs using .NET's OS CSPRNG
/// without shelling out to ssh-keygen. Compatible with Windows OpenSSH Server and SSH.NET.
/// </summary>
public static class OpenSshKeyGenerator
{
    public sealed record GeneratedKeyPair(
        string Algorithm,
        string PrivateKeyPem,
        string PublicKeyLine,
        string FingerprintSha256);

    public static GeneratedKeyPair GenerateEcdsaP256(string comment = "hhj-remote-manager")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = ecdsa.ExportECPrivateKeyPem();
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);

        var blob = EncodeEcdsaP256PublicBlob(parameters.Q.X!, parameters.Q.Y!);
        var blobBase64 = Convert.ToBase64String(blob);
        var fp = Convert.ToBase64String(SHA256.HashData(blob)).TrimEnd('=');

        var safeComment = string.IsNullOrWhiteSpace(comment) ? "hhj-remote-manager" : comment.Trim();
        var pubLine = $"ecdsa-sha2-nistp256 {blobBase64} {safeComment}";

        return new GeneratedKeyPair("ecdsa-sha2-nistp256", pem, pubLine, fp);
    }

    /// <summary>Encodes an ECDSA P-256 public key in RFC 5656 SSH wire format.</summary>
    public static byte[] EncodeEcdsaP256PublicBlob(byte[] x, byte[] y)
    {
        if (x.Length != 32 || y.Length != 32)
            throw new ArgumentException("P-256 coordinates must be 32 bytes each.");

        // Uncompressed point format: 0x04 || X || Y (65 bytes)
        var point = new byte[65];
        point[0] = 0x04;
        Buffer.BlockCopy(x, 0, point, 1, 32);
        Buffer.BlockCopy(y, 0, point, 33, 32);

        using var ms = new MemoryStream();
        WriteSshString(ms, "ecdsa-sha2-nistp256"u8);
        WriteSshString(ms, "nistp256"u8);
        WriteSshString(ms, point);
        return ms.ToArray();
    }

    private static void WriteSshString(Stream s, ReadOnlySpan<byte> bytes)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)bytes.Length);
        s.Write(len);
        s.Write(bytes);
    }
}
