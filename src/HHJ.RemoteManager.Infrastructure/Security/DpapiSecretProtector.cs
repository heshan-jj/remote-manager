using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using HHJ.RemoteManager.Core.Security;

namespace HHJ.RemoteManager.Infrastructure.Security;

/// <summary>Encrypts managed SSH private keys at rest using Windows DPAPI (CurrentUser).</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretProtector : ISecretProtector
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("HHJ.RemoteManager.SshKey.v1");

    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] ciphertext) =>
        ProtectedData.Unprotect(ciphertext, Entropy, DataProtectionScope.CurrentUser);
}
