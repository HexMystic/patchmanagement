using System.Security.Cryptography;
using System.Text;

namespace PatchManagement.Connectors.IntegrationTests;

/// <summary>
/// A valid SSH private key the lab fleet has never authorised.
///
/// <para>It must be genuinely well-formed: a corrupted key would fail to PARSE and surface as
/// ProtocolError, which would let the auth-failure test pass while proving something entirely
/// different. The point is a key the server understands and rejects, not one the client cannot
/// read.</para>
///
/// <para>RSA in PKCS#8 PEM rather than ed25519 because .NET can emit it directly, with no shelling
/// out to ssh-keygen and no dependency on what happens to be installed on the machine.</para>
/// </summary>
internal sealed class SshKeyScratch : IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);

    public byte[] PrivateKeyBytes => Encoding.UTF8.GetBytes(_rsa.ExportPkcs8PrivateKeyPem());

    public void Dispose() => _rsa.Dispose();
}
