namespace PatchManagement.Contracts.Credentials;

/// <summary>
/// A credential resolved into memory for immediate use. Per CLAUDE.md NEVER #1/#2 this
/// is <b>memory-only</b>: its secret material is never logged, serialized, persisted, or
/// returned by any API. Dispose zeroes the secret buffer. <see cref="ToString"/> is redacted.
/// </summary>
public sealed class ResolvedCredential : IDisposable
{
    private readonly byte[] _secret;
    private bool _disposed;

    public ResolvedCredential(CredentialKind kind, byte[] secret, string? username = null)
    {
        Kind = kind;
        Username = username;
        _secret = secret ?? throw new ArgumentNullException(nameof(secret));
    }

    public CredentialKind Kind { get; }

    /// <summary>Login name where applicable (e.g., SSH/Windows user). Not itself a secret.</summary>
    public string? Username { get; }

    /// <summary>
    /// The secret material (SSH private key bytes or password UTF-8). Use in-memory only;
    /// never copy into logs, caches, temp files, or API responses.
    /// </summary>
    public ReadOnlySpan<byte> Secret
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _secret;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Array.Clear(_secret);
        _disposed = true;
    }

    /// <summary>Deliberately redacted so a stray interpolation can never leak the secret.</summary>
    public override string ToString() => $"ResolvedCredential(kind={Kind}, user={Username ?? "<none>"}, secret=<redacted>)";
}
