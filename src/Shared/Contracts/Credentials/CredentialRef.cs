namespace PatchManagement.Contracts.Credentials;

/// <summary>
/// An opaque reference to a stored credential — an id plus optional scope. It is NOT the
/// secret; callers pass this to <see cref="ICredentialProvider"/> to resolve the real
/// material at the moment of use. Safe to log.
/// </summary>
public readonly record struct CredentialRef(Guid Id, string? Scope = null)
{
    public override string ToString() => Scope is null ? $"cred:{Id}" : $"cred:{Id}({Scope})";
}

/// <summary>The kind of secret a credential carries.</summary>
public enum CredentialKind
{
    SshKey,
    WindowsPassword,
}
