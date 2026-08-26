using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Discovery;

namespace PatchManagement.Discovery.Classification;

/// <summary>
/// Classifies an endpoint from the SSH identification string it sends on connect — criterion (b),
/// the step that picks a connector before anything logs in.
///
/// <para>Usable at all because RFC 4253 §4.2 has the server send its identification string
/// <b>unsolicited, before key exchange</b>. No credential, no session, no negotiation: the endpoint
/// volunteers this to anyone who opens a socket.</para>
///
/// <para><b>What it will not do is guess.</b> Debian and Ubuntu patch the version string and name
/// themselves; Rocky and AlmaLinux emit a bare <c>SSH-2.0-OpenSSH_9.9</c> — byte-identical to each
/// other, and carrying no distro, no family, nothing. The tempting rule is "no vendor suffix ⇒ Red
/// Hat family", because on this fleet that is true. It is not true anywhere else: upstream OpenSSH,
/// Alpine, and everything that ships the version string unpatched look exactly the same, so that
/// inference is right for the lab and wrong in the field — with a green suite either way. An
/// unrecognised banner is therefore <c>unknown</c>, and establishing the distro is inventory's job,
/// because it needs <c>/etc/os-release</c> and therefore a login.</para>
///
/// <para>See <c>tests/PatchManagement.Discovery.Tests/Samples/PROVENANCE.md</c> — the captures that
/// establish this, including both identical RHEL-family banners kept side by side so the point
/// cannot be mistaken for one unrecognised value.</para>
/// </summary>
internal static class SshBannerClassifier
{
    private const string SshPrefix = "SSH-";

    public static EndpointClassification Classify(string? banner)
    {
        var text = banner?.Trim();

        if (string.IsNullOrEmpty(text) || !text.StartsWith(SshPrefix, StringComparison.Ordinal))
        {
            return new EndpointClassification
            {
                Protocol = EndpointProtocol.Ssh,
                OsFamily = EndpointClassification.UnknownFamily,
                Confidence = ClassificationConfidence.None,
            };
        }

        if (text.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase))
        {
            return Debian("ubuntu");
        }

        if (text.Contains("Debian", StringComparison.OrdinalIgnoreCase))
        {
            return Debian("debian");
        }

        // It is SSH — which settles the connector — but the banner named no distro. Reporting the
        // family as unknown is the whole point; see the class remarks.
        return new EndpointClassification
        {
            Protocol = EndpointProtocol.Ssh,
            OsFamily = EndpointClassification.UnknownFamily,
            Confidence = ClassificationConfidence.Port,
            Evidence = text,
        };

        EndpointClassification Debian(string osId) => new()
        {
            Protocol = EndpointProtocol.Ssh,
            OsFamily = "debian",
            OsId = osId,
            Confidence = ClassificationConfidence.Banner,
            Evidence = text,
        };
    }
}
