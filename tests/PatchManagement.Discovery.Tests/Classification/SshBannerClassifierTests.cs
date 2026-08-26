using PatchManagement.Contracts.Connectors;
using PatchManagement.Contracts.Discovery;
using PatchManagement.Discovery.Classification;
using PatchManagement.TestSupport;

namespace PatchManagement.Discovery.Tests.Classification;

/// <summary>
/// Criterion (b): classify the OS family before a connector is chosen.
///
/// <para>Every banner here is a <b>real capture</b> from the lab fleet — see
/// <c>Samples/PROVENANCE.md</c>. Hand-authoring one would prove the classifier agrees with whoever
/// wrote the fixture, which is the mistake Phase 5 already had to delete two fixtures for.</para>
/// </summary>
public sealed class SshBannerClassifierTests
{
    private static string Banner(string container) =>
        File.ReadAllText(RepoPaths.Source(
            "tests", "PatchManagement.Discovery.Tests", "Samples", "banners", $"{container}.banner.txt"));

    // -----------------------------------------------------------------------------------
    // The family that names itself
    // -----------------------------------------------------------------------------------

    [Theory]
    [InlineData("ubuntu2204", "ubuntu")]
    [InlineData("ubuntu2404", "ubuntu")]
    [InlineData("debian12", "debian")]
    public void A_banner_that_names_its_distro_is_classified_from_what_it_said(string container, string osId)
    {
        var result = SshBannerClassifier.Classify(Banner(container));

        Assert.Equal(EndpointProtocol.Ssh, result.Protocol);
        Assert.Equal("debian", result.OsFamily);
        Assert.Equal(osId, result.OsId);
        Assert.Equal(ClassificationConfidence.Banner, result.Confidence);
    }

    /// <summary>
    /// The captured banners carry a trailing CRLF because RFC 4253 §4.2 puts one there. A classifier
    /// that only works on pre-trimmed input is not the thing under test — the bytes off the wire are.
    /// </summary>
    [Fact]
    public void The_trailing_crlf_the_protocol_mandates_does_not_defeat_the_parse()
    {
        var raw = Banner("ubuntu2204");

        Assert.EndsWith("\r\n", raw, StringComparison.Ordinal);
        Assert.Equal("ubuntu", SshBannerClassifier.Classify(raw).OsId);
    }

    // -----------------------------------------------------------------------------------
    // The family that does not — the finding these captures exist to record
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// Rocky and Alma emit <c>SSH-2.0-OpenSSH_9.9</c> and nothing else. The classifier must say so
    /// rather than infer <c>rhel</c> from the absence of a vendor suffix: upstream OpenSSH, Alpine
    /// and anything that does not patch its version string look identical, so that inference is
    /// right for this lab and wrong in the field — green either way.
    /// </summary>
    [Theory]
    [InlineData("rocky9")]
    [InlineData("alma9")]
    public void A_banner_that_names_no_distro_is_unknown_rather_than_guessed(string container)
    {
        var result = SshBannerClassifier.Classify(Banner(container));

        Assert.Equal(EndpointProtocol.Ssh, result.Protocol);
        Assert.Equal(EndpointClassification.UnknownFamily, result.OsFamily);
        Assert.Null(result.OsId);
        Assert.NotEqual(ClassificationConfidence.Banner, result.Confidence);
    }

    /// <summary>
    /// The evidence, stated as a test so it cannot quietly stop being true: two different distros
    /// send the same bytes. Any future classifier that claims to tell Rocky from Alma by banner is
    /// contradicted here.
    /// </summary>
    [Fact]
    public void Rocky_and_alma_are_indistinguishable_by_banner()
    {
        Assert.Equal(Banner("rocky9"), Banner("alma9"));

        var rocky = SshBannerClassifier.Classify(Banner("rocky9"));
        var alma = SshBannerClassifier.Classify(Banner("alma9"));

        Assert.Equal(rocky.OsFamily, alma.OsFamily);
        Assert.Equal(rocky.OsId, alma.OsId);
    }

    // -----------------------------------------------------------------------------------
    // Protocol identification, which is what actually selects a connector
    // -----------------------------------------------------------------------------------

    /// <summary>
    /// Every captured banner is recognisably SSH, so the connector choice is settled even when the
    /// distro is not. That split — protocol known, family unknown — is the whole reason the two are
    /// separate properties.
    /// </summary>
    [Theory]
    [InlineData("ubuntu2204")]
    [InlineData("ubuntu2404")]
    [InlineData("debian12")]
    [InlineData("rocky9")]
    [InlineData("alma9")]
    public void Every_captured_banner_selects_the_ssh_connector(string container)
    {
        Assert.Equal(EndpointProtocol.Ssh, SshBannerClassifier.Classify(Banner(container)).Protocol);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("HTTP/1.1 400 Bad Request")]
    [InlineData("* OK IMAP4rev1 Service Ready")]
    public void Text_that_is_not_an_ssh_identification_string_classifies_nothing(string text)
    {
        var result = SshBannerClassifier.Classify(text);

        Assert.Equal(EndpointClassification.UnknownFamily, result.OsFamily);
        Assert.Equal(ClassificationConfidence.None, result.Confidence);
        Assert.Null(result.OsId);
    }

    /// <summary>
    /// The evidence is carried so an operator can see what the classification was read from —
    /// CLAUDE.md §4.6, the same requirement that makes an unmanaged flag explainable.
    /// </summary>
    [Fact]
    public void The_classification_carries_the_text_it_was_read_from()
    {
        var result = SshBannerClassifier.Classify(Banner("debian12"));

        Assert.NotNull(result.Evidence);
        Assert.Contains("OpenSSH_9.2p1", result.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", result.Evidence, StringComparison.Ordinal);
    }
}
