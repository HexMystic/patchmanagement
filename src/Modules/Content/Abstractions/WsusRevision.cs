using System.Xml.Linq;

namespace PatchManagement.Content.Abstractions;

/// <summary>
/// One revision's detail, gathered from the three blob families a shard carries. Each is a few KB,
/// so they are materialised as elements rather than streamed — unlike the graph, which is not.
/// </summary>
/// <param name="RevisionId">The shard-relative key: the blob's own file name IS this number.</param>
/// <param name="Core">
/// <c>c/&lt;n&gt;</c> — carries <c>Properties/@UpdateType</c>, the real software-vs-category
/// discriminator. <c>package.xml</c>'s <c>IsSoftware</c> is <c>"false"</c> throughout and is not it.
/// </param>
/// <param name="Extended">
/// <c>x/&lt;n&gt;</c> — <c>KBArticleID</c>, <c>MsrcSeverity</c>, and
/// <c>InstallationBehavior/@RebootBehavior</c>. Absent for many revisions.
/// </param>
/// <param name="Localized">
/// <c>l/en/&lt;n&gt;</c> — <c>LocalizedProperties/Title</c>. Absent for many revisions; 37 languages
/// exist and only English is read.
/// </param>
public sealed record WsusRevision(
    long RevisionId,
    XElement Core,
    XElement? Extended,
    XElement? Localized);
