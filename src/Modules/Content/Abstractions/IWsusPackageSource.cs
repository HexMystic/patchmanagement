namespace PatchManagement.Content.Abstractions;

/// <summary>
/// Opens the <c>package.xml</c> offline-sync catalogue that lives INSIDE <c>wsusscn2.cab</c>.
///
/// The split exists because the two halves of wsusscn2 ingestion have very different natures:
/// <list type="bullet">
///   <item>Decompressing the ~627&#160;MB nested CAB (<c>wsusscn2.cab</c> → <c>package.cab</c> →
///   <c>package.xml</c>) is a platform/binary concern — .NET has no built-in cross-platform CAB
///   reader, so the production implementation shells out to <c>expand.exe</c> on Windows.</item>
///   <item>Turning the resulting XML into <c>patches</c> + <c>patch_supersedence</c> is pure,
///   testable normalization owned by <see cref="PatchManagement.Content.Connectors.Wsusscn2Connector"/>.</item>
/// </list>
/// Abstracting the first behind this interface lets the connector's normalization be fully tested
/// against a small sample <c>package.xml</c> without a gigabyte of CAB.
/// </summary>
public interface IWsusPackageSource
{
    /// <summary>Open the extracted <c>package.xml</c> for the cab at <paramref name="cabPath"/>.</summary>
    Task<Stream> OpenPackageXmlAsync(string cabPath, CancellationToken ct);
}
