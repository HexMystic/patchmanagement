using PatchManagement.Contracts.Discovery;

namespace PatchManagement.Discovery.Correlation;

/// <summary>
/// An evidence source backed by a file of known addresses, one per line.
///
/// <para><b>This is the synthetic source criterion (f) is written against, and it is not a
/// placeholder for a missing feature.</b> The lab has no Active Directory and no DHCP server, so
/// correlation is proven against sources whose contents the test controls — which is what makes
/// "absent from AD" assertable at all. Real LDAP and real lease ingestion are deferred with named
/// owners (D-401, D-402); this seam is what they plug into.</para>
///
/// <para><b>A missing file throws.</b> It does not read as "this source knows nothing", because that
/// would make every host in the estate look unmanaged the first time a path was mistyped — an
/// outage reported as a finding. Same rule as <see cref="IAssetEvidenceSource"/>'s contract: "could
/// not check" is never "absent".</para>
/// </summary>
internal sealed class FileBackedEvidenceSource(string source, string path) : IAssetEvidenceSource
{
    public string Source => source;

    public async Task<EvidenceLookup> LookupAsync(string address, CancellationToken ct)
    {
        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"Evidence source '{source}' cannot be consulted: '{path}' does not exist. Treating "
                + "an unreadable source as an absence would flag the whole estate as unmanaged.");
        }

        var known = await File.ReadAllLinesAsync(path, ct).ConfigureAwait(false);

        foreach (var line in known)
        {
            var entry = line.Trim();
            if (entry.Length == 0 || entry.StartsWith('#'))
            {
                continue;
            }

            // "<address>" or "<address>\t<detail>" — the detail is the source's corroboration, e.g.
            // a lease id or a distinguished name, and is carried into the evidence row.
            var parts = entry.Split('\t', 2);
            if (string.Equals(parts[0].Trim(), address, StringComparison.OrdinalIgnoreCase))
            {
                return new EvidenceLookup(true, parts.Length > 1 ? parts[1].Trim() : null);
            }
        }

        return new EvidenceLookup(false);
    }
}
