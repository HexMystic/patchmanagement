namespace PatchManagement.Contracts.Discovery;

/// <summary>A host that answered on at least one probed port.</summary>
public sealed record DiscoveredHost
{
    public required string Address { get; init; }

    /// <summary>Ports that completed a TCP connection, ascending.</summary>
    public required IReadOnlyList<int> OpenPorts { get; init; }

    /// <summary>Fastest observed connect latency across the open ports.</summary>
    public required TimeSpan Latency { get; init; }
}

/// <summary>
/// A requested range that was not swept, and why — named rather than dropped. Carries no secret
/// and no remote output; the reason is a fixed, caller-safe string.
/// </summary>
public sealed record RefusedRange(string Range, string Reason);

/// <summary>
/// The result of a sweep. Modelled so that "refused" can never be mistaken for "found nothing":
/// <see cref="Hosts"/> is empty in both cases, so <see cref="Outcome"/> is the load-bearing field
/// and <see cref="Succeeded"/> is the only honest way to read it.
/// </summary>
public sealed record SweepResult
{
    public required SweepOutcome Outcome { get; init; }

    public required IReadOnlyList<DiscoveredHost> Hosts { get; init; }

    /// <summary>Ranges refused by policy or rejected as uninterpretable. Empty on success.</summary>
    public IReadOnlyList<RefusedRange> Refused { get; init; } = [];

    /// <summary>Addresses actually probed. Zero whenever the sweep was refused.</summary>
    public int AddressesProbed { get; init; }

    public bool Succeeded => Outcome == SweepOutcome.Ok;

    public static SweepResult Swept(IReadOnlyList<DiscoveredHost> hosts, int addressesProbed) =>
        new() { Outcome = SweepOutcome.Ok, Hosts = hosts, AddressesProbed = addressesProbed };

    public static SweepResult Refuse(SweepOutcome outcome, IReadOnlyList<RefusedRange> refused) =>
        new() { Outcome = outcome, Hosts = [], Refused = refused, AddressesProbed = 0 };
}
