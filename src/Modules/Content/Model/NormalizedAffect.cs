namespace PatchManagement.Content.Model;

/// <summary>
/// One fix statement, normalized for <c>advisory_affects</c>: "package <see cref="PackageName"/>
/// is fixed at <see cref="FixedVersion"/> on release <see cref="Platform"/>".
///
/// <see cref="Platform"/> and <see cref="FixedVersion"/> are carried RAW AS SOURCED — never parsed,
/// split, or canonicalized (ADR 0011). The Phase 6 comparator owns interpretation. <see cref="Platform"/>
/// is NULL when the source states no release scope; it is part of the row identity, so two NULL
/// platforms collide under <c>NULLS NOT DISTINCT</c> rather than duplicating.
/// </summary>
public sealed record NormalizedAffect(
    string PackageName,
    string Ecosystem,
    string? Platform,
    string? FixedVersion,
    bool Backported);
