# 8. Windows patch content source strategy (wsusscn2.cab + MSRC CSAF)

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
Windows assessment needs authoritative "which updates are missing" data. Two sources
exist: Microsoft's **`wsusscn2.cab`** (the offline scan catalog consumed via the
Windows Update Agent API) and the **MSRC CSAF/CVRF API** (machine-readable security
advisories). Each answers a different question. Full analysis in
`docs/HARD-PROBLEMS.md`.

## Decision
Use **both, for different jobs**:
- **`wsusscn2.cab` as the applicability engine** — it authoritatively determines
  *which updates apply to a given machine* (supersedence, bundles, product
  applicability) via WUA. This is our source of truth for "missing on this host".
- **MSRC CSAF as the CVE overlay** — maps updates/KBs ⇄ CVEs, severities, and
  exploitability so findings are vulnerability-centric and explainable.

Phase 0 only **downloads** the cab (into `/lab/content/`, gitignored) and reports its
size. **No parsing** until Phase 5.

## Consequences
- Accurate applicability (cab) + rich CVE context (CSAF); neither alone suffices.
- The cab is large (~1 GB) and periodic; ingestion must be incremental (Phase 5).

## Rejected
- **Cab only** — weak CVE mapping; hard to make findings explainable.
- **CSAF only** — no per-host applicability/supersedence; can't say "missing here".
