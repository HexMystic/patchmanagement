# Sample provenance

Every file here is a **real payload captured from the live feed**, recorded so a reader can tell
what is evidence and what is not. Captured **2026-07-28 UTC**.

> **Why this file exists.** The two fixtures that previously sat here (`nvd.sample.json`,
> `kev.sample.json`) were **hand-written**, in the same commit as the parsers they fed — fictional
> vendors (`FooCorp`/`libfoo`), fictional CVE ids, and containing *only* the keys each parser reads.
> A parser asserted against a fixture written to that parser proves self-consistency and nothing
> else. Both were deleted. Do not reintroduce a hand-authored payload here; if a feed cannot be
> captured, the connector stays untested and unticked in `docs/phases/phase-5.md`.

## NVD — `nvd.<CVE>.json`

Whole, unedited responses from `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>`.
One file per request because that is one request's response; no merging, no trimming.

| File | Bytes | Why this CVE |
|---|---|---|
| `nvd.CVE-2024-0182.json` | 3,903 | `cvssMetricV31` lists **Secondary (`cna@vuldb.com`, 7.3 HIGH) BEFORE** NVD's own Primary (`nvd@nist.gov`, 9.8 CRITICAL). The scores cross a severity band, so taking the wrong one is observable in both `CvssBaseScore` and `Severity`. |
| `nvd.CVE-2023-33025.json` | 13,052 | **Secondary only** (`product-security@qualcomm.com`, 9.8) — NVD published no Primary. There is a score, but NVD did not supply it, so `CvssSource` must be null rather than `"nvd"`. |
| `nvd.CVE-2021-44228.json` | 87,091 | Primary listed first (the agreement case), **and** `cvssMetricV2` alongside `cvssMetricV31` (family preference 3.1 → 2.0), **and** an `ssvcV203` family with **no `cvssData` member at all**. |
| `nvd.CVE-2015-5477.json` | 10,907 | **`cvssMetricV2` only** — no 3.x anywhere. Exercises the v2 fallback, `CvssVersion == "2.0"`, and severity read from the metric wrapper rather than from `cvssData`. |

Two facts worth recording, because they justify the selection rather than making it look arbitrary:

- A scan of **300 consecutive real CVEs** (published Jan 2024) found **125** where a Secondary is
  listed first *and* disagrees with NVD's Primary score. Secondary-first is not an edge case; it is
  roughly 40% of the feed.
- `CVE-2024-3094` (xz) was captured first and **rejected as a fixture**: its Secondary and Primary
  carry *byte-identical* vectors and scores, so a test using it would pass whether the parser picked
  the right metric or the wrong one. It is the exact shape of a test that cannot fail.

Also observed while selecting: in this window every CVE with **no** `metrics` at all was a
**Rejected** CVE. No no-metrics fixture is included, because asserting against one would bake in the
claim that a rejected CVE should become an advisory — a separate question, recorded in
`docs/phases/phase-5.md` rather than settled by a fixture.

## EPSS — `epss.sample.json`

387 bytes, the **entire** response, unedited, from
`https://api.first.org/data/v1/epss?cve=CVE-2024-3094,CVE-2021-44228,CVE-2015-5477`.

Note `epss` and `percentile` arrive as JSON **strings** (`"0.859740000"`), not numbers, and are
probabilities in `[0,1]` — not percentages. Both facts are load-bearing and are asserted.

## KEV — `kev.sample.json`

From `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
(`catalogVersion` 2026.07.27, 1,655 entries, 1.5 MB).

**This is the one file that is not a whole response, and the compromise is deliberate.** The live
catalogue is 1.5 MB and changes daily. What was done:

- The envelope (`title`, `catalogVersion`, `dateReleased`, `count`) is **the real one**.
- Two entries are retained **field-for-field as published** — no key added, removed, reordered or
  retyped, and no value altered.
- Everything else in the array was dropped.

Being exact about the one thing that is *not* byte-identical: this file was re-serialized with
two-space indentation, so its **whitespace** differs from the wire response. Every retained record
still compares equal to the live catalogue's when both are parsed — that equality was verified, and
is the claim being made. The NVD and EPSS files below carry no such caveat: they are the raw
response bytes exactly as received.

The two retained records come from the oldest, now-frozen cohort (`dateAdded: 2021-11-03`) so they
will not drift, and between them they cover both branches of the ransomware mapping:

| CVE | Vendor | `knownRansomwareCampaignUse` |
|---|---|---|
| `CVE-2021-40539` | Zoho | `"Known"` |
| `CVE-2020-29583` | Zyxel | `"Unknown"` |

`count` is left at the **real catalogue's 1,655**, not the retained record count. That is
intentional twice over: it documents that the array was truncated, and the parser must not depend on
it. Do not "correct" it to 2.

## Not captured

`wsusscn2.cab` has **no fixture and will not be given a hand-written one.** The cab is ~627 MB, lives
only in the main worktree, is gitignored, and `ExpandCabPackageSource` has never been executed
against it. Supersedence inversion is the highest-consequence logic in the module; a fabricated
`package.xml` would make it look tested while proving nothing.
