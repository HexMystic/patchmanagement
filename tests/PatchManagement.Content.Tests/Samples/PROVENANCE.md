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

## USN — `usn.sample.json`

From `https://usn.ubuntu.com/usn-db/database.json` — the connector's own endpoint. Captured
**2026-07-29 UTC**, when the live file was **339,603,368 bytes** holding **7,678 notices**.

**Truncated, like KEV, and for the same reason.** 339 MB cannot be committed. What was done:

- The root **is** the map, so keeping a subset of keys preserves the document shape exactly — there
  is no envelope or counter to reconcile (KEV needed its real `count` deliberately left wrong).
- Two notice objects are retained **complete and unedited** — no key added, removed, reordered or
  retyped, no value altered. Verified field-identical to the live database at capture time.
- Every other key was dropped. That is the only edit. (Whitespace differs: the file is re-serialized
  with two-space indentation, same caveat as KEV.)

| Notice | Bytes | Why this one |
|---|---|---|
| `8465-1` | ~2.4 KB | **One package (`mina2`) across THREE releases at THREE different versions** — `jammy` 2.1.5-1ubuntu0.1~esm1, `noble` 2.2.1-3ubuntu0.1~esm1, `resolute` 2.2.1-4ubuntu0.1~esm1. The per-release fan-out in its purest form: identical package name, so a test asserting only the row *count* would pass while every version was wrong. Includes **`resolute` = 26.04 LTS**, the label that matters most in production. |
| `4123-1` | ~2.6 KB | `bionic` + `disco` for `node-fstream`, versions differing only in the release suffix (`1.0.10-1ubuntu0.18.04.1` vs `…0.19.04.2`). `disco` was **unmapped** in `DistroReleases`, so this is the fixture that proved the codename gap red-first. |

Both `~esm1` suffixes and the `1ubuntu0.19.04.2` revision are asserted verbatim: `fixed_version` is
stored raw as sourced (ADR 0011) and nothing may parse or canonicalize it.

**Deliberately NOT covered, because real data does not contain it:** a notice with no CVEs. All
7,678 notices in the live database carry at least one, so `SourceMetadataJson == null` is
unreachable from captured data and is left untested rather than fabricated. Likewise, all 29
codenames appearing in the database exist in Ubuntu's published release list, so after the map fix
the `ubuntu:<codename>` fallback is no longer reachable from real data either — it remains for
release series that do not exist yet.

**`USN-4147-1` was considered and rejected**: it is a kernel notice weighing **156 KB** on its own,
more than twenty times the whole committed fixture, and covers nothing the two above do not.

## Not captured

`wsusscn2.cab` has **no fixture and will not be given a hand-written one.** The cab is ~627 MB, lives
only in the main worktree, is gitignored, and `ExpandCabPackageSource` has never been executed
against it. Supersedence inversion is the highest-consequence logic in the module; a fabricated
`package.xml` would make it look tested while proving nothing.
