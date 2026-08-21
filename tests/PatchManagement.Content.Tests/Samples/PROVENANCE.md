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

## RHSA — `rhsa.sample.json`

1,448 bytes, one **whole, unedited** response from
`https://access.redhat.com/hydra/rest/securitydata/csaf.json?after=2026-08-19&before=2026-08-20&per_page=3&page=3`
— the connector's own endpoint. Captured **2026-08-21 UTC**, when the unpaginated endpoint returned
**5,658,789 bytes**.

`per_page` and `page` are the API's own paging parameters, so this is a complete response to a
complete request — the same status as the NVD files, not a truncation. No merging, no trimming.

**The root is a JSON ARRAY**, which is the entire defect this fixture exists to pin: the previous
parser asked the root for an `advisories` member, `JsonHelpers.Array` requires an object receiver,
and it was handed `[]` in silence. Empty batch, `status = 'ok'`, cursor advanced.

| Advisory | Why this one |
|---|---|
| `RHSA-2026:57149` | **Epoch 1**, and one package on **four arches at one version** (`ansible-core-1:2.14.18-3.el9_8.1` ×4). Arch is not part of a fix statement, so the four must collapse to one row — a count assertion would pass at 4, 1 or anything between. The package name also contains digits and hyphens, so a parser splitting on the wrong separator mangles it. |
| `RHSA-2026:57148` | Epoch 1 on **`.el10_2`** — a different RHEL major from the advisory above, so a hardcoded platform passes one case and fails the other. |
| `RHSA-2026:57175` | **`java-21-openjdk-portable-main@aarch64`** — a module-stream reference, not a NEVRA. It carries no version at all, so it can state no fix. Proves the skip is deliberate rather than accidental. |

Both NEVRA advisories also ship a `.src` rpm, which is not installable and must not become a fix
statement. Between them the three advisories cover every shape `released_packages` was observed to
take.

**Deliberately NOT covered, because the summary payload does not contain it:** a title, a CVSS
score, and a reboot flag. The endpoint carries none of the three, so `Title` falls back to the
advisory id and the CVSS members stay null rather than being invented. The full CSAF document behind
each `resource_url` has more, and fetching it per advisory is the N+1 design that was rejected.

## MSRC — `msrc.updates.sample.json` and `msrc.sample.json`

Two files because MSRC is **two calls**. Captured **2026-08-21 UTC**.

### `msrc.updates.sample.json` — 48,354 bytes, the **entire** response, unedited

From `https://api.msrc.microsoft.com/cvrf/v3.0/updates`, the connector's own endpoint. **191**
monthly entries, each with an `ID`, both release dates and a `CvrfUrl`.

Kept whole because its size is reasonable and because the selection rule depends on the *whole* set:
`2026-Apr`, `2026-Jul` and `2026-Aug` all carry `CurrentReleaseDate` of `2026-08-20`, so a max over
that field is decided by array order and can return a four-month-old document. `InitialReleaseDate`
is the discriminator, and only the complete index proves the tie exists.

### `msrc.sample.json` — 73,106 bytes, **TRUNCATED**

From `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Aug`, which at capture time was
**6,428,354 bytes** holding **800 vulnerabilities** and **209** `FullProductName` entries.

**6.4 MB cannot be committed.** What was done:

- The envelope — `DocumentTitle`, `DocumentType`, `DocumentPublisher`, `DocumentTracking`,
  `DocumentNotes` — is **the real one**, unedited. `DocumentTracking` matters: it carries the
  `2026-Aug` id the connector uses as its cursor.
- **Four vulnerabilities are retained field-for-field as published** — no key added, removed,
  reordered or retyped, and no value altered.
- `ProductTree.FullProductName` is filtered to the **33** products those four reference, from 209.
  Every `ProductID` appearing in a retained vulnerability still resolves, which is the property the
  parser depends on.
- `ProductTree.Branch` was dropped entirely. The connector never reads it.
- Every other vulnerability was dropped. (Whitespace differs: re-serialized with two-space
  indentation, same caveat as KEV and USN.)

| CVE | Why this one |
|---|---|
| `CVE-2026-50472` | The full Windows shape: **35 remediations**, KBs on **Type 2** with `FixedBuild`, `RestartRequired: Yes` and `Supercedence`. Also the collision case — **two KBs fix Windows Server 2022 at different builds** (`…5499` and `…5440`), which `advisory_affects`'s unique key cannot both hold. |
| `CVE-2026-58650` | Visual Studio Code: Type 2's `Description.Value` is **`"Release Notes"`, not a KB**. A parser trusting that field mints a patch whose `vendor_id` is that label. Also `RestartRequired: Maybe`, the third value. |
| `CVE-2026-65768` | Microsoft Teams for Android: `"Release Notes"` again, with `RestartRequired: No` — the other end of the reboot mapping. |
| `CVE-2026-62896` | **Zero remediations**, and `Critical` severity. 333 of the 800 have no remediation, so this is normal data, not an edge case — an advisory with nothing to install yet. |

**The remediation types are not what the CVRF spec implies, which is why this had to be captured.**
Measured across the live document: **Type 2** carries the KB, `FixedBuild`, `RestartRequired` and
`Supercedence`; **Type 3** has no `Description` member at all; **Type 6** repeats a KB already on
Type 2. A parser written from the spec reads Type 3 as "Vendor Fix", finds nothing, and returns an
empty batch that the sync reports as `ok`.

**`ReleaseDate` is `0001-01-01T00:00:00` with `ReleaseDateSpecified: false`** on every retained
record — a .NET default serialized as a date, not a publication time. Do not "correct" it, and do
not let it become a `DateTimeOffset`: it would sort ahead of everything and read as real.

**Deliberately NOT covered, because the captured month does not contain it:** a vulnerability whose
severity Threat is absent. Every one of the 800 carries a Type-3 Threat, so the `unknown` severity
fallback is unreachable from this data and is left untested rather than fabricated.

## DSA — `dsa.sample.list`

1,135,558 bytes, the **entire** file, unedited, from
`https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list`.
Captured **2026-08-21 UTC**. **6,519 advisories**, 2002-07-30 to 2026-08-20.

Not JSON. This is Debian's line-oriented advisory list, and it is the only source carrying both DSA
identifiers and per-suite fixed versions — see **ADR 0022** (on `main`; this branch predates the
file), which accepts it with its stability risk named.

**Kept whole, which is a departure worth justifying.** At 1.1 MB it is ~15× the largest other
sample. It is kept entire because the edge cases are the point and they are scattered through
twenty-four years of history: truncating to the recent entries would leave a fixture containing only
`trixie`, only suffixed ids, only tab indentation and no annotations — the exact shape of a test that
cannot fail. It is plain text and compresses well.

**Measured across the whole file**, so the parser is written from fact:

| Element | Count | Note |
|---|---|---|
| Advisories | 6,519 | header lines |
| CVE lines | 6,326 | indented `{CVE-… CVE-…}` |
| Suite lines | 8,560 | 8,498 versioned, **62 annotated** |
| Annotations | 62 | `<not-affected>` 55 · `<end-of-life>` 4 · `<unfixed>` 3 |
| NOTE lines | 485 | commentary, no applicability fact |
| Codenames | **12** | woody · sarge · etch · lenny · squeeze · wheezy · jessie · stretch · buster · bullseye · bookworm · trixie |

| Fixture | Why this one |
|---|---|
| `DSA-6455-1` | The top entry, and therefore the cursor. Whole shape: 15 CVEs, one trixie fix at `151.0.7922.169-1~deb13u1`. |
| `DSA-6352-1` | **Two suites, two different versions** for the same package (`bookworm` …`deb12u1`, `trixie` …`deb13u1`). Identical package name on both rows, so a row-COUNT assertion would pass while every version was wrong. |
| `DSA-1105` | **`woody`** (Debian 3.0) — unmapped before this slice, and one of 871 such lines. Also spans `sarge`. |
| `DSA-1209` | **No revision suffix** — plain `DSA-1209`, one of 450 pre-2007 ids. A pattern requiring `-N` drops them all. |
| `DSA-4205-1` | An **announcement**: "jessie end-of-life", no `package - description` split, zero suite lines. One of 217. Also **space-indented**, one of the 260 advisories that are. |
| `DSA-3699-1` | A suite line whose version is **`<end-of-life>`** — an annotation where a version belongs. |
| `DSA-6197-*` | Three revisions (`-1`, `-2`, `-3`) of one DSA number, each its own advisory under the frozen `(source, external_id)` uniqueness. |

**Two facts that determined the parser's shape**, neither guessable from a sample of recent entries:

- **Indentation is mixed** — 14,846 tab-indented lines and **525 space-indented**, across 260
  advisories. A parser anchored on `	` drops them silently.
- **The file is ordered by DATE, not by id.** Revisions are re-inserted at the top, so 179 DSA
  numbers carry several revisions and the id order inverts **181 times**. This is why the cursor is
  the newest *full* id rather than a number or a date.

**Deliberately NOT covered, because the file does not contain it:** a suite codename outside the
twelve. Every one now maps, so the `debian:<codename>` fallback is unreachable from real data — it
remains for the release after `forky`, and `DsaParseTests` asserts no fix statement reaches it.

## wsusscn2 — `wsusscn2/` (a selected slice, not a whole file)

From the real `lab/content/wsusscn2.cab` — **658,155,174 bytes**, fetched Phase 0, gitignored, and
opened for real on **2026-08-21 UTC**. The cab holds `index.xml`, `package.cab` (the ~115 MB update
graph) and **74 detail shards**; a whole-file fixture is out of the question, and the shards are
LZX-compressed binaries besides.

**This is a SELECTED SLICE of real bytes, and the selection is the claim.** Every file here was
extracted verbatim from the cab — no key added, removed, reordered or retyped, no value altered —
but the set is chosen rather than complete:

- `package.xml` holds **20 `<Update>` elements**, copied whole, inside the real root element with its
  real `PackageId`. All 20 have `RevisionId <= 626`, which is shard 2's range, so the slice is
  internally consistent: every revision the graph names is present in the blobs beside it.
- `c/<n>`, `x/<n>` and `l/en/<n>` are the matching blobs for those revisions — **20, 20 and 12**
  respectively. Twelve, not twenty, because eight of these revisions genuinely have no English title.

The blobs are XML **fragments** — several sibling top-level elements with no single root — which is
why both the fake source and the real one wrap them before parsing. That is a property of the
format, not an edit to the files.

| Fixture | Why this one |
|---|---|
| rev **1** | `UpdateType=Software`, a KB (`5087058`), `MsrcSeverity=Critical`, an English title, and a `SupersededBy` pointing at revision **222 — deliberately NOT in the slice**, so a dangling edge must produce nothing |
| rev **2** | Software with **no KB and no title**: the vendor id falls back to `UpdateId`. Carries `RebootBehavior=CanRequestReboot` |
| rev **3** | `UpdateType=Detectoid` — an applicability probe, not installable, must be dropped |
| rev **5** | `UpdateType=Category` — taxonomy, must be dropped |
| rev **21** + **616** | A real supersedence pair with **both ends present**: KB5094126 (June) superseded by KB5101650 (July). The one case that proves the inversion |
| rev **33** + **616** | **One KB, two updates.** Both are KB5101650 with *different* `UpdateId`s — Microsoft ships a KB across product families. They must collapse to one patch, because `patches` is unique on (source, vendor_id) |

**Measured across the whole cab**, so the parser was written from fact: 137,091 updates in the graph;
in shard 2, `UpdateType` splits 523 Software / 93 Detectoid / 10 Category, `KBArticleID` appears in
256 of 626 `x/` blobs, `MsrcSeverity` in 251 and `RebootBehavior` in 267; `l/` carries 37 languages.

**Deliberately NOT covered, because the catalogue does not contain it:** `Uninstallable`. Zero
occurrences across every `c/` and `x/` blob in the shard, so `reversible` cannot be sourced and stays
`false` as a stated limit rather than a fabricated value.

## Not captured

*(Superseded 2026-08-21 — wsusscn2 now has a captured slice; see the section above. The paragraph
below is kept because its reasoning is why the fixture is a real slice rather than a fabrication.)*

`wsusscn2.cab` has **no fixture and will not be given a hand-written one.** The cab is ~627 MB, lives
only in the main worktree, is gitignored, and `ExpandCabPackageSource` has never *successfully* run
against it — the cab WAS opened on 2026-08-16 and the extractor found to be broken (phase-5.md,
D-504), which is a stronger reason for this entry, not a weaker one. Supersedence inversion is
the highest-consequence logic in the module; a fabricated
`package.xml` would make it look tested while proving nothing.
