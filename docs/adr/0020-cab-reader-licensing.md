# 20. The managed CAB reader is vendored WiX DTF source under MS-RL, not a paid binary dependency

- **Status:** Accepted
- **Date:** 2026-08-20
- **Relates to:** [ADR 0005](0005-cqrs-mediator.md) (the same rejection, for MediatR/AutoMapper),
  [ADR 0008](0008-windows-content-source.md) (wsusscn2 is the Windows applicability source),
  **D-504** (the wsusscn2 rewrite), CLAUDE.md §1 (this product is sold)
- **Applies to:** `third_party/wix-dtf/`
- **Unblocks:** D-504. Does **not** implement it — nothing consumes this code yet.

## Context

`wsusscn2.cab` is a 658 MB multi-file cabinet containing `index.xml` plus `package.cab` and
`package2..75.cab`. ADR 0008 makes it the source of truth for "what is missing on this Windows
host", so reading it is not optional.

The current extractor, `ExpandCabPackageSource`, shells out to Windows `expand.exe`. The 2026-08-20
wsusscn2 audit established that it **cannot run at all** — it passes a file path as the destination
for a multi-file cab, which `expand.exe` refuses with *"Destination directory required for a
multi-file CAB"* (exit 2) — and that it reads 1 cab of 75 even in principle. D-504 owns the rewrite.

Shelling out is also the wrong shape independently of that bug: it is Windows-only, it expands
gigabytes to disk to read a fraction of them, and it makes a subprocess exit code load-bearing in a
codebase whose NEVER #3 exists precisely because exit codes are not evidence. A **managed** cabinet
reader with random access is what the rewrite wants, and the mature managed implementation on .NET
is **WiX DTF** (`WixToolset.Dtf.Compression.Cab`) — a wrapper over the FCI/FDI cabinet APIs, already
named as the alternative to weigh in the extractor's own TODO.

That raises a licensing question, and it is the same question ADR 0005 answered for MediatR and
AutoMapper: **a commercial fee on a dependency of a product we sell.**

## The fee

WiX v6.0.0 (April 2025) introduced the **Open Source Maintenance Fee (OSMF)**, enforced by EULA
acceptance from v7. Organisations generating **≥ US$10,000 annual revenue** must sponsor the
`wixtoolset` GitHub organisation to use the project's **binary releases**, including the packages
published to NuGet.org. This product is sold, so consuming
`WixToolset.Dtf.Compression.Cab` from NuGet would put us in scope.

## Decision

**Reject the fee; vendor the source under MS-RL.**

`third_party/wix-dtf/` holds `WixToolset.Dtf.Compression` and `WixToolset.Dtf.Compression.Cab`,
copied from `wixtoolset/wix` at tag **`v7.0.0`**, commit
**`b8977d6f88e7b68e000bac226a2814f236770570`**, together with upstream's `LICENSE.TXT`. We compile
it ourselves. Provenance, refresh procedure and the exact local modifications are recorded in
`third_party/wix-dtf/README.md`.

This is not a loophole; it is the arrangement upstream documents. The OSMF EULA template v1.1 **§4,
"Conflicts with OSI License"**, states:

> To the extent any term of this Agreement conflicts with User's rights under the OSI License
> regarding the Software, the OSI License shall govern. **This Agreement applies only to the Binary
> Release and does not limit User's ability to access, modify, or distribute the Software's source
> code or self-compiled binaries. User may independently compile binaries from the Software's source
> code without this Agreement, subject to OSI License terms.** User may redistribute the Binary
> Release received under this Agreement, provided such redistribution complies with the OSI License
> (e.g., including copyright and permission notices). This Agreement imposes no additional
> restrictions on such rights.

and **§3, "Nature of the Fee"**:

> The Fee is not a license fee. The Software's source code is licensed to User under the OSI License
> and remains freely distributable under the terms of the OSI License and any applicable open-source
> licenses.

Upstream's own package README, vendored alongside the code, draws the same line: *"While the source
code is freely available under the terms of the LICENSE, this package and other aspects of the
project require adherence to the Open Source Maintenance Fee EULA."* The fee attaches to the
**binary release and project conveniences** — official builds, the issue tracker, support channels.
It does not attach to the source.

**Two facts checked rather than assumed**, because the whole decision rests on them:

- `LICENSE.TXT` at `wixtoolset/wix@main` is **byte-identical** to `LICENSE.TXT` on the WiX v3
  `develop` branch (md5 `d224d0c38b164f77b8c44cd8f2cd0f0e`). The source license did **not** change
  across the OSMF transition — it is pure MS-RL before and after, with no fee, revenue or EULA
  clause in it at all.
- The `.cs` sources of these two projects are **identical from `v5.0.2` through `v7.0.0`** — only
  READMEs and two `PackageReadmeFile` csproj lines differ. Taking the latest release costs nothing
  and there is no pre-OSMF version with different code to retreat to.

## The MS-RL obligation — file-scoped, NOT project-wide

This was the question that had to be answered before vendoring, and it is answered from the license
text, not from reputation. MS-RL **§3(A), "Reciprocal Grants"**, in full:

> For any file you distribute that contains code from the software (in source code or binary
> format), you must provide recipients the source code to that file along with a copy of this
> license, which license will govern that file. **You may license other files that are entirely your
> own work and do not contain code from the software under any terms you choose.**

**Finding: the reciprocal obligation is scoped to the file.** The second sentence is explicit and
decisive — files that are entirely our own work and contain no DTF code may be licensed on any terms
we choose. Referencing the vendored assemblies from our code does **not** make our code MS-RL.
MS-RL is weak copyleft of the per-file kind (the LGPL/MPL family in effect), not the per-program
kind (GPL). There is **no project-wide obligation**, no obligation to publish the rest of this
repository, and no obligation on the patch-management product as a whole.

What we **do** owe, from the same section:

| Clause | Obligation | What it means here |
|---|---|---|
| §3(A) | Source of any distributed file containing DTF code, plus a copy of the license | If we ship compiled DTF to a customer, that customer can demand the source of those files. `LICENSE.TXT` ships with it |
| §3(D) | Retain all copyright, patent, trademark and attribution notices | Every vendored `.cs` carries an MS-RL header. Never strip them |
| §3(E) | Source form only under this license, with a complete copy included; compiled form only under a license that complies | We distribute compiled — so our EULA must not contradict MS-RL for those files |
| §3(B) | No trademark license | We may not use the WiX name, logo or marks as branding. Attribution in a notices file is not branding |
| §3(F) | "As-is", no warranty | We carry the support burden for this code. See Consequences |

**The boundary to police is copying, not calling.** A file of ours that *contains* DTF code becomes
MS-RL by §3(A). So: reference the projects, never paste from them. That rule is written into
`third_party/wix-dtf/README.md` where someone editing the tree will actually see it.

**Honest limit of this analysis.** This is a careful reading of the license text as quoted above,
performed by an engineer, not legal advice. The conclusion is the mainstream reading of MS-RL and
rests on an unambiguous sentence, but a product that is *sold* should have counsel confirm the
file-scoped reading and check that the customer-facing EULA does not contradict §3(E) before the
first commercial shipment. Recorded as a release-gate item, not a build blocker.

## Consequences

- **No fee, no runtime licence exposure, no compliance calendar.** Same outcome as ADR 0005, reached
  the same way.
- **We own the maintenance.** §3(F) is "as-is", and we have taken ourselves out of the support
  channel that the fee buys. Upstream security fixes will not arrive automatically — refreshing is a
  deliberate act, documented in the vendored README. Mitigated by the code being remarkably stable
  (unchanged across three major versions) and small (29 `.cs` files).
- **A notices obligation at ship time.** The product needs a third-party notices file carrying MS-RL
  and the DTF attribution, and a route for a customer to obtain the source of the vendored files.
  Neither exists yet; both belong to the packaging work that is still unowned.
- **`third_party/` is now a category in this repo**, with a `Directory.Build.props` that severs it
  from our root MSBuild props so vendored code builds under upstream's assumptions rather than ours.
  Future vendoring follows the same shape.
- **Nothing is consumed yet.** The projects build and are in the solution; no code references them.
  D-504 is the slice that wires `ExpandCabPackageSource` to a managed reader, and it has not started.
  As with ADR 0019: admitting a capability is not evidence that anything uses it.

## Alternatives rejected

- **Pay the OSMF fee (≥ US$10k/yr).** Rejected on the ADR 0005 precedent: a recurring commercial fee
  for a component we can lawfully compile ourselves, on a product we sell. The fee buys official
  binaries, the issue tracker and support conveniences — real value, but not value we need for a
  wrapper over a Win32 API that has not changed in three major versions. Revisit if we ever want the
  support relationship on its own merits; this is a cost decision, not a hostile one, and upstream
  explicitly permits the path we took.
- **Keep shelling out to `expand.exe`.** Free, and wrong. Windows-only, expands gigabytes to read a
  fraction, and makes a subprocess exit code load-bearing. It is also the code that has never
  successfully run.
- **Write our own MSZIP/LZX cabinet decoder.** The cabinet format is documented, but LZX decoding is
  genuinely intricate, and a subtle bug yields *silently wrong* patch content — the worst failure
  class in this product. Not a wheel to reinvent for a feed we do not control.
- **`System.IO.Packaging` / `System.Formats.*`.** Neither reads Microsoft cabinets. There is no
  in-box .NET CAB reader; that absence is why DTF exists.
- **Vendor from a pre-OSMF tag (`v5.0.2`).** Considered as a belt-and-braces move to sidestep the
  EULA question entirely. Rejected as unnecessary theatre: the `.cs` files are byte-identical to
  `v7.0.0`, the source LICENSE is identical, and §4 already resolves the question in writing.
  Pinning to an older tag would buy nothing and cost us the newest baseline for future refreshes.
