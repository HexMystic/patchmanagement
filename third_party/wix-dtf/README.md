# WiX Toolset DTF — vendored source (`WixToolset.Dtf.Compression` + `.Cab`)

Managed cabinet (`.cab`) pack/unpack, vendored as **source** rather than consumed as a NuGet
package. This directory is a copy of someone else's code. Read this file before touching anything
in it.

## What was pulled, and from where

| | |
|---|---|
| **Upstream** | https://github.com/wixtoolset/wix |
| **Release tag** | `v7.0.0` |
| **Commit** | `b8977d6f88e7b68e000bac226a2814f236770570` |
| **Tag date** | 2026-04-03 |
| **Pulled** | 2026-08-20 |
| **Upstream paths** | `src/dtf/WixToolset.Dtf.Compression/`, `src/dtf/WixToolset.Dtf.Compression.Cab/` |
| **License** | Microsoft Reciprocal License (MS-RL) — `LICENSE.TXT` in this directory |

`LICENSE.TXT` is upstream's own file, copied verbatim from the same commit. Its content is
byte-identical to the upstream original (md5 `d224d0c38b164f77b8c44cd8f2cd0f0e` over LF-normalised
bytes; the working copy is CRLF). It is **also** byte-identical to the LICENSE.TXT on the WiX v3
`develop` branch — the source license has not changed across the OSMF transition.

`WixToolset.Dtf.Compression.Cab` depends on `WixToolset.Dtf.Compression` for its abstract archive
base types, which is why both projects are here rather than just the Cab one.

## Why source, not the NuGet package

WiX v6 introduced the **Open Source Maintenance Fee (OSMF)**: organisations above US$10,000 annual
revenue must sponsor the project to use the **binary releases**. This product is sold, so the fee
would apply to us if we consumed the package.

The fee does **not** attach to the source. The OSMF EULA template v1.1 §4 ("Conflicts with OSI
License") says so directly:

> This Agreement applies only to the Binary Release and does not limit User's ability to access,
> modify, or distribute the Software's source code or self-compiled binaries. User may
> independently compile binaries from the Software's source code without this Agreement, subject to
> OSI License terms.

and §3 ("Nature of the Fee"):

> The Fee is not a license fee. The Software's source code is licensed to User under the OSI
> License and remains freely distributable under the terms of the OSI License and any applicable
> open-source licenses.

Upstream's own package README (vendored alongside, in each project directory) states the same split:
*"While the source code is freely available under the terms of the LICENSE, this package and other
aspects of the project require adherence to the Open Source Maintenance Fee EULA."*

Full reasoning, alternatives weighed, and the MS-RL obligation analysis:
[`docs/adr/0020-cab-reader-licensing.md`](../../docs/adr/0020-cab-reader-licensing.md).

## Our MS-RL obligations, in practice

MS-RL is **file-scoped** weak copyleft, not project-wide (§3(A), quoted in full in the ADR). The
practical rules for this repo:

1. **Every file in this directory stays MS-RL**, whether we modify it or not. If we ship compiled
   form to a customer, we must make the source of these files available to them and include
   `LICENSE.TXT` (§3(A), §3(E)).
2. **Our own code stays under our own terms.** §3(A) is explicit: *"You may license other files that
   are entirely your own work and do not contain code from the software under any terms you
   choose."* Calling into these assemblies from our code does not make our code MS-RL.
3. **Do not copy DTF code into our tree.** A file of ours that contains DTF code becomes MS-RL by
   §3(A). Reference the projects; never paste from them.
4. **Do not strip the headers.** §3(D) requires retaining all copyright and attribution notices.
   Every `.cs` file here carries one — leave it.
5. **Prefer zero local modifications.** Every edit widens the surface we have to publish and makes
   the next upstream refresh harder.

## Local modifications

Kept deliberately minimal. Currently **one**, in each of the two `.csproj` files:

- `<TargetFrameworks>netstandard2.0;net20</TargetFrameworks>` → `<TargetFrameworks>netstandard2.0</TargetFrameworks>`

  Upstream multi-targets `net20`, which needs a legacy targeting pack the modern .NET SDK does not
  ship. `netstandard2.0` is what our `net9.0` code consumes. The change is marked with a
  `LOCAL MODIFICATION` comment at the edit site.

**No `.cs` file has been modified.** All 29 source files are verbatim upstream.

`third_party/Directory.Build.props` severs this tree from the repo-root MSBuild props (which set
`net9.0`, `Nullable=enable`, `ImplicitUsings=enable`) so upstream code builds under upstream's
assumptions. That file is ours, not upstream's.

## Refreshing to a newer upstream

1. Clone `wixtoolset/wix` at the new tag; copy the same two directories plus `LICENSE.TXT`.
2. Re-apply the `TargetFrameworks` modification.
3. Update the table at the top of this file — tag, commit, date.
4. Re-read §4 of the OSMF EULA at that version; the split between source and binary is the whole
   basis for this arrangement, and it is upstream's to change.

Note that the `.cs` sources of these two projects were **identical** from `v5.0.2` through `v7.0.0`
— only READMEs and two `PackageReadmeFile` csproj lines differed. This is very stable code, so
refreshes should be rare and cheap.

## Status in this repo

**Vendored but not yet consumed.** Nothing references these projects yet. They are here for
**D-504**, the `wsusscn2` rewrite, where `ExpandCabPackageSource`'s `expand.exe` shell-out is
replaced by a managed reader — that work is a separate slice and has not started. The projects are
in `PatchManagement.sln` so the vendored code is proven to build, and for no other reason.
