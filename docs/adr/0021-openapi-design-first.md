# 21. `api/openapi.yaml` is design-first — authoritative, hand-authored, and enforced by test

- **Status:** Accepted
- **Date:** 2026-08-20
- **Relates to:** CLAUDE.md §4.5 (frozen contracts), NEVER #6, review finding **H5**
  (`docs/reviews/phase-1-review.md:175-189`), Phase 12 (UI, builds against this contract)
- **Applies to:** `api/openapi.yaml`, and every future HTTP endpoint in `src/Host/Api`
- **Closes:** **H5**, open since Phase 1, re-flagged by the 2026-08-18 audit

## Context

CLAUDE.md §4.5 lists OpenAPI among the frozen contract artifacts. The file itself used to say:

> are added by later phases; this file is regenerated code-first once controllers exist.

H5 named the contradiction: *"the file's own header inverts the freeze… 'regenerated code-first once
controllers exist' means the implementation will dictate the contract, the opposite of what
CLAUDE.md §4.5 defines freezing to mean. One of these documents is wrong, and both are checked in."*

Both cannot be true. **A file a build step rewrites is an output, not a contract** — nothing can be
frozen that regenerates itself. The 2026-08-18 audit struck the false line but deliberately left the
decision open, recording in the file that whoever resolved it had to pick a direction and write this
ADR.

H5 has a **second half that matters more**, and it survived the audit untouched: *"no test guards
it: nothing in `tests/` reads `api/openapi.yaml`, so the one frozen contract with no enforcement is
also the one that contradicts itself."*

### What "frozen" actually means in this repo

The rationale for design-first is usually given as "every other frozen contract here is spec-first."
**That is not accurate**, and the accurate version is a stronger argument. The four other frozen
artifacts do not share an authoring direction:

| Contract | Authoritative artifact | Direction | Drift test |
|---|---|---|---|
| JSON schemas (`schemas/*.json`) | the hand-authored schema | design-first | ✅ `ContentVocabularyTests` pins C# constants to the schema |
| Endpoint state machine | C# data table, `StateMachine.cs` | code-as-spec | ✅ `PatchManagement.Contracts.Tests` |
| Schema + RLS | EF model + migrations | code-first | ✅ behaviourally, by `RlsConventionTests` against the live catalog |
| `db/schema.sql` | — it is a `pg_dump` **export** | generated snapshot | ❌ **none** — review finding **L4** |
| **`api/openapi.yaml`** | **contested** | **contested** | ❌ **none** |

The invariant this repo actually holds is not "spec-first". It is: **every frozen contract has
exactly one authoritative artifact, and a test that fails when anything drifts from it.** OpenAPI
was the only contract missing *both* halves — it could not say which artifact was authoritative, and
nothing checked it either way. That is why H5 is a live contradiction rather than a documentation
nit.

### Why this is cheap now and expensive later

The API surface is **exactly two routes** — `GET /health` and `GET /diag/assets`, both minimal APIs
in `src/Host/Api/Program.cs`. There are **zero controllers** in the repo, and modules structurally
cannot register routes: `IModuleRegistrar.Register` takes only an `IServiceCollection`, so routing
lives solely in `Program.cs`. `api/openapi.yaml` already describes exactly those two operations.

So there is nothing to reverse-engineer and no accumulated drift to reconcile. Every resource
endpoint added before this decision would have deepened the inconsistency, which is precisely what
the audit warned about.

## Decision

**Design-first.** `api/openapi.yaml` is the authoritative contract: hand-authored, reviewed, frozen,
and never generated. The host conforms to the file, not the reverse. Drift fails
`OpenApiContractTests`.

**CLAUDE.md needs no edit** — and that is the decisive argument between the two options. Design-first
is what makes OpenAPI's presence on the §4.5 frozen list *true*. The code-first alternative would
have required deleting OpenAPI from §4.5, weakening the governance rule to accommodate a file that
had drifted from its own stated purpose.

Adding an endpoint now runs in this order: **specify it here first — which turns the suite red — then
implement it until it goes green.** That is this repo's red-first discipline applied to the API
surface, and it is enforced mechanically rather than by convention.

### The enforcement

`tests/PatchManagement.IntegrationTests/OpenApiContractTests.cs` compares the set of `VERB /route`
operations declared in the spec against the set the host actually serves, read from the real
`EndpointDataSource` of a composed `WebApplicationFactory<Program>` host (no database needed, the
same way `HostModuleDiscoveryTests` works). Reading the live endpoint table rather than scanning
source matters: a route added by a library would be invisible to a source scan.

**The comparison is bidirectional**, and both directions catch a real defect:

- a route absent from the spec is a **stowaway endpoint** shipping without a contract;
- a spec path with no route is a **promise the API does not keep** — and Phase 12 would build a UI
  against it.

`Microsoft.OpenApi.Readers` is added to the **test project only**. The shipped API project takes no
OpenAPI package, because there is nothing to generate.

**Three of the four tests are controls.** A spec that failed to parse and a host whose endpoints
could not be enumerated both produce an empty set, and two empty sets compare *equal* — the check
would pass at its loudest having verified nothing. So the suite separately pins that the spec parsed
as valid OpenAPI with a non-empty path set, that the route scan found endpoints, and — the repo's
pattern-audit idiom — that the comparison itself reports a difference in both directions when fed
synthetic sets.

Proven red before green, in both directions, via `scripts/mutation-guard.ps1`: a stowaway
`GET /diag/mutation-probe` route in `Program.cs` failed the suite naming the undocumented route, and
the same path added to the spec alone failed it naming the unimplemented promise. Each mutation
turned **exactly one** test red and left the other three green, then was reverted with the guard's
`-Absent` check.

## Consequences

- **The spec cannot be generated.** No Swashbuckle, no NSwag, no `Microsoft.AspNetCore.OpenApi` in
  `src/Host/Api`. Anyone reaching for one is reversing this ADR and needs a new one. (It was never
  viable anyway: the endpoints return anonymous types — `new { status = "ok" }` — which generate
  poor schemas.)
- **Phase 12 finally has a contract to build against**, which was H5's original complaint. What it
  can build against is still only two diagnostic endpoints — see the known gaps.
- **Editing `api/openapi.yaml` remains a NEVER #6 change** requiring an explicit ask. This ADR does
  not make the file editable at will; it settles which direction authority flows.
- The frozen-contract count with real enforcement goes from three of five to four of five.

## Known gaps — named, not fixed

- **`servers.url` is wrong.** The spec says `http://localhost:5080`; `launchSettings.json` runs the
  host on `5296`/`7083`. The drift test covers `paths` only, so it does not catch this. Deliberately
  left alone: fixing the spec to match the code is the code-first direction this ADR rejects, and
  fixing `launchSettings.json` is scope this decision did not cover. **Owner: whoever adds the first
  real resource endpoint**, who has to touch this file anyway.
- **L4 is the same defect shape.** `db/schema.sql` is a frozen contract that is a generated snapshot
  with **no drift test** — it "will drift silently the first time a later phase adds a migration and
  forgets to re-dump". This ADR sets the pattern that finding needs. Still unowned.
- **This fixes authority, not emptiness.** H5 had a third complaint — that the contract is "an empty
  skeleton" with no resource surface for assets, findings, credentials, deployments or audit. That
  is still true. It is now a contract that is *honest and enforced* about being small, which is a
  different thing from being complete.
- The walk-up that locates the repo root is now duplicated a **fifth** time. Consolidating the copies
  is a cleanup with no owner; a `ProjectReference` to `PatchManagement.TestSupport` was deliberately
  **not** added to reach `RepoPaths`, because it would place another `PatchManagement.*.dll` in the
  test output directory that `CompositionRoot.LoadModuleAssemblies` scans — the exact class of
  subtle change ADR 0017 warns about.

## Rejected alternatives

- **Code-first regeneration.** Requires removing OpenAPI from CLAUDE.md §4.5's frozen list, since a
  regenerated file cannot be frozen. That weakens a governance rule to accommodate a drifted file,
  and it discards the one property Phase 12 needs — a contract that exists *before* the
  implementation it describes. It was also unimplementable with the current toolchain.
- **One-directional drift tests.** "Implemented ⊆ spec" alone lets a spec path be quietly abandoned
  forever, and nothing then proves the contract is real. "Spec ⊆ implemented" alone permits exactly
  the undocumented stowaway endpoint the contract exists to prevent, and inverts design-first.
- **Parsing the YAML by regex** to avoid a dependency, as `LabFleetManifestTests` does for
  `docker-compose.yml`. Rejected: a regex that silently matches nothing is this project's
  characteristic failure, and re-implementing OpenAPI semantics by hand to avoid one MIT test-only
  package is a poor trade. Parsing it as a real OpenAPI document also validates it.
