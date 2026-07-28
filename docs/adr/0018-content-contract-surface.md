# ADR 0018 — The content contract surface lives in Shared/Contracts

**Status:** Accepted — 2026-07-28 (Phase 5)
**Supersedes:** nothing. **Follows:** [ADR 0017](0017-connector-contract-surface.md), which made the
same move for `IEndpointConnector` and for the same reason. **Relates to:**
[ADR 0010](0010-global-content-catalogue.md) (the catalogue is global), [ADR 0011](0011-fixed-version-raw-as-sourced.md)
(fixed versions are raw as sourced).

## Context

`IContentConnector` and the normalized model it returns were declared inside
`src/Modules/Content`, alongside the eight feed connectors and an Npgsql-backed upsert store.

**The host-discovery guard could not be written at all.** `CompositionRoot` finds modules by
scanning `PatchManagement.*.dll` in `AppContext.BaseDirectory`. Under a test host that directory is
the *test project's* output. A test project that referenced the Content module would put the DLL
there, discovery would succeed on that copy, and the test would pass while the shipped API still
lacked the module. ADR 0017 records that trap; the Vault hit it at `a50d9ec` and Phase 3's WIP hit
it again. **Phase 5 had it a third time** — `PatchManagement.Api` never referenced
`PatchManagement.Content`, so `ContentRegistrar` was undiscoverable and every line of the module was
dead in production. The only way the guard can fail for the right reason is to assert through a type
the test project already has, which means a type in Contracts. Content had none.

**The vocabulary had no source of truth.** The frozen Phase-1 content vocabulary was written down
three times with nothing tying the copies together: `Feeds`/`Ecosystems` inside the module,
`AppDbContext`'s CHECK-constraint arrays, and the enums in `schemas/advisory.schema.json` /
`schemas/patch.schema.json`. Divergence would surface as a Postgres `23514` at ingest time.

**Consumers would inherit a database driver.** Phase 6 (Assessment) correlates inventory against
normalized content and Phase 7 (Risk) reads the KEV/EPSS overlays. With the model beside
`ContentStore`, every consumer would take a dependency on Npgsql it has no use for.

## Decision

`IContentConnector`, `ContentSourceState`, `NormalizedBatch`, `NormalizedAdvisory`,
`NormalizedPatch`, `NormalizedAffect`, `ProvenanceEntry`, `KevOverlay`, `EpssOverlay`, `Feeds` and
`Ecosystems` live in `src/Shared/Contracts/Content`, namespace `PatchManagement.Contracts.Content` —
mirroring how `ICredentialProvider` and `IEndpointConnector` already sit under `Credentials/` and
`Connectors/`.

**The Npgsql-shaped seams deliberately stay in the module.** `IContentStore` and
`IContentConnectionFactory` carry `NpgsqlConnection`/`NpgsqlTransaction` in their signatures;
promoting them would put a database driver into Contracts, which is exactly the coupling this move
exists to prevent. `IHttpContentFetcher`, `IWsusPackageSource`, `SyncOutcome` and everything under
`Connectors/`, `Http/` and `Ingestion/` also stay — they are implementation seams, not a contract.

This is an **additive** change to the Phase 1 contracts, not a change to a frozen artifact. NEVER #6
enumerates the schema, RLS policies, OpenAPI, JSON schemas and the state machine; adding an
interface beside an existing one is the same class of change ADR 0017 already made.

## Consequences

- `HostModuleDiscoveryTests` can assert the Content module is both shipped (`deps.json`) and
  resolvable from the real host container **without** referencing the module — so the guard retains
  the ability to fail. It **did** fail, red-first, before `PatchManagement.Api` gained its
  `ProjectReference`; both failures are quoted in that commit body.
- The guard resolves `IEnumerable<IContentConnector>` rather than `IContentStore`. `IContentStore`
  and `IContentConnectionFactory` depend on `ConnectionStrings:Content`, so resolving them would
  confuse a *wiring* failure with a *configuration* one. Resolving the connector set also proves all
  eight feeds registered, and — because `WebApplicationFactory` validates scopes — catches the
  captive-dependency class of bug that ADR 0017 records `deps.json`-alone missing.
- `Feeds`/`Ecosystems` are now referenceable without depending on the module, so
  `ContentVocabularyTests` can pin them against the JSON schemas. The third copy —
  `AppDbContext`'s CHECK arrays — is **not** yet collapsed; that is recorded below as a residual.
- Phases 6 and 7 consume the normalized model with no database dependency.
- `Contracts` gains no package references. A test asserts it references no database driver, so
  `IContentStore`'s Npgsql surface cannot drift inward later.

### Residual, stated rather than implied

**The vocabulary is still duplicated twice, not three times.** `Feeds` is now pinned against the
JSON schemas, but `AppDbContext.ContentSourceKinds`/`AdvisorySources`/`PatchSources` remain an
independent copy. Collapsing them means either Persistence referencing Contracts (it already does)
and consuming the constants, or a test tying the three together. It is a real cleanup and it is
**not** done here — this slice is foundation, and changing what a migration emits is a
frozen-contract question under NEVER #6. Owner: **Phase 6**, which is `solo` and is the next phase
to read this vocabulary in anger.

## Rejected alternatives

**Leave the interface in the module and assert discovery via `deps.json` alone.** ADR 0017 already
rejected this and the reasoning is unchanged: it proves the DLL ships, not that the container can
construct the module. The captive-dependency bug Phase 3 found would have survived it, because the
assembly was present and correct — it simply could not be built.

**Reference the module from the integration test project.** The trap the Vault documented and
Phase 3 repeated. It makes the guard incapable of failing, which is this project's characteristic
defect rather than a minor weakness.

**Look the type up reflectively by name from the loaded assembly.** Workable — `Assembly.GetType`
on the discovered `PatchManagement.Content` would be red when unreferenced and green after, with no
compile-time dependency. Rejected because it leaves the guard string-typed against a namespace that
no compiler checks, and because it would have left the vocabulary triplication and the Phase 6/7
Npgsql coupling untouched. The move solves three problems; the reflection trick solves one.
