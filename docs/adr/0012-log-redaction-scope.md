# 12. What the log-redaction belt covers — and what it deliberately does not

- **Status:** Accepted — **amended 2026-07-25 (review H3)**, see decisions D and E
- **Date:** 2026-07-25
- **Amends:** nothing — this records boundaries that were previously implicit in
  `docs/THREAT-MODEL.md` ("a redaction filter on the logging pipeline") and
  `docs/phases/phase-2.md` ("a logging redaction filter")
- **Context:** Phase 2 review of `SecretRedactingLoggerProvider` (commits `e260203`,
  `814fc40`)

> **Amendment 2026-07-25.** The original Consequences claimed the belt covered "two channels"
> with scope state as "the only known third". That was wrong: **structured log state is a
> further uncovered channel, and it is the one production sinks actually read.** Review H3
> reproduced a registered sentinel surviving into `AddJsonConsole`'s `State` and into
> `EventSourceLoggerProvider`'s `[MessageJson]` while the formatted line showed
> `***REDACTED***`. Decision D below records the corrected scope; decision E reverses the
> unconditional exception replacement. The rest of this ADR stands.

## Context

Phase 2 ships `SecretRedactingLoggerProvider` — a defense-in-depth filter wired into
the logging pipeline by `VaultModule.AddVaultModule`. THREAT-MODEL and `phase-2.md`
both call for "a redaction filter on the logging pipeline" but neither specifies what
it filters, what it cannot filter, or who feeds it. Three boundary questions came out
of review, and all three were answerable only from code, not from any document:

1. `Register()` — which populates the set of literals to scrub — has **no runtime
   caller**. In production the set is empty, so message-scrubbing guards nothing.
   No document ever named an owner for that wiring.
2. `ILogger.BeginScope` state is forwarded to the sink **unscrubbed**. Scope state is
   a third channel sinks render, alongside message text and the exception object.
3. `StoreCredentialRequest` is a `record`, and a record's compiler-generated
   `ToString()` prints every property — a leak channel that opens the moment a secret
   field's type changes.

The primary guarantee has never been the filter. It is that **vault code simply does
not pass secret material to a logger**, proven by `NeverLogTests`, which runs a real
store/resolve flow and scans every emitted line for the secret in four encodings. The
filter is the belt to that suspenders. This ADR records where the belt reaches.

## Decision

### A. Resolve-time self-registration is rejected

`ResolveAsync` will **not** register resolved secrets with the filter, and neither
will any caller. This is a rejection, not a deferral — no phase owns it.

`Register(string)` stores its argument in a `ConcurrentDictionary` that lives for the
process lifetime. Registering each resolved credential would mean an immutable,
non-zeroable managed **string** copy of every secret the process ever resolved, held
until exit. That directly contradicts `docs/THREAT-MODEL.md`:

> Credentials are decrypted **only in memory**, only at the moment of use, into a
> pinned buffer that is **zeroed immediately after**.
>
> Plaintext is **never** written to disk, cache, swap-visible structures, temp files,
> or logs.

A permanent in-process registry of plaintext is precisely such a cache. It would
defeat the pinned-buffer zeroing that `ResolvedCredential.Dispose` performs, and would
turn a single heap dump into every credential the process ever touched. The cure is
worse than the disease it treats.

`Register()` therefore has one legitimate use: **literals already resident for the
process lifetime**, registered deliberately by a caller that knows the value must
never surface — a config-sourced bootstrap value, or a test proving the filter bites.
Per-request resolved credentials are explicitly out of scope.

### B. Log scope state is not covered

`RedactingLogger.BeginScope` forwards state to the inner provider unchanged. Scrubbing
it in general is not possible: `TState` is arbitrary, commonly an anonymous type, and
there is no way to rewrite one while preserving what a structured sink reads from it.

Accepted because nothing creates a data-carrying scope: a repo-wide audit found three
`BeginScope` occurrences, all `ILogger` interface implementations (two forwarders, one
no-op), and **zero invocations passing application data**. This is enforced, not
merely asserted — `VaultLoggingConventionTests` fails if a `BeginScope` call appears
anywhere in `src/Modules/Vault` beyond the known pass-through.

Note the coverage gap this closes by other means: `CapturingLoggerProvider`, which
`NeverLogTests` scans through, returns `null` from `BeginScope` and discards state. A
secret placed in a scope would be **invisible to the never-log test suite**. The
convention test exists because the scanner cannot see this channel.

### C. Secret-bearing types must not rely on a generated `ToString()`

A `record` prints all properties from its compiler-generated `ToString()`, so any
`LogInformation("{Request}", request)` renders them. Types carrying secret material
must either not be records or must override `ToString()` with a redacted form — the
pattern `ResolvedCredential` already follows:

```csharp
public override string ToString() => $"ResolvedCredential(kind={Kind}, user={Username ?? "<none>"}, secret=<redacted>)";
```

`StoreCredentialRequest` is a record whose `Secret` is `byte[]`, which renders as
`System.Byte[]` — inert today, and a leak the moment that field becomes a `string`.
`VaultLoggingConventionTests` pins both: it asserts the rendered form of each
secret-bearing type carries no sentinel, and fails when a new secret-bearing record
appears uncovered.

**Scope of the scan, corrected 2026-07-26 (re-review H-1).** It detected records by looking for the
compiler-generated `<Clone>$`, which is emitted for record **classes** only — record *structs* are
copied by value and get none. Every record struct was therefore invisible to a test this decision
claimed pinned them; `KeyBinding` is one. Detection now also accepts a value type carrying a
compiler-generated `PrintMembers`, which covers both record kinds, and the change was
mutation-checked in both directions: a throwaway `readonly record struct` with a `string` secret
member **passed** under the old detection and **fails** under the new one.

What this deliberately does **not** widen: ordinary (non-record) classes stay out of scope, because
they have no compiler-generated `ToString()` — the one leak this decision exists to guard against.
`KekKeyset` is such a class and carries a hand-written redacted `ToString()`. The test's own comment
already scopes it correctly as "an enforcement aid, not a completeness proof", and that remains the
honest reading: it catches the specific accident of a new secret-bearing record, not every way a
type could render a secret.

### D. Structured log state is not covered (added 2026-07-25, review H3)

`RedactingLogger.Log` forwards `TState` to the sink **verbatim**. That is the structured
channel: a JSON console, an OTel exporter, or `EventSourceLoggerProvider` enumerates it as
key/value pairs and emits the **raw values**, and may never call the formatter at all. It is
what production sinks actually read, and it is not scrubbed.

It stays uncovered, deliberately:

- **A sentinel-based scrubber would be inert.** `Scrub` matches only registered literals,
  and decision A above rejects ever registering one at runtime, so projecting state values
  through it would change nothing while adding per-log allocation and a `TState`
  substitution.
- **Type-based filtering would be destructive.** Strings are exactly where a secret would
  live, so meaningful filtering means redacting every string value — destroying the
  diagnostics the structured channel exists to provide.
- **Partial rewriting gives false assurance**, the same reason already recorded under
  Rejected for scope state. Claiming this channel is covered is the error this amendment
  exists to correct.

What protects it is the **primary** guarantee — vault code never puts secret material in a
log — verified at the time of writing: all five vault log call sites pass only `Guid`,
enum, `int`, and two identifier strings. `StructuredStateChannelTests` pins both halves:
the boundary (the belt scrubs the formatted message and *not* structured state, so a silent
change fails the build) and the guarantee (a real store/resolve puts no secret into
structured state, swept in four encodings, with `byte[]` rendered as base64 rather than
`System.Byte[]`).

`EventId.Name` is likewise unscrubbed. It is a compile-time constant at every call site, so
inert — recorded for completeness rather than as a live concern.

### E. The exception is replaced only when the belt is armed (added 2026-07-25)

**This reverses the unconditional replacement introduced in `e260203`.** That decision
reasoned that `InnerException` and `Data` are unscrubbable channels and so should be dropped
regardless. It assumed the belt was a meaningful live control. Decision A means it is not:
nothing registers a sentinel in production, so `Scrub` is the identity function and the only
live effect was destroying the inner chain and `Data` for every vault exception — at exactly
the moment an operator needs them, in exchange for redaction that cannot fire.

The belt now replaces the exception only when `IsArmed` (at least one registered literal).
Unarmed, the original passes through untouched. The capability is kept for when a caller
registers a process-lifetime literal; the cost is not paid when it cannot help.

## Consequences

- The belt covers **two** channels — formatted message text (`Scrub`) and the
  exception object (`ScrubException`, when armed) — for categories under
  `PatchManagement.Vault.` only. **Structured log state and scope state are both uncovered**,
  and structured state is the one a production sink renders. Neither is an oversight; both
  are pinned by tests so they cannot move silently.
- Message-scrubbing is **inert in production today** and that is by design, not an
  unfinished task. Since decision E, an unarmed belt has **no live effect at all** — which
  is the honest position: it is a thin secondary that arms only when someone registers a
  literal.
- **Read the belt as secondary, never as the guarantee.** The never-log invariant rests on
  vault code not passing secrets to loggers, proven by `NeverLogTests` — which correctly
  bypasses the belt entirely — and now by the structured-channel sweep as well.
- The never-log guarantee rests where it always did: on vault code not passing secrets
  to loggers, proven by `NeverLogTests`. Reviewers should not read the presence of a
  redaction filter as end-to-end coverage.
- **Named owner for the residual obligation: Phase 3 (Connectors).** It is the first
  module to consume `ResolvedCredential`, and `docs/phases/phase-3.md` already binds
  it — "a `ResolvedCredential` is used in memory only and never logged or returned".
  Phase 3 must extend the NeverLog scan to its own module; the vault-scoped belt does
  not cover connector log categories.

## Rejected

- **Self-registration at resolve time** — creates a process-lifetime plaintext
  registry, as above.
- **A scoped `Register`/`Unregister` pair around each use** — still mints a
  non-zeroable string, still widens the window under concurrency, and adds an API that
  invites the rejected pattern.
- **Scrubbing arbitrary `TState` scope objects** — cannot rewrite an anonymous type;
  a partial implementation covering only `string` and
  `IEnumerable<KeyValuePair<string, object>>` would give false assurance for the
  shapes it misses.
- **Applying the belt to every log category** — would extend the exception handling's
  `InnerException`/`Data` drop to all application logging (EF Core, Npgsql, ASP.NET),
  where the inner chain is usually the actual cause, for no redaction benefit.
