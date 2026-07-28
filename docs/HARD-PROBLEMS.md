# HARD-PROBLEMS

The problems that make patch management genuinely hard. Each: the problem, our
**recommended approach**, and the **alternatives we rejected**. These shape the
Phase 1 contracts and later engines; revisit before implementing the relevant phase.

---

## 1. Windows patch content — `wsusscn2.cab` vs MSRC CSAF API
**Problem.** Two authoritative sources answer *different* questions. The cab (offline
scan catalog, consumed via the Windows Update Agent) knows *which updates apply to a
specific machine* including supersedence and bundles. MSRC CSAF/CVRF knows *which
CVEs a KB fixes* and their severity/exploitability.
**Recommended.** Use **both**: `wsusscn2.cab` as the **applicability engine**
("what's missing on this host"), MSRC CSAF as the **CVE overlay** ("why it matters").
See ADR 0008.
**Rejected.** Cab-only (weak CVE mapping, findings not explainable). CSAF-only (no
per-host applicability/supersedence — can't say "missing *here*").

## 2. Backport detection — RHEL/Debian fix CVEs without version bumps
**Problem.** Enterprise distros **backport** security fixes into the *same* upstream
version-number, changing only the package **release/revision**. A naive "installed
version < fixed upstream version" check produces massive false positives (flagging
patched hosts as vulnerable).
**Recommended.** Assess against **distro security advisories** (USN, RHSA/OVAL,
Debian DSA), which state the exact fixed **distro package version** (e.g.,
`1.2.3-4ubuntu0.5`). Compare the installed package's full distro version/release to
the advisory's fixed version using the **distro's own comparison semantics** — never
upstream semver. Track `backported` on `advisory_affects`.
**Rejected.** Upstream-version comparison (false positives). CPE/NVD version ranges
alone (blind to backports).

## 3. Version comparison — RPM epochs, Debian revisions, Windows builds
**Problem.** "Is A older than B?" has no universal answer across ecosystems.
- **RPM:** `epoch:version-release`, where **epoch dominates** everything and
  `rpmvercmp` has non-obvious tilde/caret rules.
- **Debian:** `[epoch:]upstream-revision` with `dpkg --compare-versions` semantics
  (tilde sorts *before* everything, for pre-releases).
- **Windows:** four-part **build numbers** (e.g., `10.0.19045.4046`); "patched" is a
  build/revision threshold, not a package version.
**Recommended.** Implement **per-ecosystem comparators** with exact native semantics
(port `rpmvercmp` and `dpkg` compare; numeric tuple compare for Windows builds),
each behind a common `IVersionComparator` and covered by a **conformance test
corpus** drawn from real advisories. Never a generic string/semver compare.
**Rejected.** Generic semver (wrong for all three). Shelling out to `rpm`/`dpkg` on
the *server* (not portable, not present for cross-distro assessment).

## 4. Supersedence
**Problem.** A newer patch **supersedes** older ones; a host missing a superseded
patch should be told to install the **superseding** patch, and chains can be deep.
Missing this produces redundant or impossible deployment plans.
**Recommended.** Model an explicit **supersedence DAG** (`patch_supersedence`). At
assessment, resolve each missing patch to its **effective head** (latest
non-superseded applicable patch); deploy that. Detect and break cycles defensively.
**Rejected.** Flat "latest by date" heuristic (wrong across product families).
Ignoring supersedence (redundant installs, wasted windows).

## 5. Verification — never trust exit codes
**Problem.** An installer returning `0` does **not** prove the patch is applied
(pending reboot, partial apply, wrong package, silent no-op). Trusting exit codes
reports false "verified".
**Recommended.** **Re-observe state.** After deploy, re-run inventory/applicability
against the host and assert the specific patch/build is now present (and, where
relevant, the reboot completed). Verification is a *fresh assessment*, not a return
code. State goes `deploy-in-progress → pending-reboot → verified` only on observed
evidence. (CLAUDE.md NEVER #3.)
**Rejected.** Exit-code-as-truth. Installer stdout parsing as sole proof.

## 6. Idempotency
**Problem.** Agentless ops run over flaky links; retries and overlapping schedules
are inevitable. Non-idempotent operations double-apply or corrupt state.
**Recommended.** Every endpoint operation is **safe to retry**: check-then-act
against observed state; use operation keys/leases (Redis) so the same logical action
isn't executed twice concurrently; make "already in desired state" a success, not an
error. All operations time-bounded (CLAUDE.md NEVER #5).
**Rejected.** Fire-and-forget commands. Assuming exactly-once delivery.

## 7. Exception & risk-acceptance workflow
**Problem.** Not every finding gets patched — some are formally **risk-accepted** or
deferred. Without a first-class workflow, teams silence findings in ad-hoc ways and
lose auditability.
**Recommended.** First-class `exceptions` (scope: finding/asset/group; reason;
approver; **expiry**). An active exception moves a finding out of "actionable"
without deleting it; on expiry it **automatically reopens**. Every exception is
audited. Explainable: the finding shows *why* it's suppressed and by whom.
**Rejected.** Deleting/hiding findings (no audit, silent risk). Global mute lists
(no expiry, no approver, no scope).

## 8. Honest state model
**Problem.** The easy failure is to collapse "couldn't check" into "compliant". That
hides risk — the cardinal sin of a security product.
**Recommended.** Distinct, **honest** states: `unreachable`, `auth-failed`,
`scan-failed`, `assessed-compliant`, `assessed-missing`, `deploy-in-progress`,
`deploy-failed`, `pending-reboot`, `verified`, `rollback-in-progress`, `rolled-back`
— with enforced legal transitions (Phase 1). An unreachable host is *never*
compliant. Illegal transitions throw.
**Rejected.** Boolean compliant/non-compliant. Treating errors as compliant.

## 9. Double-hop
**Problem.** A remote WinRM/PowerShell session **cannot authenticate onward** (e.g.,
to an SMB share to fetch a patch) without credential delegation — the classic
"double-hop". Naive designs hang or fail opaquely mid-deploy.
**Recommended.** Avoid the second hop where possible: **push** the payload to the
target first (SMB/SFTP *from the console*), then execute locally on the target so no
onward auth is needed. Where a hop is unavoidable, use explicit, scoped delegation
(constrained Kerberos / CredSSP with eyes-open tradeoffs) and **surface the
requirement** rather than hang. The connector detects and reports double-hop
conditions (Phase 3).
**Rejected.** Blind CredSSP everywhere (credential-theft exposure). Pretending the
hop works (opaque hangs/failures).
**Status after Phase 3.** Detection ships and is protocol-scoped: Windows-shaped signals (UNC paths,
onward-session cmdlets, network-drive mapping) apply to WinRM only, because running them against SSH
produced false refusals on commands that merely contained the text. Push and pull are assessed too —
writing to a UNC share over WinRM is the textbook case and was previously unchecked.
**A warning for whoever implements delegation.** The detection was **inert on its most important
pattern** until Phase 3: the onward-session regex matched the switch as `\b-ComputerName`, and a word
boundary can never sit between a space and a hyphen, so the ordinary form never matched. It was
written, reviewed and shipped without ever firing. Delegation work should assume the same of any
pattern it adds, and prove each one against a known-offending sample.
**Still open — D-304, owner Phase 8.** `AllowCredentialDelegation` currently only *skips the check*;
it delegates nothing. A flow that genuinely needs a second hop is refused, not attempted.

Cold review R3 flagged that this was documented here and in the ROADMAP but **not at the contract an
operator actually reads** — `EndpointTarget.AllowCredentialDelegation` described itself as "whether the
connector may attempt onward credential delegation (CredSSP / constrained Kerberos)", which promises a
capability that does not exist. Setting it does not make a second hop work; it converts an immediate,
honest `DoubleHopRequired` into the opaque hang or access-denied this section exists to prevent. The
property now says exactly that. **The deferral is unchanged — only the description was wrong.**

## 10. Roaming devices
**Problem.** Agentless management **cannot reach machines that aren't on a reachable
network** — laptops off-VPN, travelling endpoints. This is a real, structural gap.
**Recommended.** **Document the gap honestly.** Model an asset's reachability and
`last_seen`; surface roaming/off-network devices as an explicit, reported category
("known but unreachable") — never silently count them compliant. If cloud-reachable
management is added later it's an additive capability, not a hidden assumption.
**Rejected.** Pretending coverage is total. Silently dropping unreachable devices
from compliance denominators (dishonest metrics).

## 11. Host-key verification without a key store
**Problem.** An agentless connector authenticates *to* endpoints with high-value credentials, so it
must first authenticate *the endpoint*. Phase 3 shipped with `e.CanTrust = true` — every presented
host key accepted — which authenticates whatever answers on the target's address and then sends it a
private key. But refusing unknown keys requires a store of verified fingerprints, and nothing owns
one yet.
**Recommended.** Refuse by default and make the exception explicit configuration
(`ConnectorSecurityOptions.AllowUnknownHostKeys`, default false). The dev lab opts in, because its
containers regenerate host keys on every rebuild and there is nothing stable to pin. A real fleet
needs the store, and until it exists the flag is what keeps the connector off production — the gating
is the point, not a side effect.
**Rejected.** Trust-on-first-use with no persistence (indistinguishable from trusting everything
after a restart). Accepting all keys with a warning (warnings in build output are what get missed).
**Owner.** D-301, Phase 4 — the store belongs with asset persistence, where a fingerprint is just
another observed fact about a host.

## 12. Reachability and authentication are different questions
**Problem.** Bounding "can I reach this host and log in" with one timeout makes the timeout decide the
*outcome*, not just the deadline. The lab's sshd takes ~10.15s to reject an unauthorised key
(measured, stock OpenSSH client); under a single 15s budget the connector ran out of time mid-exchange
and reported `Timeout` for a rejected credential. On a real estate the gap is wider — PAM fail-delays,
fail2ban and directory-backed auth reject far more slowly. `unreachable` sends someone to the network
team and `auth-failed` sends them to whoever owns credentials, so conflating them wastes the hour the
report is read in.
**Recommended.** Budget them separately. A TCP pre-flight on a short budget answers reachability;
authentication gets a generous budget because its duration is controlled by the far end. This improves
*both* properties: unreachable is detected sooner (which matters at 10,000 endpoints, where a sweep
over a dead subnet costs hosts × timeout of held connection budget) and rejection is classified
truthfully.
**Rejected.** Raising the single timeout — it only moves the cliff, and you pay the larger number on
every genuinely dead host. Also: resolving addresses sequentially. A dual-stack host whose first
address is unroutable consumes the whole budget before the second is tried, reporting an outage that
does not exist; addresses are probed concurrently, first success wins.

## 13. Proving a secret never became a managed string
**Problem.** NEVER #1/#2 require that credential material is never decoded into a managed `string` —
a .NET string is immutable, cannot be zeroed, and survives on the heap until some later collection,
so it is readable in a process dump long after the operation ends. The rule is easy to state and
**unusually hard to enforce**, because the defect is invisible at runtime: a string that was created
and later collected looks exactly like one that never existed.

**Three enforcement attempts have now failed here, each in a different way.** They are recorded
because each looked sufficient when written.

1. **A statement-scoped regex** anchored on `.Secret` appearing in the same statement as the decode.
   Splitting the offence across two lines walked past it (cold review R3).
2. **Flow analysis** (`SecretFlowScanner`) following the bytes through local assignments. Cold review
   R4 walked past it by *extracting a method*: taint is seeded from assignments, and a parameter is
   not an assignment, so `DecodeSecret(byte[] m) => Encoding.UTF8.GetString(m)` launders a private key
   with the whole suite green. Lambdas, local functions, extension methods, `out` parameters, instance
   fields and cross-file helpers all do the same. **Its doc claimed it could only over-report.**
3. **Behavioural observation** — the obvious answer, and the one to stop proposing. Two variants were
   built and measured, not argued about:
   - *Assert on the credential.* `NetworkCredential` reports a non-null, non-read-only
     `SecurePassword` of identical length whichever constructor built it, and `.Password` returns the
     plaintext either way. Green for the defect exactly as for the fix.
   - *Scan process memory for the secret as UTF-16* (a managed string is UTF-16; the legitimate
     representations here are UTF-8 bytes and a `SecureString`, so the encoding discriminates). This
     **cannot be green for correct code**, measured on this lab: SSH.NET's own key parser leaves
     **4** managed copies of every private key it reads; reading `NetworkCredential.Password` — which
     any HTTP auth stack must do — creates another; and `SecureString.AppendChar` *decrypts to append*,
     so even the correct first-party `ToSecureString` was measured leaving up to **3** transient UTF-16
     copies. Worse, it is nondeterministic: across five identical runs, one showed 4 occurrences and
     four showed 0, depending purely on whether the allocator had reused the buffers before the scan.
     An assertion that is red for correct code, red for third-party code we cannot change, and flaky
     besides does not enforce a guarantee.

**Recommended — restrict the capability instead of tracking the data.** Whatever route the bytes take,
turning them into text has to *call something that makes text*, in code we own. There are **four** such
calls in the whole connector surface. `SecretMaterialisationScanner` enumerates them and the test pins
each to a written justification; a fifth is red by default, whichever helper, lambda, field or file fed
it. This is fail-closed and shape-independent — the two properties every previous attempt lacked — and
it is cheap precisely because the surface is tiny. `SecretFlowScanner` is kept *behind* it as a second
layer, for the one thing the ban cannot see: a secret reaching one of the four calls that are allowed.

**Rejected.** Making the flow analysis interprocedural. It would close the shapes R4 happened to try
and leave the next one open — virtual dispatch, delegates in fields, reflection — and the residuals are
not enumerable, which is the argument against it. Also rejected: deleting the flow analysis once the
ban shipped; it covers the allow-listed sites, which the ban structurally cannot.

**Known limits of the guarantee, stated so nobody over-reads it.**

- It governs *first-party* code. It does **not** and cannot mean the secret is never a managed string
  in the process — SSH.NET puts every private key we load into four of them. Removing that needs a
  different key parser, not a better test, and is not currently scoped.
- **It covers the connector surface only — `src/Modules/Connectors`, `src/Shared/Contracts/Connectors`
  and `src/Shared/Contracts/Credentials`. The vault is NOT scanned.** Phase 3's scoped re-check found
  two materialising calls in Phase 2 code that the ban would have required someone to justify:
  `CredentialPayload.Read` decodes the **username** (documented as not a secret; the secret bytes stay
  a span), and `KeyFileKekSource.WriteDurablyAsync` base64s the **KEK** to write the key file — already
  recorded in Phase 2 as the KEK memory-hygiene limitation, and unavoidable given the key-file format.
  **Neither is a defect and neither is new**; both would pass with the justifications their own comments
  already carry. What is missing is the *enforcement*, so a third one could appear in the vault
  silently. Extending the ban to `src/Modules/Vault` is **D-311** — held out of Phase 3 because the
  vault is Phase 2's owned path and `PatchManagement.Connectors.Tests` deliberately has no vault
  dependency (`VaultIndependenceTests` asserts that mechanically).
