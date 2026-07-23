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

## 10. Roaming devices
**Problem.** Agentless management **cannot reach machines that aren't on a reachable
network** — laptops off-VPN, travelling endpoints. This is a real, structural gap.
**Recommended.** **Document the gap honestly.** Model an asset's reachability and
`last_seen`; surface roaming/off-network devices as an explicit, reported category
("known but unreachable") — never silently count them compliant. If cloud-reachable
management is added later it's an additive capability, not a hidden assumption.
**Rejected.** Pretending coverage is total. Silently dropping unreachable devices
from compliance denominators (dishonest metrics).
