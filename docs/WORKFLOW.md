# WORKFLOW — How to run sessions

How work actually gets done in this repo: starting a phase, choosing a parallelism
level, merging safely, and keeping `ROADMAP.md` honest.

## 1. Starting a phase
1. Open `docs/ROADMAP.md`; pick the next phase whose **dependencies are `complete`**
   and whose **mode** is compatible with what's already in flight (a `solo` phase
   must run alone; **Phase 8 is SOLO**).
2. Read that phase's detail (`docs/phases/phase-N.md` where it exists) and any ADRs
   it references.
3. Set the phase **Status → in-progress** in ROADMAP (commit that change).
4. Work to the phase's **exit criteria**. Nothing is "done" early (CLAUDE.md §6).

## 2. The four parallelisation levels — when to use each

| Level | Mechanism | Use when | Avoid when |
|-------|-----------|----------|-----------|
| **1. Manual worktree** | `git worktree add ../pm-<phase> -b phase/<n>` | You want a second phase in a separate checkout you drive by hand | The phase is `solo` |
| **2. `claude --worktree`** | Launch Claude in its own worktree | One focused phase, isolated from your main checkout, you supervise | You need many at once |
| **3. Dispatched background subagents** | Agent tool w/ per-agent **worktree isolation** | Several **parallel-safe** phases fan out at once (e.g., 2,3,5 after 1) | Phases share owned paths, or any is `solo` |
| **4. `/batch`** | Batched task runner | Many small, uniform, independent edits across the tree | Work needs judgement/coordination or touches contracts |

Rules of thumb: **never** run two phases that own overlapping paths concurrently;
**never** parallelise a `solo` phase; prefer level 3 for the post-Phase-1 fan-out
(2/3/5 are parallel-safe), and reserve level 4 for mechanical sweeps.

## 3. Infrastructure & per-worktree setup
- **Only the main worktree runs Docker infra** (root `docker-compose.yml`: Postgres,
  Redis). Other worktrees **connect to it** over `localhost` — they do **not** start
  their own pg/redis. The `/lab` fleet likewise runs once, from main.
- Each new **.NET worktree**: run `dotnet restore` before building.
- Each new **web worktree**: run `npm install` before building.
- `.worktreeinclude` propagates `.env`, `.env.local`, local config, and `/lab/keys`
  into new worktrees so they're immediately usable (these are gitignored).

## 4. The merge sequence (strict)
When multiple worktrees have finished parallel phases, integrate them **one at a
time**, never all at once:

1. **Merge one branch → `main`.**
2. **Run tests on `main`.** If red, fix or revert before proceeding.
3. **Rebase each remaining worktree onto the new `main`.**
4. **Test each rebased worktree in isolation** (its own checkout, connecting to the
   main infra stack).
5. **Merge the next branch → `main`**, and repeat from step 2.

This guarantees `main` is always green and each branch is validated against the
latest integrated state before it lands.

## 5. Closing a phase
- Confirm every **exit criterion** is met and tests pass.
- Set the phase **Status → complete** in `docs/ROADMAP.md`; note anything deferred.
- If the phase produced a significant decision, add an ADR under `docs/adr/`.
- If it changed a contract, that required a prior explicit ask (CLAUDE.md §6) — record it.
