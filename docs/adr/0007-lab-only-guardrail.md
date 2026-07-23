# 7. Lab-only endpoint guardrail (localhost-only SSH, WinRM denied)

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
CLAUDE.md NEVER #4: never target a non-lab machine during development. We want this
enforced by tooling, not discipline. An earlier attempt tried to have a permission
rule *dynamically parse* `/lab/docker-compose.yml` to allow only its hosts — but
Claude Code permission rules are static globs and cannot read a file, and the
precedence is **deny > allow**, so "allow localhost SSH, deny all other SSH" cannot
be expressed as pure globs (a broad ssh-deny would also block localhost).

## Decision
Enforce with **static logic**, two layers:
1. A **PreToolUse hook** (`.claude/hooks/lab_only_guard.py`, fail-closed) that allows
   `ssh`/`scp`/`sftp` **only** when the target host is `localhost` / `127.0.0.1` /
   `::1`, and **denies all WinRM** (`Enter-PSSession`, `New-PSSession`,
   `Invoke-Command -ComputerName`, `Connect-WSMan`, `winrs`). No compose parsing.
2. **Static permission `deny` rules** in `.claude/settings.json` for the WinRM
   cmdlets and destructive commands (globs work for these).

Because the lab fleet is published on `localhost` ports (ADR 0004), localhost-only =
lab-only in practice, and it is actually enforceable.

## Consequences
- Dev sessions cannot SSH to a non-localhost host or invoke WinRM at all.
- When real remote Windows targets arrive, they run through the product's connector
  (out of band from the dev shell), not ad-hoc `Invoke-Command` — the guard stays.

## Rejected
- **Dynamic compose-parsing permission rule** — impossible with static globs; fragile.
- **Deny all SSH+WinRM outright** — also blocks the localhost lab we must reach.
