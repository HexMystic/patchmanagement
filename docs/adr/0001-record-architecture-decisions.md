# 1. Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
We need to capture significant, hard-to-reverse decisions with their rationale so a
fresh session (or a new engineer) understands *why*, not just *what*. This matters
more here than usual: the product is sold to customers and several early decisions
(multi-tenancy, key custody, contracts) are effectively permanent.

## Decision
We use **Architecture Decision Records (ADRs)** in the lightweight MADR style, one
Markdown file per decision in `docs/adr/`, numbered sequentially and never deleted
(supersede instead). Each ADR states context, the decision, and consequences.

## Consequences
- Decisions are auditable and teachable; superseded ADRs remain for history.
- A small authoring overhead per significant decision — accepted deliberately.
