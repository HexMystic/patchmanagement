# 5. CQRS via an in-house minimal mediator (no MediatR / AutoMapper)

- **Status:** Accepted
- **Date:** 2026-07-24

## Context
We use CQRS. MediatR is the usual dispatcher and AutoMapper the usual mapper, but
**both moved to commercial licensing in 2025**. This product is *sold to customers*;
taking a paid runtime dependency (and its licensing/compliance burden) for something
we can trivially own is a poor trade. CLAUDE.md also forbids black-box mapping.

## Decision
Implement a **~100-line first-party dispatcher**: `IRequest<T>`,
`IRequestHandler<TReq,TRes>`, an `ISender` resolved from DI, and an ordered
**pipeline behavior** interface for cross-cutting concerns (validation, logging,
tenant context, transactions). **Mapping is explicit hand-written code** (or source
generators), never a reflection-based mapper.

## Consequences
- No third-party license exposure; full control of the pipeline.
- Small maintenance surface we own; explicit, debuggable mapping.

## Rejected
- **MediatR + AutoMapper** — commercial license + dependency for a sold product.
- **Pin old free MediatR versions** — dead-ends on security fixes; still a black box.
