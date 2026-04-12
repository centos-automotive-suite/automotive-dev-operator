# 1. Use Architecture Decision Records

Date: 2026-04-12

## Status
Accepted

## Context
Architectural decisions in this project (Tekton integration, operator patterns,
build strategies) are currently undocumented beyond code comments and commit
messages. New contributors lack context on why certain approaches were chosen.

## Decision
We will use Architecture Decision Records (ADRs) as described by Michael Nygard
to document significant architectural decisions. ADRs are stored in `docs/adr/`
and numbered sequentially.

## Consequences
- Decisions are documented with context and rationale
- Future contributors understand why things are the way they are
- ADRs are lightweight, version-controlled Markdown files
- Each significant decision gets its own record
