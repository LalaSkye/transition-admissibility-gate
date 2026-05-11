# Claim Boundary

Date: 2026-05-11
Repository: `LalaSkye/transition-admissibility-gate`

## Purpose

This file keeps the repository's claim surface bounded to the implemented and tested mutation-boundary demonstration.

## Allowed claims

This repository may be described as:

- a bounded artefact
- a path-local demonstration
- a fail-closed mutation-boundary surface
- a live-state admissibility demonstration
- a testable transition-control primitive
- a governed write-path example

## Mechanism claim

Safe wording:

> `transition-admissibility-gate` demonstrates that a valid authority record is necessary but not sufficient: the proposed state transition must still be admissible under current state at the mutation boundary.

## Evidence claim

Safe wording:

> The repository provides code and tests for a demonstrated governed path where invalid transitions are denied before mutation.

## Forbidden claims

Do not claim:

- adoption
- validation
- endorsement
- certification
- compliance
- production readiness
- field impact
- proven market demand
- path-universal coverage
- standardisation
- atomic audit custody
- control over all possible deployed mutation routes

## Known gap boundary

The repository currently records a v1 hardening gap around mutation-before-nonce and mutation-before-audit ordering.

Therefore, do not claim atomic proof / replay / audit ordering until the implementation and tests prove it.

## Public sentence

> This is a bounded mutation-boundary demonstration: authority must still resolve against live-state admissibility before consequence is allowed.

## Stop line

If the evidence is not in code, tests, README, receipt, or release, do not claim it.
