# ADR-0035: Canonical relational evidence with rebuildable graph/search projections

- **Status:** Accepted
- **Date:** 2026-10-07
- **Decision class:** Architecture invariant with multiple derived graph formats
- **Affected components:** Observatory persistence, graph traversal, RDF interoperability, search
- **Security properties affected:** provenance consistency, auditability, projection integrity

## Context

Observatory workloads need strong transactional integrity, provenance traversal and fast search.

A relational database is well suited to canonical constraints and atomic ingest. Property graphs are convenient for traversal. RDF/PROV is valuable for standards interoperability. Search engines are optimized for retrieval.

Making all stores authoritative would create synchronization and conflict-resolution problems.

## Serious alternatives considered

### Graph-native canonical store

Rejected as the canonical contract. Graph databases remain excellent projection targets, but making the graph authoritative weakens portability of relational integrity/transaction requirements and creates vendor-specific semantics.

### Search/document-native canonical store

Rejected. Search indexes are optimized derived data structures and are routinely rebuilt.

### Triple store as the only canonical representation

Rejected as the only model, but implemented as a first-class W3C PROV RDF projection.

### Relational canonical model with rebuildable projections

Accepted.

## Decision

The canonical logical store is relational and append-only.

Two serious graph forms are implemented:

- operational property graph; and
- standards-oriented W3C PROV RDF triples.

Search documents are generated independently.

All projections are deterministic, versioned and bound to the source bundle/row-set digests.

## Security consequences

A corrupted or stale projection can be discarded and rebuilt without losing evidence.

The tradeoff is projection lag and additional storage/compute.

Applications must surface projection freshness rather than silently presenting stale data as current.

## Compatibility constraints

Projection vendors are non-normative.

PostgreSQL DDL is a reference implementation, not a product mandate.

PR 36 confidence/classification records must enter through canonical relational evidence before appearing in graph/search projections.

## Reconsideration triggers

Re-open if a later portable datastore standard can provide equivalent append-only relational constraints plus graph/search semantics without multi-store projection risk.
