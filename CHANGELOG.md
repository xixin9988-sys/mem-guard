# Changelog

## [0.1.1] - 2026-11-10

### Fixed (from external review)
- Issuer attestation: a caller can no longer mint `user_verified` by writing `source=`; only registered `Issuer`s may assert source kinds.
- Atomic conflicts: a memory entering `CONFLICT` no longer supersedes the older ACTIVE memory.
- Consumer authorization is enforced from the precompiled policy (`search(..., consumer=...)`), inspectors can read quarantine.
- Append-only audit log (`Guard.audit()`, `explain()` includes audit) persisted with the store.
- Structured `ConflictReport` for rule conflicts (rule ids, scopes, triggers, priorities, suggested resolution).
- Benchmark metrics: contamination/trust violations are now per served item and per strategy, not per query and not a second `search()` call.

### Added
- `MemoryStore` protocol and `JsonFileStore` (temp → fsync → replace); `Guard(path=...)` survives restarts.

## [0.1.0] - 2026-11-10

Initial release: provenance validator, state governance, trust partitions, consolidation gate, rule compiler, contamination benchmark.
