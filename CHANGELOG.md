# Changelog

## 2.0.0 — 2026-11-27

### Added

- **Gateway** (`mem_guard.server:app`) in front of NanoMemory's vector store:
  `/v1/guard/remember`, `/v1/guard/recall`, `/v1/guard/feedback`,
  `/v1/guard/grounding/check`, `/v1/guard/quota`, `/healthz`.
- **Signed tenant scope**: HMAC-SHA256 envelope (`X-NM-*`) shared with NanoMemory, golden-vector
  tested on both sides; request bodies cannot carry scope.
- **Prompt-injection detector** (English + Chinese patterns, weighted scoring, severity).
- **Content safety**: secrets/PII detection with redaction or block mode, before embedding.
- **Quota**: per-tenant/user token bucket + daily SQLite ledger for writes, searches, embedding
  and retrieval tokens, with `429` and `Retry-After`.
- **Hash-chained audit log** with `verify()` and per-line tamper reporting.
- **Feedback ledger** bound to `trace_id`, outage-tolerant (`forwarded=false`).
- **Grounded-answer guard**: identifiers, dates and amounts in an answer must appear in the
  evidence; question entities must be covered; deterministic, audited.
- **Docs**: `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/GATEWAY.md`,
  `docs/COMPLIANCE_FAQ.md`.

### Changed

- Package version 2.0.0; adds `pydantic>=2.7` as a dependency and a `gateway` extra
  (fastapi, httpx, uvicorn). The governance library keeps its zero-dependency behaviour.

### Compatibility

- `Guard`, `Memory`, `Policy`, `Provenance`, `TrustLevel` are unchanged; existing tests pass.

## 0.1.1

- Issuer attestation, atomic supersede, consumer policy, audit log, ConflictReport.
