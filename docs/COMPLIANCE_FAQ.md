# Compliance and IP FAQ (template)

This is an engineering template, not legal advice. Have counsel review before publishing claims.

## Licensing

| Component | License | Obligation |
| --- | --- | --- |
| mem-guard | MIT | keep the copyright notice |
| NanoMemory | MIT | keep the copyright notice |
| pydantic | MIT | notice |
| fastapi / starlette | MIT / BSD-3 | notice |
| httpx | BSD-3 | notice |
| SQLite (via Python) | public domain | none |

No GPL/AGPL code is linked. A dependency licence report can be generated with
`pip-licenses --format=markdown` in CI.

## Data handling

- **What is stored by mem-guard:** audit entries (ids, codes, counts, hashed snippets — no raw
  content), quota counters, feedback rows. Memory content lives in NanoMemory.
- **What leaves the host:** only embedding requests to the configured provider, containing
  redacted content. No telemetry is enabled by default.
- **Retention:** configurable; defaults keep audit and usage indefinitely in `state/`. Operators
  must define a retention period and prune accordingly.
- **Deletion:** deleting a memory in NanoMemory is a soft delete (state `deleted`); permanent
  purge is an operator action. Feedback referencing a deleted trace remains as an id-only record.

## Auditability

- Every allow/redact/block decision has an `audit_id` and a timestamp.
- The audit chain is verifiable at runtime (`/healthz`) and offline
  (`python -m mem_guard.cli audit verify` — planned CLI wiring; the `AuditLog.verify()` API is
  available today).
- Retrieval decisions carry NanoMemory's `trace_id`, which links to the candidate ids, scores and
  filter that produced the evidence.

## Framework mapping (not a certification)

| Requirement (NIST AI RMF / ISO/IEC 42001 themes) | Where it is addressed |
| --- | --- |
| Govern: documented roles and policies | this document, `SECURITY.md`, scope brief in NanoMemory |
| Map: intended use and affected parties | `docs/THREAT_MODEL.md` |
| Measure: monitored metrics and evaluation | quota/usage endpoints, eval set + reports in NanoMemory |
| Manage: incident response and rollback | audit chain, memory rollback, key rotation procedure |
| Data provenance and traceability | signed scope, provenance fields, trace ids |
| Human oversight for high-impact actions | trust gate + OmniCare's approval flow (refunds > 500 require a human) |

**No certification is claimed.** These are mappings to themes, useful for a security review
questionnaire, not evidence of conformity.

## Questions a customer will ask

1. *Can one tenant read another's memory?* No: tenant is part of a signed envelope enforced in
   NanoMemory's SQL pre-filter; request bodies reject scope fields; tests cover forged and
   tampered envelopes.
2. *Where is my data?* In your deployment: a SQLite file for vectors/traces and JSONL/SQLite for
   audit/quota/feedback. No external service except the embedding endpoint you configure.
3. *Can you delete my data?* Yes: soft delete via API, permanent purge by the operator; backups
   must be handled in the operator's retention policy.
4. *Do you train on my data?* No training pipeline exists in either component.
5. *What happens if the model provider is down?* Reads degrade to lexical retrieval (flagged
   `degraded=true`), writes fail closed with a retryable 503 and a pending record.
