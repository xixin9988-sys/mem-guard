# Security policy and threat model

mem-guard sits between an application (OmniCare) and NanoMemory's vector store. It authenticates
the calling service, proves tenant scope to the memory engine, screens content, enforces budgets,
and records a tamper-evident audit trail. This document states what that does and does not
protect against.

Report a vulnerability privately to the maintainers; do not open a public issue with a working
exploit.

## Trust boundaries

```text
end user --(session, JWT)--> OmniCare BFF --(service key + scope)--> mem-guard --(HMAC scope)--> NanoMemory
                                    |                                    |                          |
                              user identity                     policy, quota, audit        vector store
```

- End users never reach mem-guard directly and never hold its service key.
- mem-guard never accepts a tenant/user from a request body; it reads the scope headers asserted
  by the authenticated service and re-signs them for NanoMemory.
- NanoMemory only accepts scope from a valid HMAC envelope, so even a process that can reach
  NanoMemory's port cannot choose a tenant without the shared key.

## Threats and controls

| # | Threat | Control | Residual risk |
| --- | --- | --- | --- |
| T1 | Cross-tenant read via a forged filter | Scope is signed (HMAC-SHA256, timestamped, 300 s window) and NanoMemory applies it in SQL before similarity; request bodies reject scope fields | A leaked signing key breaks the boundary — rotate it and restrict network access to the two services |
| T2 | Cross-tenant read via a client bug | Tenant is not a parameter anywhere in the public API | A compromised OmniCare can assert any tenant it serves; that is the service's responsibility |
| T3 | Memory poisoning (instructions stored as memory) | Injection detector on write and on query, hash-chained audit, quarantine-by-rejection, provenance/trust labels | Detection is heuristic; sophisticated payloads can pass. Trust labels keep model/tool text from being treated as user facts |
| T4 | PII/secret leakage into vectors, traces or the embedding provider | PII/secret scan **before** embedding, redaction or block mode, findings stored without the raw value | Regex detection misses unusual formats and free-form identifiers |
| T5 | Unauthorized data exfiltration through retrieved context | Retrieval returns evidence only; the answer guard checks identifiers/dates/amounts against it; trust gate drops untrusted rows for strict consumers | Semantic leaks (a paraphrase with no shared entity) are not detected |
| T6 | Cost abuse / runaway loops | Per-tenant/user token bucket (429 + Retry-After), daily token and write/read budgets (429 `quota_exceeded`), token accounting per call | Multi-replica deployments multiply the in-memory rate limit; the shared ledger still caps daily spend |
| T7 | Audit tampering | Each entry hashes the previous one; `/healthz` verifies the chain; a broken link is reported with its line number | An attacker with write access can truncate the whole file; ship logs to append-only storage for strong guarantees |
| T8 | Feedback poisoning | Feedback must reference an existing trace owned by the tenant; badcases are exported as candidates, not auto-merged into the eval set | A malicious user can still downvote; rate limits and trace ownership bound the impact |
| T9 | Replay of a signed context | Signatures carry a timestamp and NanoMemory rejects envelopes older than `NANOMEMORY_CONTEXT_SIGNING_MAX_AGE_SECONDS` | Within the window a captured envelope is replayable; use TLS and short windows |
| T10 | Dependency compromise | Small dependency surface (pydantic, fastapi, httpx), pinned minimums, no dynamic plugin loading | Standard supply-chain risk remains |

## Defaults

- Fail closed in production: `MEM_GUARD_ENVIRONMENT=production` requires the service key, the
  NanoMemory signing key, and `MEM_GUARD_ALLOW_DEFAULT_SCOPE=false`. Startup aborts otherwise.
- No secrets in logs: the service key and signing key are never printed; audit entries contain
  lengths, codes and ids, not raw content.
- Secrets in memory content are redacted **before** the embedding call, so they never reach the
  provider or the vector store.
- CORS is not enabled on the gateway; it is an internal service.

## What mem-guard does not do

- It is not an identity provider: it trusts the authenticated service's scope assertion.
- It is not a DLP product: the scanner is a pragmatic regex set, not a classifier.
- It does not encrypt data at rest; use full-disk or database encryption.
- It does not guarantee that a retrieved memory is *true* — only that it is in scope, labelled and
  retrievable with a trace.
