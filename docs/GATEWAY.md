# Gateway operations and API

## Run it

```bash
pip install -e ".[gateway]"
export MEM_GUARD_ENVIRONMENT=development
export MEM_GUARD_NANOMEMORY_URL=http://127.0.0.1:8000
export MEM_GUARD_CONTEXT_SIGNING_KEY=dev-shared-secret   # must equal NanoMemory's key
uvicorn mem_guard.server:app --host 127.0.0.1 --port 8080
```

Production:

```bash
export MEM_GUARD_ENVIRONMENT=production
export MEM_GUARD_SERVICE_API_KEY=...            # OmniCare -> mem-guard
export MEM_GUARD_CONTEXT_SIGNING_KEY=...         # mem-guard -> NanoMemory
export MEM_GUARD_ALLOW_DEFAULT_SCOPE=false
export MEM_GUARD_STATE_DIR=/var/lib/mem-guard
```

Startup fails if any of those is missing — that is deliberate.

## Write

```bash
curl -s -X POST http://127.0.0.1:8080/v1/guard/remember \
  -H 'Authorization: Bearer service-key' \
  -H 'X-Guard-Tenant: acme' -H 'X-Guard-User: u-1' -H 'X-Guard-Acl: team-a' \
  -H 'Content-Type: application/json' \
  -d '{"content":"客户电话 13800001234，订单 A1001 已签收。","category":"order","source_kind":"user"}'
```

```json
{
  "record": {"id": "vec-…", "state": "active"},
  "trace_id": "tr-…",
  "guard": {
    "decision": "redact",
    "redacted": true,
    "safety": [{"kind": "cn_phone", "severity": "medium", "snippet": "13***34"}],
    "quota_remaining": {"embedding_tokens": 199988, "...": 0},
    "audit_id": "aud-…"
  }
}
```

## Recall

```bash
curl -s -X POST http://127.0.0.1:8080/v1/guard/recall \
  -H 'Authorization: Bearer service-key' \
  -H 'X-Guard-Tenant: acme' -H 'X-Guard-User: u-1' \
  -d '{"query":"A1001 的运单号","limit":5,"min_trust":"user_provided"}'
```

The response carries the evidence and NanoMemory's `trace_id`; `guard.trust_filtered` says how
many rows were dropped by the trust gate. `insufficient_context=true` means: tell the user the
memory does not contain an answer.

## Grounding check

Call this after generation, before showing the answer:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/guard/grounding/check \
  -H 'Authorization: Bearer service-key' \
  -H 'X-Guard-Tenant: acme' -H 'X-Guard-User: u-1' \
  -d '{"question":"C9999 的状态？","answer":"C9999 已发货。","evidence":["A1001 已签收。"]}'
```

```json
{"action":"insufficient_evidence","reasons":["question_entity_not_in_evidence"],
 "missing_question_entities":["C9999"],"question_coverage":0.0,"audit_id":"aud-…"}
```

Actions: `allow`, `insufficient_evidence` (show "not in memory"), `block` (the answer asserts
something the evidence does not contain), `repair` (reserved).

## Quota

```bash
curl -s http://127.0.0.1:8080/v1/guard/quota \
  -H 'Authorization: Bearer service-key' -H 'X-Guard-Tenant: acme' -H 'X-Guard-User: u-1'
```

```json
{"day":"2026-11-27",
 "limits":{"writes":20000,"searches":50000,"embedding_tokens":200000,"retrieval_tokens":500000},
 "used":{"writes":12,"searches":40,"embedding_tokens":1830,"retrieval_tokens":9200},
 "remaining":{"writes":19988,"searches":49960,"embedding_tokens":198170,"retrieval_tokens":490800}}
```

## Error envelope

```json
{"code":"rate_limit_exceeded","message":"…","details":{"limit_per_minute":120},"request_id":"…"}
```

| Code | HTTP | Retry |
| --- | --- | --- |
| `guard_auth_required` / `guard_auth_invalid` | 401 | no |
| `guard_scope_required` / `guard_scope_invalid` | 400 | no |
| `prompt_injection_detected` | 422 | no |
| `sensitive_content_blocked` | 422 | no |
| `trace_not_found` | 404 | no |
| `rate_limit_exceeded` / `quota_exceeded` | 429 + Retry-After | yes |
| `embedding_failed` | 503 (from NanoMemory) | yes, after fix |
| `nanomemory_unavailable` | 502 | yes |

## Retention and rotation

- `state/audit.jsonl` — append-only; rotate by renaming and starting a new chain. Keep the old
  file for the audit period.
- `state/usage.db` — daily counters; prune rows older than the billing window.
- `state/feedback.db` — feedback rows; export badcases to the eval set before pruning.
- Rotate the signing key by setting the new value on both services in the same deployment; the
  envelope carries no key id, so overlapping keys are not supported.
