# mem-guard × NanoMemory — Governance Contract v1

Status: **proposal; pending owner approval**  
Date: 2026-11-27  
Dependency direction: NanoMemory owns memory records and embeddings; mem-guard owns governance decisions and policy compilation.

## 1. Product boundary

NanoMemory is the system of record for canonical memory content, provenance, lifecycle, embedding profiles, vector indexes and retrieval execution.

mem-guard is a storage-agnostic governance SDK. It decides whether a memory may be admitted, read, exposed to a caller or used for a proposed action. It does not become a second memory database, does not own vector embeddings and must not duplicate NanoMemory's storage lifecycle.

The two projects compose through a typed, versioned contract. A memory record may be semantically similar to a query and still be denied by governance.

## 2. Security invariants

1. Authentication establishes the principal. A request body, memory text, model output or embedding cannot establish identity.
2. Authorization is distinct from trust. Trust answers "what is the origin/evidence of this record?"; authorization answers "may this principal access it?"
3. Access constraints are compiled before retrieval and resolved to physical security domains; NanoMemory must search only authorized ANN partitions.
4. A shared global HNSW index plus a WHERE/RLS predicate is not sufficient to claim pre-ANN isolation: pgvector approximate-index filters may be applied after the index scan, and shared indexes can affect other tenants' recall and latency. Use partition pruning into authorized domains, an exact filtered scan for finer ACLs, or deny.
5. Post-filtering a global nearest-neighbour result in Python is not an acceptable tenant or document-security boundary.
5. Missing identity, missing policy, unknown fields, invalid policy version or repository inability to apply a filter must fail closed.
6. Model-generated memory or tool output cannot grant itself a higher trust level, role or scope.
7. A policy decision is attributable to a version, rule IDs, actor, resource scope, decision and reason code.
8. A failed governance service must not silently fall back to an allow-all policy.

## 3. Typed contract

Introduce versioned, Pydantic-validated contracts (names illustrative until implementation):

### AuthorizationContext
- tenant_id: required authenticated tenant
- subject_id: required authenticated user or service principal
- roles: server-verified role set
- scopes: server-verified permission scopes
- collection_ids: permitted collections
- session_id: optional conversation session
- purpose: operation purpose (recall, explain, update, export, delete)
- policy_version: resolved immutable policy version
- request_id: correlation ID

### MemoryDescriptor
- memory_id
- tenant_id
- owner_user_id
- collection_id
- memory_type
- source_type and provenance reference
- trust_level
- lifecycle_state
- sensitivity classification
- metadata labels

No raw embedding is required by mem-guard. The policy engine should operate on stable metadata and a constrained access context, not on vector values.

### RetrievalFilterPlan
A typed, immutable plan, not caller-supplied SQL:
- mandatory tenant ID
- allowed owner IDs / collection IDs
- allowed security_domain_ids (mandatory for ANN access)
- allowed lifecycle states
- allowed trust levels
- sensitivity constraints
- policy version and matched rule IDs
- deny reason / human confirmation requirement where applicable

The NanoMemory repository translates this plan into SQL predicates and PostgreSQL RLS context. mem-guard must never return arbitrary SQL fragments for direct execution.

### GovernanceDecision
- decision: ALLOW | DENY | REQUIRE_CONFIRM | QUARANTINE
- reason_code
- policy_version
- matched_rule_ids
- evaluated_at
- decision_id
- audit metadata

## 4. Retrieval handshake

1. OmniCare or another trusted BFF authenticates the caller.
2. NanoMemory receives a signed or otherwise verified service identity and a request-scoped AuthorizationContext.
3. mem-guard validates the context and compiles a RetrievalFilterPlan.
4. NanoMemory verifies the policy version, mandatory tenant binding and allowed security_domain_ids.
5. NanoMemory uses partition pruning so only authorized security-domain partitions participate in ANN retrieval; it applies remaining owner/status/trust predicates in SQL and RLS as defence in depth. For ACLs that do not align with a security domain, it uses exact filtered search or denies.
6. Only authorized candidates proceed to rank fusion, reranking and context packing.
7. The result includes policy version, decision IDs and score breakdown, but only permitted records.
8. Both systems emit correlated audit events using the same request/run ID.

If mem-guard is unavailable, NanoMemory must use an explicitly configured local deny-by-default policy for self-hosted mode or return a dependency error. It must never widen access automatically.

## 5. Lifecycle alignment

mem-guard maps its governance state to the canonical NanoMemory lifecycle without silently mutating NanoMemory records:
- model inference or unverified import -> candidate / pending_confirmation / quarantined according to policy;
- confirmed user or verified evidence -> may be admitted as active;
- conflicting evidence -> conflict or review decision;
- superseded and archived records remain historical but are excluded from default recall;
- rollback and restore are explicit compensating operations with a reason and audit entry.

mem-guard may recommend a transition. NanoMemory's transactional lifecycle service validates and commits it. This prevents two systems from disagreeing about which state is authoritative.

## 6. API and SDK changes

Add a stable governance API at the SDK boundary:
- validate_memory(memory_descriptor, authorization_context)
- compile_retrieval_filter(authorization_context, operation)
- authorize_action(action, arguments, authorization_context)
- evaluate_input(text, authorization_context)
- evaluate_output(text, authorization_context)
- explain_decision(decision_id, authorization_context)

Every method returns a typed decision and stable reason code. Compatibility wrappers may preserve current Guard methods for a deprecation window, but new methods must not overload trust labels as access permissions.

Persist policy packs and decision audits independently from memory content. If persistence is offered, state clearly which backend is durable; do not advertise Guard(path=...) or cross-process durability until it is implemented and tested.

## 7. Required tests

### Unit and contract
- Valid and invalid AuthorizationContext schema.
- Unknown roles, scopes and policy versions rejected.
- Policy compilation produces deterministic, immutable filter plans.
- Conflicting equal-priority rules return REQUIRE_CONFIRM.
- Model-derived trust can never become user-verified through model-supplied fields.
- Filter plan cannot remove mandatory tenant or owner predicates.

### Integration with PostgreSQL + pgvector
- Two tenants seed semantically identical vectors; tenant A query never sees tenant B candidate.
- A user with access to one collection cannot see a near-identical result in another collection.
- Quarantined, archived, superseded and pending-confirmation memories are excluded according to policy before ranking.
- Missing policy or DB filter application causes fail-closed behaviour.
- RLS remains effective when application-level predicates are accidentally omitted.
- Audit records include policy version and matched rule IDs without leaking hidden content.

### Regression / attack
- Prompt injection inside memory content cannot change tools, identity or policy.
- Crafted metadata and provenance cannot elevate trust.
- Malformed or stale filter plans are rejected.
- A simulated mem-guard outage never falls back to allow-all.
- Replayed request IDs / duplicate transitions remain idempotent.

## 8. User stories and Given / When / Then

### US-G01 — Pre-retrieval permission
- Given tenant A and tenant B store semantically identical memories, when tenant A recalls, then only tenant A-authorized IDs enter the vector candidate set.
- Given a principal permitted to collection X but not Y, when it recalls a query matching a record in Y, then the database excludes Y before ranking.
- Given an absent or stale policy, when recall is requested, then the result is DENY or dependency failure and no candidate content is returned.

### US-G02 — Trust and authorization remain separate
- Given a user-provided memory that is private to its owner, when a different user asks for it, then verified provenance does not override access denial.
- Given a model-inferred memory with no confirmation, when an agent recalls, then it remains pending/quarantined according to policy.
- Given a validly authenticated user requests a restricted action, when policy denies it, then the action is not executed and an audit decision is recorded.

### US-G03 — Auditable policy changes
- Given an active policy version, when a new version is published, then in-flight requests retain their resolved version and new requests use the new version.
- Given a rule conflict with equal specificity, when the compiler evaluates it, then it returns REQUIRE_CONFIRM and identifies conflicting rule IDs.
- Given a policy rollback, when the prior version is reactivated, then the rollback is itself recorded and never erases prior decisions.

## 9. Non-goals

- Storing memory text, embeddings or ANN indexes.
- Replacing NanoMemory's record lifecycle or SQL transactions.
- Building an LLM-based semantic truth detector.
- Generating arbitrary SQL from policy rules.
- Owning end-user authentication or issuing end-user JWTs.
- Claiming a synthetic benchmark proves production security.

## 10. Release gates

- Public API types and compatibility policy documented.
- Contract tests pass against the exact supported NanoMemory release.
- Tenant and collection isolation tests pass against PostgreSQL + pgvector.
- EXPLAIN-plan tests verify only allowed partitions are scanned; shared global ANN indexes are not accepted for mutually isolated scopes.
- Fine-grained ACL fallback uses exact filtered search or fails closed, never post-filters a global ANN result.
- No retrieval route can bypass the compiled access plan.
- Policy failure is fail-closed and observable.
- Policy decision traces and audit retention are documented.
- README accurately states persistence and supported deployment scope.
