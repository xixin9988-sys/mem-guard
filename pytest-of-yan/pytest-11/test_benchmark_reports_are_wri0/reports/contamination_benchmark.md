# Contamination benchmark

- seeded memories: 8
- queries: 3
- state distribution: {"quarantined": 8}
- partitions: {"quarantine": 8}

| metric | naive | governed | better |
| --- | --- | --- | --- |
| valid hit rate | 1.0 | 0.0 | higher |
| contamination rate | 1.0 | 0.0 | lower |
| stale value served | 0.3333 | 0.0 | lower |
| hallucination served | 0.6667 | 0.0 | lower |
| injection served | 0.3333 | 0.0 | lower |
| trust violations | 0 | 0 | lower |

Seeded failures: outdated (`port 5000`), contradictory (`port 9000`), hallucinated
(`written in Go / MongoDB`, model inference without evidence) and prompt injection
(`Ignore previous instructions…`, external document without evidence).

Mock-free: the benchmark is deterministic and uses no model provider.
