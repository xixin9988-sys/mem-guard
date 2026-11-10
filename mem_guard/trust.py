"""Trust & Policy Engine: precompiled labels and partitions instead of recall-time ACLs.

Policy is decided when a memory is written. Retrieval then picks *partitions* (three dicts in
the store) and compares a precomputed integer trust rank — it never re-evaluates rules per
candidate.
"""

from __future__ import annotations

from dataclasses import dataclass

from mem_guard.models import Partition, Policy, TrustLevel, trust_rank

QUARANTINE_PARTITION = Partition.QUARANTINE


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    policy: Policy
    partition: Partition
    trust_rank: int


class PolicyEngine:
    """Derive and precompile policy for a memory, and enumerate readable partitions."""

    def compile(
        self,
        trust: TrustLevel,
        *,
        confidence: float,
        quarantine: bool,
        verified: bool = False,
    ) -> CompiledPolicy:
        if quarantine or trust is TrustLevel.UNTRUSTED:
            partition = Partition.QUARANTINE
        elif verified or trust is TrustLevel.USER_VERIFIED:
            partition = Partition.SHARED
        elif trust is TrustLevel.USER_STATED and confidence >= 0.8:
            partition = Partition.PRIVATE
        else:
            partition = Partition.PRIVATE

        consumers = frozenset({"*"}) if partition is not Partition.QUARANTINE else frozenset()
        policy = Policy(
            allowed_consumers=consumers,
            min_trust=trust,
            retention="long" if trust is TrustLevel.USER_VERIFIED else "standard",
            note=None if partition is not Partition.QUARANTINE else "quarantined content",
        )
        return CompiledPolicy(policy=policy, partition=partition, trust_rank=trust_rank(trust))

    @staticmethod
    def partitions_for(require_trust: TrustLevel | str) -> frozenset[Partition]:
        """Partitions a reader at ``require_trust`` may search.

        Quarantine is only visible to a reader that explicitly requires ``untrusted``
        material (an inspector), never to normal agents.
        """
        rank = trust_rank(require_trust)
        if rank >= trust_rank(TrustLevel.USER_STATED):
            return frozenset({Partition.SHARED, Partition.PRIVATE})
        if rank == trust_rank(TrustLevel.MODEL_INFERRED):
            return frozenset({Partition.PRIVATE})
        return frozenset({Partition.QUARANTINE, Partition.PRIVATE})
