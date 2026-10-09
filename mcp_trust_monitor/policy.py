"""Load the operator policy and derive the revision that approvals are bound to."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .revision import digest


@dataclass(frozen=True)
class PolicyRef:
    policy_id: str
    revision: str
    digest: str

    @property
    def binding(self) -> str:
        """Value stored with each approval. Any edit to the policy document changes it."""
        return f"{self.policy_id}@{self.revision}#{self.digest}"


def load_policy(path: Path) -> PolicyRef:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return PolicyRef(
        policy_id=document["policy_id"],
        revision=str(document["revision"]),
        digest=digest(document),
    )


def policy_rule_ids(path: Path) -> frozenset[str]:
    """Rule IDs in the loaded policy; detector matches must cite one of them."""
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return frozenset(rule["id"] for rule in document["rules"])
