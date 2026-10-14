"""Load the operator policy and derive the revision that approvals are bound to."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

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


@dataclass(frozen=True)
class DetectorBinding:
    """Operator-declared compatibility, checked against the actual rule inventory."""
    rules_path: Path
    policy_digest: str
    rules_digest: str
    rule_mapping: Mapping[str, str]
    scanned_fields: tuple[str, ...] = ('description',)

    def __post_init__(self):
        object.__setattr__(self, 'rules_path', Path(self.rules_path).resolve())
        object.__setattr__(self, 'rule_mapping', MappingProxyType(dict(self.rule_mapping)))
        object.__setattr__(self, 'scanned_fields', tuple(self.scanned_fields))

    def validate(self, policy_path: Path) -> None:
        from .config import ConfigurationError
        from .detector import rules_digest_of
        document = json.loads(Path(policy_path).read_text())
        raw = Path(self.rules_path).read_bytes()
        if self.policy_digest != digest(document) or self.rules_digest != rules_digest_of(raw):
            raise ConfigurationError('detector policy/rules digest mismatch')
        if self.scanned_fields != ('description',):
            raise ConfigurationError('only description scanning is supported')
        try:
            rules = json.loads(raw)['rules']
        except (ValueError, KeyError):
            try:
                import yaml
            except ImportError:
                raise ConfigurationError('YAML rules require the semgrep extra (PyYAML)') from None
            rules = yaml.safe_load(raw)['rules']
        inventory = {}
        for rule in rules:
            rule_id, policy_id = rule['id'], rule.get('metadata', {}).get('policy_id')
            if rule_id in inventory or not isinstance(policy_id, str):
                raise ConfigurationError('duplicate rule or missing policy metadata')
            inventory[rule_id] = policy_id
        known = {r['id'] for r in document['rules']}
        required = {r['id'] for r in document['rules'] if r.get('hard_deny_condition')}
        if inventory != self.rule_mapping or set(inventory.values()) - known or required - set(inventory.values()):
            raise ConfigurationError('undeclared, missing, or incompatible deterministic coverage')

    def scan(self, tools, policy_path, *, cancel_event=None, timeout_seconds=120.0):
        from .detector import scan_tools
        self.validate(policy_path)
        result = scan_tools(tools, rules_path=self.rules_path,
                            known_policy_ids=policy_rule_ids(policy_path),
                            cancel_event=cancel_event, timeout_seconds=timeout_seconds)
        if result.rules_digest != self.rules_digest:
            from .detector import DetectorError
            raise DetectorError('scanned rules changed from declared binding')
        return result
