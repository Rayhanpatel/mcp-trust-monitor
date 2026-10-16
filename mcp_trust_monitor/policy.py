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


# Approvals, generations and selection tokens bind the policy binding plus this
# detector segment (REQ-TRU-02, REQ-DEC-06). Bindings written before the segment existed
# never equal one that has it, so either binary treats the other's decisions as a
# genuine change and fails closed.
DETECTOR_SEGMENT = "|detector="
DETECTOR_DISABLED = "disabled"


def decision_binding(policy: PolicyRef, detector: object | None) -> str:
    """The decision context approvals, generations and selection tokens are bound to.

    The policy binding plus the active detector's identity, or `disabled`. Changing the
    policy document, the declared rules, their mapping or scanned fields, or enabling or
    disabling detection, is a genuine change. Equal declarations are the same binding
    wherever the rules file is stored. Raises `ConfigurationError` for a detector that
    declares no rules digest, before anything is activated.
    """
    return policy.binding + DETECTOR_SEGMENT + _detector_identity(detector)


def _detector_identity(detector: object | None) -> str:
    if detector is None:
        return DETECTOR_DISABLED
    if isinstance(detector, DetectorBinding):
        return detector.binding_digest
    from .config import ConfigurationError
    rules_digest = getattr(detector, "rules_digest", None)
    if not isinstance(rules_digest, str) or not rules_digest:
        raise ConfigurationError("a configured detector must declare its rules digest")
    try:
        declaration = {
            "kind": f"{type(detector).__module__}.{type(detector).__qualname__}",
            "policy_digest": getattr(detector, "policy_digest", None),
            "rules_digest": rules_digest,
            "rule_mapping": {str(key): str(value)
                             for key, value in dict(getattr(detector, "rule_mapping", None) or {}).items()},
            "scanned_fields": [str(field) for field in getattr(detector, "scanned_fields", None) or ()],
        }
        return digest(declaration)
    except (TypeError, ValueError):
        raise ConfigurationError("the configured detector declaration is not serializable") from None


def load_policy(path: Path) -> PolicyRef:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return PolicyRef(
        policy_id=document["policy_id"],
        revision=str(document["revision"]),
        digest=digest(document),
    )


_BINDING_FIELDS = {"rules_path", "policy_digest", "rules_digest", "rule_mapping"}


def load_detector_binding(path: Path) -> "DetectorBinding":
    """Read an operator-authored binding JSON file without validating it against a policy.

    Fields: `rules_path` (relative paths resolve beside this file), `policy_digest`,
    `rules_digest`, `rule_mapping` (detector rule ID to policy rule ID) and optional
    `scanned_fields`. The owner validates the binding against the actual policy and rule
    inventory before activating it (REQ-DEC-06).
    """
    from .config import ConfigurationError
    path = Path(path).expanduser().resolve()
    document = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or not _BINDING_FIELDS <= set(document)
            or set(document) - _BINDING_FIELDS - {"scanned_fields"}
            or not all(isinstance(document[key], str) and document[key]
                       for key in ("rules_path", "policy_digest", "rules_digest"))
            or not isinstance(document["rule_mapping"], dict)
            or not all(isinstance(key, str) and isinstance(value, str)
                       for key, value in document["rule_mapping"].items())
            or not isinstance(document.get("scanned_fields", []), list)
            or not all(isinstance(field, str) for field in document.get("scanned_fields", []))):
        raise ConfigurationError("invalid detector binding file")
    rules = Path(document["rules_path"]).expanduser()
    document["rules_path"] = rules if rules.is_absolute() else path.parent / rules
    if "scanned_fields" in document:
        document["scanned_fields"] = tuple(document["scanned_fields"])
    return DetectorBinding(**document)


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

    @property
    def binding_digest(self) -> str:
        """Digest of the declared policy/rules pair that decides hard-deny coverage.

        The rules path is not part of it: equal content stored elsewhere is the same pair.
        """
        return digest({"policy_digest": self.policy_digest, "rules_digest": self.rules_digest,
                       "rule_mapping": dict(self.rule_mapping),
                       "scanned_fields": list(self.scanned_fields)})

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
