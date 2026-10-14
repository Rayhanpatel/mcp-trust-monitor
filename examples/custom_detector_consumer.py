#!/usr/bin/env python3
"""Standalone installed-package consumer for custom JSON detector configuration.

Copy this file anywhere outside the checkout, install the candidate monitor wheel
in a virtual environment, and run it with that environment's Python. The scan uses
the library's pinned, isolated uvx Semgrep command (or MCP_TRUST_SEMGREP override).
It never imports repository fixtures or uses the demonstration policy/rules.
"""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile

import mcp_trust_monitor
from mcp_trust_monitor.config import ConfigurationError
from mcp_trust_monitor.detector import SEMGREP_VERSION, rules_digest_of, verify_semgrep
from mcp_trust_monitor.policy import DetectorBinding, load_policy


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    rule_id = "hard-deny.ext-1.external-customer-records"
    marker = "EXPORT_CUSTOMER_RECORDS_EXTERNALLY"
    with tempfile.TemporaryDirectory(prefix="mtm-custom-detector-") as temporary:
        directory = Path(temporary).resolve()
        policy_path = directory / "customer-policy.json"
        rules_path = directory / "customer-rules.json"
        policy_path.write_text(json.dumps({
            "policy_id": "customer-local-policy", "revision": "customer-1",
            "rules": [{"id": "EXT-1", "requirement": "Do not export customer records.",
                       "hard_deny_condition": "The tool description contains the exact prohibited export directive."}],
        }), encoding="utf-8")
        rules_path.write_text(json.dumps({"rules": [{
            "id": rule_id, "languages": ["generic"], "severity": "ERROR",
            "message": "Customer policy prohibits this explicit export directive.",
            "metadata": {"policy_id": "EXT-1"}, "pattern-regex": marker,
        }]}), encoding="utf-8")
        binding = DetectorBinding(rules_path=rules_path,
            policy_digest=load_policy(policy_path).digest,
            rules_digest=rules_digest_of(rules_path.read_bytes()),
            rule_mapping={rule_id: "EXT-1"})
        binding.validate(policy_path)
        version = verify_semgrep()
        require(version == SEMGREP_VERSION, "The pinned Semgrep version did not run")

        def tool(description: str) -> dict:
            return {"name": "customer_records", "description": description,
                    "inputSchema": {"type": "object", "properties": {}}}

        description = "Customer directive: " + marker + "."
        matching = binding.scan([tool(description)], policy_path)
        require(matching.policy_ids == ("EXT-1",), "Custom policy did not match")
        require(matching.semgrep_version == version and matching.scanned_tools == 1,
                "The actual Semgrep scan did not cover the configured tool")
        require(len(matching.matches) == 1, "Expected one custom-rule match")
        evidence = matching.matches[0].evidence
        require(evidence.text == marker and description[evidence.start:evidence.end] == marker,
                "Custom-rule evidence offsets do not match the scanned description")

        benign_tools = [tool("Summarize public customer documentation supplied by the caller.")]
        clean = binding.scan(benign_tools, policy_path)
        require(not clean.matches and clean.scanned_tools == 1 and clean.semgrep_version == version,
                "The real no-match scan did not complete cleanly")
        require(matching.rules_digest == clean.rules_digest == binding.rules_digest,
                "Results were not bound to the explicit custom rules")

        mismatched = replace(binding, rule_mapping={"hard-deny.undeclared-name": "EXT-1"})
        try:
            mismatched.scan(benign_tools, policy_path)
        except ConfigurationError:
            mismatch_refused = True
        else:
            raise RuntimeError("Mismatched inventory was accepted for a no-match input")

        # A post-validation policy edit must also invalidate the declared pair.
        changed = json.loads(policy_path.read_text(encoding="utf-8"))
        changed["revision"] = "customer-2"
        policy_path.write_text(json.dumps(changed), encoding="utf-8")
        try:
            binding.scan(benign_tools, policy_path)
        except ConfigurationError:
            stale_binding_refused = True
        else:
            raise RuntimeError("A changed custom policy retained the prior detector binding")

        print(json.dumps({"consumer": "custom_detector", "status": "passed",
            "package_path": str(Path(mcp_trust_monitor.__file__).resolve()),
            "working_directory": os.getcwd(), "semgrep_version": version,
            "policy_ids": list(matching.policy_ids), "matched_evidence": evidence.text,
            "clean_scan_tools": clean.scanned_tools,
            "mismatched_inventory_refused_on_no_match": mismatch_refused,
            "changed_policy_binding_refused": stale_binding_refused,
            "configuration": "explicit temporary JSON policy and rules"}, indent=2))


if __name__ == "__main__":
    main()
