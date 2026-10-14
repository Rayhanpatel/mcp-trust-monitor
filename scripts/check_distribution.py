#!/usr/bin/env python3
"""Install the built wheel outside this checkout, without optional cloud packages."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    wheels = sorted((ROOT / "dist").glob("mcp_trust_monitor-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Build one candidate wheel in dist/ first")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    with tempfile.TemporaryDirectory(prefix="mtm-wheel-consumer-") as temporary:
        directory = Path(temporary)
        def execute(command, expected=0):
            result = subprocess.run([str(value) for value in command], cwd=directory,
                env=env, text=True, capture_output=True, timeout=120)
            if result.returncode != expected:
                raise RuntimeError(f"consumer command failed ({result.returncode}): "
                    + result.stdout[-1000:] + result.stderr[-1000:])
            return result
        execute(["uv", "venv", "--python", sys.executable, directory / "venv"])
        python = directory / "venv/bin/python"
        cli = directory / "venv/bin/mcp-trust-monitor"
        execute(["uv", "pip", "install", "--python", python, wheels[0]])
        for name in ("installed_consumer.py", "external_stdio_server.py", "custom_detector_consumer.py"):
            shutil.copy2(ROOT / "examples" / name, directory / name)
        checks = """import importlib.util,importlib.resources as r,pathlib
import mcp_trust_monitor as m
assert importlib.util.find_spec('openai') is None
assert importlib.util.find_spec('yaml') is None
assert 'site-packages' in m.__file__
assert r.files(m).joinpath('py.typed').is_file()
assert r.files(m).joinpath('console_assets/index.html').is_file()
print(m.__version__)
"""
        execute([python, "-c", checks])
        execute([cli, "--help"])
        execute([python, directory / "installed_consumer.py"])
        execute([python, directory / "custom_detector_consumer.py"])
        def write(name, value):
            path = directory / name
            path.write_text(json.dumps(value), encoding="utf-8")
            return path
        definition = write("definition.json", {"name": "public_echo", "description": "Echo public text.",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}})
        policy = write("policy.json", {"policy_id": "outside-checkout", "revision": "1",
            "rules": [{"id": "EXT-1", "requirement": "Use public text only."}]})
        calls = directory / "calls.jsonl"
        profile = {"server_id": "external", "command": str(python),
            "args": [str(directory / "external_stdio_server.py"), "--definition", str(definition),
                     "--calls", str(calls)], "origin": "synthetic_fixture"}
        config = write("config.json", {"state_dir": "state", "policy_path": "policy.json", "servers": [profile]})
        def command(*args, expected=0):
            return execute([cli, "--config", config, *args], expected)
        observed = json.loads(command("observe", "external").stdout)
        command("approve", "external", "--revision", observed["observed_revision"],
                "--generation", str(observed["generation"]))
        refused = command("call", "external", "public_echo", expected=3)
        assert json.loads(refused.stderr)["reason"] == "session_refresh_required"
        assert calls.read_text() == ""
        command("call", "external", "public_echo", "--refresh", "--arguments", '{"text":"hello"}')
        assert len(calls.read_text().splitlines()) == 1
        assert json.loads(command("catalog").stdout) == []
        assert json.loads(command("status").stdout)[0]["state"] == "approved"
        database = directory / "state" / "trust.sqlite3"
        stored = database.read_bytes()
        exported = json.loads(command("export").stdout)
        assert exported["schema"] == "mcp-trust-monitor.decision-records"
        assert exported["schema_version"] == 2
        assert exported["records"]
        # Keyed pseudonyms: a fresh key per default export, stable under an operator key.
        assert exported["pseudonymization"]["scope"] == "export"
        assert all(row["server_id"].startswith("pid:") for row in exported["records"])
        key_file = directory / "export.key"
        key_file.write_bytes(os.urandom(32))
        keyed = [json.loads(command("export", "--pseudonym-key-file", key_file).stdout)
                 for _ in range(2)]
        assert keyed[0]["pseudonymization"]["scope"] == "operator_key"
        assert keyed[0]["records"] == keyed[1]["records"]
        assert ({row["event_id"] for row in exported["records"]}
                .isdisjoint(row["event_id"] for row in keyed[0]["records"]))
        assert key_file.read_bytes().hex() not in json.dumps(keyed)
        assert database.read_bytes() == stored  # export opens the store read-only
        # A launch identity change is rejected before refresh/launch, even with unchanged metadata.
        profile["args"] += ["--name", "changed-process-profile"]
        write("config.json", {"state_dir": "state", "policy_path": "policy.json", "servers": [profile]})
        command("call", "external", "public_echo", "--refresh", expected=3)
        assert len(calls.read_text().splitlines()) == 1
        print(json.dumps({"wheel": wheels[0].name, "core_only": True,
            "outside_checkout": True, "consumer": "passed", "separate_process_cli": "passed",
            "launch_identity_invalidation": "passed", "installed_resources": "passed",
            "custom_semgrep_binding": "passed", "sanitized_cli_export": "passed",
            "keyed_pseudonymous_export": "passed"}, indent=2))


if __name__ == "__main__":
    main()
