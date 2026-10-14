"""Compose optional adapters and the local console around one SDK owner.

Run with an explicit --config JSON and --env-file. --memory additionally requires
--capability-evidence from the successful Senso probe. Keys are never printed.
"""
from __future__ import annotations
import argparse
import asyncio
import json
from dataclasses import replace
from pathlib import Path

from mcp_trust_monitor import DetectorBinding, TrustMonitor
from mcp_trust_monitor.assessor import DEFAULT_MODEL
from mcp_trust_monitor.console import ConsoleServer
from mcp_trust_monitor.history import REQUIRED
from mcp_trust_monitor.history_adapter import ClickHouseSink
from mcp_trust_monitor.library_cli import load_config
from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.memory_senso import SensoMemoryBackend
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from mcp_trust_monitor.policy import policy_rule_ids
from mcp_trust_monitor.senso import SensoClient, load_env


async def run(args):
    config = load_config(args.config)
    keys = ["OPENAI_API_KEY", "SENSO_API_KEY", "SENSO_POLICY_CONTENT_IDS"]
    if args.clickhouse:
        keys.extend(REQUIRED)
    settings = load_env(keys, args.env_file)
    if any(not settings.get(key) for key in keys):
        raise ValueError("Explicit environment file is missing required adapter settings")
    detector = None
    if args.detector_binding:
        binding_path = args.detector_binding.resolve()
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        rules = Path(binding["rules_path"])
        binding["rules_path"] = rules if rules.is_absolute() else binding_path.parent / rules
        detector = DetectorBinding(**binding)
    senso = SensoClient(settings["SENSO_API_KEY"])
    backend = (SensoMemoryBackend(senso, capability_evidence=args.capability_evidence)
               if args.memory else None)
    reviewer = OpenAIReviewer(api_key=settings["OPENAI_API_KEY"], model=args.model,
        senso_client=senso, policy_content_ids=tuple(v.strip() for v in settings["SENSO_POLICY_CONTENT_IDS"].split(",") if v.strip()),
        memory_enabled=args.memory, memory_backend=backend, memory_scope=args.scope)
    sink = ClickHouseSink(settings) if args.clickhouse else None
    config = replace(config, detector=detector, reviewer=reviewer, history_sink=sink)
    async with TrustMonitor(config) as monitor:
        memory = MemoryService(monitor.store, lambda: monitor.policy,
            rule_ids=policy_rule_ids(config.policy_path), scope=args.scope)
        await monitor.start_monitor()
        async with ConsoleServer(monitor, memory=memory, publication_backend=backend,
                                 port=args.port) as console:
            print(console.url, flush=True)
            await asyncio.Event().wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--memory", action="store_true")
    parser.add_argument("--capability-evidence", type=Path)
    parser.add_argument("--clickhouse", action="store_true")
    parser.add_argument("--detector-binding", type=Path,
                        help="explicit JSON DetectorBinding; omission reports detector disabled")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--scope", default="default")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if args.memory and args.capability_evidence is None:
        parser.error("--memory requires --capability-evidence")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass
