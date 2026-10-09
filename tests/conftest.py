from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.managed_client import ManagedClient, trust_db_path
from mcp_trust_monitor.policy import load_policy
from mcp_trust_monitor.trust_store import TrustStore

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "policies" / "demo-policy.json"
FIXTURE_PATH = REPO_ROOT / "fixtures" / "tool_changes.json"

LOOKUP = demo.MUTABLE_SERVER
CONTROL = demo.CONTROL_SERVER


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class DemoEnvironment:
    """Isolated state directory with real stdio launch configs for both demo servers."""

    state_dir: Path
    policy_path: Path = POLICY_PATH

    def client(self, policy_path: Path | None = None) -> ManagedClient:
        store = TrustStore(trust_db_path(self.state_dir))
        servers = {sid: demo.server_config(sid, self.state_dir, FIXTURE_PATH)
                   for sid in demo.DEMO_SERVERS}
        policy = load_policy(policy_path or self.policy_path)
        return ManagedClient(store, servers, policy_revision=policy.binding)

    def received_calls(self, server_id: str) -> int:
        """Server-side count of tools/call requests the server process received."""
        return len(demo.received_requests(self.state_dir, server_id, "tools/call"))

    def received_lists(self, server_id: str) -> int:
        return len(demo.received_requests(self.state_dir, server_id, "tools/list"))

    def mutate(self, scenario_id: str) -> None:
        demo.write_definition(self.state_dir, demo.scenario_definition(self.fixture, scenario_id))

    def restore_baseline(self) -> None:
        demo.clear_definition(self.state_dir)

    @property
    def fixture(self) -> dict:
        return json.loads(FIXTURE_PATH.read_text())


@pytest.fixture
def env(tmp_path: Path) -> DemoEnvironment:
    return DemoEnvironment(state_dir=tmp_path / "state")


async def observe_and_approve(client: ManagedClient, server_id: str):
    record = await client.observe(server_id)
    return await client.approve(server_id, revision=record.observed_revision,
                                expected_generation=record.generation, actor="test-operator")
