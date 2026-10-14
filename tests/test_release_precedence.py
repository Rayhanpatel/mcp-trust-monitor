"""The evaluation harness must not call a model after a hard denial or scan failure."""
from types import SimpleNamespace

import pytest

from mcp_trust_monitor import ReviewResult, TrustState
from scripts.release_memory import assessed_case

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("detector,stage,state", [
    ("matched", "skipped_hard_deny", TrustState.QUARANTINED),
    ("failed", "skipped_detector_failure", TrustState.PENDING_REVIEW),
    ("stale", "skipped_detector_failure", TrustState.PENDING_REVIEW),
])
async def test_no_optional_model_request_after_required_detector_stops(detector, stage, state):
    async def scan(sid, *, observe):
        assert not observe
        return ReviewResult(sid, "revision", 3, detector, "disabled", state.value)
    async def reviewer(*args):
        pytest.fail("model called after required deterministic stage stopped")
    monitor = SimpleNamespace(review_once=scan, status=lambda sid: SimpleNamespace(state=state))
    scan_result, model = await assessed_case(monitor, "frozen-case", reviewer)
    assert scan_result.detector == detector
    assert model.stage == stage and model.outcome == state.value
    assert not model.response and model.memory_status == "not_attempted"
