"""The offline learning-loop example in docs/SENSO_LEARNING_LOOP.md keeps working.

It runs the shipped example as a separate process. The example uses the real library
and real stdio servers with labelled local stand-ins for Senso and the model, so this
test checks the documented local gates, not remote service or model behavior.
"""
import json
import os
import subprocess
import sys

from conftest import REPO_ROOT


def test_offline_learning_loop_example_shows_each_documented_gate():
    environment = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    completed = subprocess.run([sys.executable, str(REPO_ROOT / "examples" / "learning_loop_offline.py")],
                               capture_output=True, text=True, timeout=180, env=environment)
    assert completed.returncode == 0, completed.stderr
    steps = {}
    for line in completed.stdout.splitlines():
        if ": {" in line:
            name, facts = line.split(": ", 1)
            steps[name] = json.loads(facts)
    assert steps["1 tool change"] == {"call": "pending_review", "server_received_calls": 1,
                                      "state": "pending_review"}
    assert steps["2 assessment"]["memory_status"] == "none_eligible"
    assert steps["3 verdict"] == {"tool_state": "quarantined", "value": "violation"}
    assert steps["4 lesson approval"]["draft_state"] == "draft"
    assert steps["4 lesson approval"]["wrong_digest"] == "MemoryConflict"
    assert steps["4 lesson approval"]["approved_state"] == "approved"
    assert steps["5 stored and verified"]["state"] == "active"
    later = steps["6 later assessment"]
    assert later["memory_status"] == "returned" and later["cited_precedents"] is True
    assert later["current_evidence"] == "external archive service"
    assert steps["7 changed lesson rejected"] == {"error": "MemoryIntegrityError", "memory_status": "retrieval_failed",
                                                  "outcome": "failed", "stage": "retrieval"}
    assert steps["8 revoked lesson ineligible"] == {"memory_status": "none_eligible", "new_remote_searches": 0}
    final = steps["9 tools still need explicit approval"]
    assert final["notes"] == ["quarantined", "quarantined"] and final["files"] == ["quarantined", "quarantined"]
    assert final["server_received_calls"] == {"files": 0, "notes": 1}
    assert '"learning_loop_offline": "passed"' in completed.stdout
