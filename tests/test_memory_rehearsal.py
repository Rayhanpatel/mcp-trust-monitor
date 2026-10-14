"""Offline control-flow proof; these tests never call cloud services."""
import asyncio
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from mcp_trust_monitor import TrustMonitor
from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from mcp_trust_monitor.paired_evaluation import _gate, freeze_plan, run_plan, summarize
from scripts import rehearse_memory as rehearsal
from scripts.release_memory import REVIEW_CONFIG
from test_memory_service import active
from test_openai_reviewer_adapter import Assessor, PolicySource, config
from conftest import LOOKUP

pytestmark = pytest.mark.anyio


async def completed_evaluation(directory):
    manifest = json.loads((rehearsal.ROOT / 'fixtures/memory_cases.json').read_text())
    plan = freeze_plan(manifest, model='test', policy_binding='policy', rules_digest='rules',
                       memory_digest='memory', review_config=REVIEW_CONFIG)
    expected = {case['id']: case for case in manifest['held_out']}
    async def attempt(case, enabled):
        item = expected[case['id']]
        return {'status': 'completed', 'applied_outcome': item['expected_outcome'],
            'model_status': 'completed', 'model_outcome': item['expected_outcome'],
            'detector_status': 'clean', 'detector_ids': item['expected_hard_deny_policy_ids'],
            'model_name': 'test', 'max_retries': 0}
    (directory / 'paired-plan.json').write_text(json.dumps(plan))
    report = await run_plan(plan, manifest, attempt=attempt, report_path=directory / 'paired-results.json')
    return manifest, plan, report


async def test_complete_frozen_gate_accepts_and_does_not_rewrite(tmp_path):
    manifest, plan, report = await completed_evaluation(tmp_path)
    original = (tmp_path / 'paired-results.json').read_bytes()
    assert rehearsal.validate_evaluation(tmp_path, manifest) == plan
    assert (tmp_path / 'paired-results.json').read_bytes() == original


@pytest.mark.parametrize('change', ['partial', 'forged_verdict', 'regression', 'different_model'])
async def test_gate_rejects_before_owner_or_credentials_are_touched(tmp_path, monkeypatch, change):
    manifest, plan, report = await completed_evaluation(tmp_path)
    if change == 'partial':
        report['results'] = report['results'][:-1]
    elif change == 'forged_verdict':
        report['results'][0]['applied_outcome'] = 'approved'
    elif change == 'different_model':
        report['results'][0]['model_name'] = 'other'
    else:
        row = next(r for r in report['results'] if r['memory'] == 'on'
                   and r['expected_outcome'] == 'pending_review')
        row.update(applied_outcome='quarantined', verdict='false quarantine')
        report['summary'], report['gate'] = summarize(report['results']), _gate(report)
    (tmp_path / 'paired-results.json').write_text(json.dumps(report))
    def forbidden(*args):
        pytest.fail('must refuse before configuration/credentials')
    monkeypatch.setattr(rehearsal, 'existing_configuration', forbidden)
    monkeypatch.setattr(rehearsal, 'read_settings', forbidden)
    args = SimpleNamespace(directory=tmp_path, env_file=tmp_path/'not-a-secret-file')
    with pytest.raises(ValueError):
        await rehearsal.run(args)
    assert not (tmp_path / rehearsal.REPORT).exists()


async def test_existing_rehearsal_refuses_overwrite_before_credentials(tmp_path, monkeypatch):
    await completed_evaluation(tmp_path)
    path = tmp_path / rehearsal.REPORT
    path.write_text('failed attempt retained')
    monkeypatch.setattr(rehearsal, 'read_settings', lambda *_: pytest.fail('no credentials'))
    with pytest.raises(FileExistsError):
        await rehearsal.run(SimpleNamespace(directory=tmp_path))
    assert path.read_text() == 'failed attempt retained'


@pytest.mark.parametrize('change', ['none', 'source_id', 'revision', 'response', 'event_kind'])
def test_prior_assessment_binds_recorded_case_and_exact_policy_sources(change):
    event = {'event_id': 'prior', 'event_type': 'model_assessment_recorded', 'server_id': 'heldout/case',
             'detail': {'assessed_revision': 'rev', 'policy_requested_content_ids': ['original'],
                        'response': {'response_id': 'actual-provider-response'}}}
    row = {'assessment_event_id': 'prior', 'response': {'response_id': 'actual-provider-response'}}
    source_ids, revision = ('original',), 'rev'
    if change == 'source_id':
        source_ids = ('different',)
    elif change == 'revision':
        revision = 'changed'
    elif change == 'response':
        row['response'] = {'response_id': 'different'}
    elif change == 'event_kind':
        event['event_type'] = 'model_assessment_failed'
    monitor = SimpleNamespace(events=lambda sid:[event])
    if change == 'none':
        assert rehearsal.validate_prior_assessment(monitor, 'heldout/case', row, source_ids, revision) == 'prior'
    else:
        with pytest.raises(ValueError):
            rehearsal.validate_prior_assessment(monitor, 'heldout/case', row, source_ids, revision)


class AsyncFakeAssessor(Assessor):
    async def assess(self, *args):
        return super().assess(*args)


async def test_real_local_revocation_discards_held_response_and_preserves_quarantine(env):
    async with TrustMonitor(replace(config(env), poll_interval=120)) as monitor:
        await monitor.observe(LOOKUP)
        await monitor.quarantine(LOOKUP, actor='test-operator', reason='Existing quarantine')
        memory = MemoryService(monitor.store, lambda: monitor.policy, rule_ids=('POL-001', 'POL-002'))
        first, fake = await active(memory, server='lesson-source-one')
        second, _ = await active(memory, backend=fake, server='lesson-source-two')
        backend = rehearsal.TracedBackend(fake)
        factory = rehearsal.held_response_factory(parent=AsyncFakeAssessor)
        reviewer = OpenAIReviewer(api_key='test-only', model='test', senso_client=PolicySource(),
            policy_content_ids=('policy-source',), memory_enabled=True, memory_backend=backend,
            assessor_factory=factory, timeout_seconds=5)
        report = {}
        await rehearsal.demonstrate(monitor, memory, backend, reviewer, factory, LOOKUP, report, lambda:None)
        assert report['status'] == 'completed'
        assert report['at_revocation_boundary']['provider_completed'] is True
        assert report['at_revocation_boundary']['network_request_pending'] is False
        assert report['assessment']['outcome'] == 'stale'
        assert report['assessment']['response']['response_id'] == 'test-response'
        assert report['additional_model_attempts_outside_frozen_run'] == 1
        assert report['next_search_excluded_revoked']
        assert report['remote_document_retained']
        assert report['quarantines_preserved']
        assert report['accepted_decision_event_ids'] == []
        assert {memory.get_lesson(x.lesson_id).state for x in (first, second)} == {'active', 'revoked'}
        assert fake.uploads == 2  # Test setup only; demonstration performs no uploads.


async def test_provider_failure_does_not_revoke_or_retry(env):
    class Failed(AsyncFakeAssessor):
        async def assess(self, *args):
            raise RuntimeError('test-only raw provider body must not enter report')
    async with TrustMonitor(replace(config(env), poll_interval=120)) as monitor:
        await monitor.observe(LOOKUP)
        await monitor.quarantine(LOOKUP, actor='test-operator', reason='Existing quarantine')
        memory = MemoryService(monitor.store, lambda:monitor.policy, rule_ids=('POL-001', 'POL-002'))
        first, fake = await active(memory, server='lesson-source-one')
        second, _ = await active(memory, backend=fake, server='lesson-source-two')
        backend = rehearsal.TracedBackend(fake)
        factory = rehearsal.held_response_factory(parent=Failed)
        reviewer = OpenAIReviewer(api_key='test-only', model='test', senso_client=PolicySource(),
            policy_content_ids=('policy-source',), memory_enabled=True, memory_backend=backend,
            assessor_factory=factory, timeout_seconds=5)
        report = {}
        with pytest.raises(RuntimeError, match='held completed-provider'):
            await rehearsal.demonstrate(monitor, memory, backend, reviewer, factory, LOOKUP, report, lambda:None)
        assert report['additional_model_attempts_outside_frozen_run'] == 1
        assert report['assessment']['outcome'] == 'failed'
        assert 'raw provider body' not in json.dumps(report)
        assert all(memory.get_lesson(x.lesson_id).state == 'active' for x in (first, second))
