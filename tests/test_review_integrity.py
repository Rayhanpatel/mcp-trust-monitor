"""Independent review regressions: real MCP/store, faked optional remote services."""
import asyncio
import json
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mcp_trust_monitor import TrustMonitor
from mcp_trust_monitor.async_assessor import AsyncOpenAIAssessor
from mcp_trust_monitor.assessor import ModelError
from mcp_trust_monitor.memory import MemoryService, SearchPassage
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from mcp_trust_monitor.paired_evaluation import digest, run_plan
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.trust_store import StorageFaultError
from scripts.release_memory import (validate_manifest, validate_source_review,
    validate_active_sources, reject_heldout_summary)
from test_memory_service import Backend, active, memory
from test_monitor_lifecycle import setup
from test_openai_reviewer_adapter import Assessor, PolicySource, config
from test_paired_evaluation import plan
from test_model_review import context, raw, retrieved_policy, fake_response, message
from conftest import LOOKUP, POLICY_PATH

pytestmark = pytest.mark.anyio


def reviewer(*, assessor=Assessor, source=None, backend=None):
    return OpenAIReviewer(api_key='not-real', model='test', senso_client=source or PolicySource(),
        policy_content_ids=('policy-source',), assessor_factory=assessor,
        memory_enabled=backend is not None, memory_backend=backend)


def delayed_assessor():
    class Delayed(Assessor):
        started = threading.Event()
        release = threading.Event()
    return Delayed


@pytest.mark.parametrize('refresh', [False, True])
async def test_notification_during_model_is_stale_even_after_identical_refresh(tmp_path, refresh):
    cfg, path, _ = setup(tmp_path)
    cfg = replace(cfg, poll_interval=10, timeout_seconds=5)
    assessor = delayed_assessor()
    async with TrustMonitor(cfg) as monitor:
        before = await monitor.observe('custom/local')
        pending = asyncio.create_task(reviewer(assessor=assessor)(monitor, 'custom/local'))
        try:
            assert await asyncio.to_thread(assessor.started.wait, 5)
            path.write_text(json.dumps({'notify_during_list':True}))
            await monitor.observe('custom/local')
            if refresh:
                path.write_text('{}')
                await monitor.observe('custom/local')
            assert monitor.status('custom/local').generation == before.generation
            assert monitor.status('custom/local').observed_revision == before.observed_revision
            assessor.release.set()
            result = await pending
            assert result.outcome == 'stale'
            assert not any(e['event_type']=='model_assessment_recorded' for e in monitor.events('custom/local'))
        finally:
            assessor.release.set()
            await asyncio.gather(pending, return_exceptions=True)


async def test_dirty_context_refuses_policy_and_model_io_before_start(tmp_path):
    cfg, path, _ = setup(tmp_path, notify_during_list=True)
    class NoIO(PolicySource):
        def search_context(self, *args, **kwargs):
            pytest.fail('dirty context must not contact policy provider')
    async with TrustMonitor(cfg) as monitor:
        await monitor.observe('custom/local')
        result = await reviewer(source=NoIO())(monitor, 'custom/local')
        assert result.outcome == 'stale' and result.stage == 'context'


@pytest.mark.parametrize('change', ['revocation', 'policy_reload', 'model_config'])
async def test_model_completion_cannot_outlive_memory_policy_or_configuration(env, tmp_path, change):
    assessor = delayed_assessor()
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        memory = MemoryService(monitor.store, lambda:monitor.policy, rule_ids=('POL-001','POL-002'))
        lesson, backend = await active(memory)
        adapter = reviewer(assessor=assessor, backend=backend)
        pending = asyncio.create_task(adapter(monitor, LOOKUP))
        try:
            assert await asyncio.to_thread(assessor.started.wait, 5)
            if change == 'revocation':
                memory.revoke_lesson(lesson.lesson_id, actor='human', reason='Withdrawn')
            elif change == 'model_config':
                adapter.model = 'different-model'
            else:
                policy = json.loads(POLICY_PATH.read_text()); policy['revision'] = 'changed'
                path = tmp_path/'new-policy.json'; path.write_text(json.dumps(policy))
                await monitor.reload_policy(path)
            assessor.release.set()
            result = await pending
            assert result.outcome == 'stale' and monitor.status(LOOKUP).state.value == 'unreviewed'
            assert not any(e['event_type']=='model_assessment_recorded' for e in monitor.events(LOOKUP))
        finally:
            assessor.release.set()
            await asyncio.gather(pending, return_exceptions=True)


async def test_authoritative_failure_propagates_without_adapter_failure_write(env, monkeypatch):
    assessor = delayed_assessor()
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        pending = asyncio.create_task(reviewer(assessor=assessor)(monitor, LOOKUP))
        try:
            assert await asyncio.to_thread(assessor.started.wait, 5)
            monitor.store._db.execute('PRAGMA query_only=ON')
            events = []
            original = monitor.store.record_event
            def record(*args, **kwargs):
                events.append(args[1]); return original(*args, **kwargs)
            monkeypatch.setattr(monitor.store, 'record_event', record)
            assessor.release.set()
            with pytest.raises(StorageFaultError):
                await pending
            assert events == []
        finally:
            assessor.release.set()
            await asyncio.gather(pending, return_exceptions=True)


async def test_cleanup_failure_does_not_replace_completed_decision(env):
    class CleanupFails(Assessor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._client = SimpleNamespace(close=self.close)
        def close(self):
            raise RuntimeError('secret remote body')
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        result = await reviewer(assessor=CleanupFails)(monitor, LOOKUP)
        assert result.stage == 'completed' and result.assessment_event_id
        assert monitor.events()[-1]['event_type'] == 'model_client_cleanup_failed'
        assert 'secret remote' not in json.dumps(monitor.events())


async def test_custom_policy_drives_query_and_requested_returned_citations(env, tmp_path):
    document = json.loads(POLICY_PATH.read_text())
    document['policy_id'] = 'custom-document-policy'
    document['rules'] = [{'id':'DOC-A', 'requirement':'Documents must retain their source title.'},
                         {'id':'DOC-B', 'requirement':'Summaries must retain source attributions.'}]
    path = tmp_path/'custom-policy.json'; path.write_text(json.dumps(document))
    class Source(PolicySource):
        def search_context(self, query, content_ids, max_results=20):
            self.query = query
            return super().search_context(query, content_ids, max_results)
    source = Source(path)
    async with TrustMonitor(config(env, path)) as monitor:
        await monitor.observe(LOOKUP)
        result = await reviewer(source=source)(monitor, LOOKUP)
        assert result.stage == 'completed'
        assert all(text in source.query for text in ('DOC-A', 'DOC-B', 'source title'))
        assert 'POL-001' not in source.query and len(source.query) <= 2000
        event = next(e for e in monitor.events() if e['event_id']==result.assessment_event_id)
        assert event['detail']['policy_requested_content_ids'] == ['policy-source']
        assert event['detail']['policy_returned_content_ids'] == ['policy-source']


async def test_foreign_memory_fails_attempt_without_policy_only_fallback(env):
    class NoModel(Assessor):
        def assess(self, *args):
            pytest.fail('foreign memory must fail before model')
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        memory = MemoryService(monitor.store, monitor.policy, rule_ids=('POL-001','POL-002'))
        lesson, backend = await active(memory)
        backend.search_results = [SearchPassage('foreign', lesson.body)]
        result = await reviewer(assessor=NoModel, backend=backend)(monitor, LOOKUP)
        assert result.outcome == 'failed' and result.stage == 'retrieval'
        assert result.error_type == 'MemoryIntegrityError'
        assert result.memory_status == 'retrieval_failed'
        event = monitor.events(LOOKUP)[-1]
        assert event['detail']['memory']['requested_content_ids'] == [lesson.content_id]
        assert event['detail']['memory']['returned_content_ids'] is None
        assert monitor.status(LOOKUP).state.value == 'unreviewed'


def completed():
    return {'status':'completed', 'detector_status':'clean', 'detector_ids':[],
            'applied_outcome':'pending_review', 'model_status':'completed', 'model_outcome':'pending_review'}


async def test_interrupted_run_keeps_frozen_48_denominator_and_is_not_resumed(tmp_path):
    manifest, frozen = plan(); count = 0
    async def attempt(case, enabled):
        nonlocal count
        count += 1
        if count == 2:
            raise asyncio.CancelledError()
        return completed()
    path = tmp_path/'report.json'
    with pytest.raises(asyncio.CancelledError):
        await run_plan(frozen, manifest, attempt=attempt, report_path=path)
    report = json.loads(path.read_text())
    assert len(report['results']) == report['summary']['scheduled_trials'] == 48
    assert report['summary']['attempted_trials'] == 2
    assert sum(r['status']=='not_started' for r in report['results']) == 46
    assert report['results'][1]['status'] == 'interrupted'
    assert report['gate']['release_blocked'] and not report['complete']
    with pytest.raises(FileExistsError):
        await run_plan(frozen, manifest, attempt=attempt, report_path=path)
    assert count == 2


@pytest.mark.parametrize('change', ['missing_trial', 'changed_expectation', 'duplicate_trial'])
async def test_rehashed_but_invalid_schedule_rejected_before_model(tmp_path, change):
    manifest, frozen = plan()
    if change == 'missing_trial':
        frozen['trials'].pop()
    elif change == 'changed_expectation':
        frozen['trials'][0]['expected_outcome'] = 'pending_review'
    else:
        frozen['trials'][1] = dict(frozen['trials'][0])
    frozen['plan_digest'] = digest({k:v for k,v in frozen.items() if k!='plan_digest'})
    async def attempt(*args):
        pytest.fail('malformed schedule must not execute')
    with pytest.raises(ValueError, match='schedule'):
        await run_plan(frozen, manifest, attempt=attempt, report_path=tmp_path/'report.json')


async def test_detector_failure_and_unexpected_hard_deny_block_evaluation_gate(tmp_path):
    manifest, frozen = plan(); count = 0
    async def attempt(*args):
        nonlocal count
        count += 1
        return {**completed(), 'detector_status':'failed' if count == 1 else 'matched',
                'detector_ids':[] if count == 1 else ['POL-001']}
    report = await run_plan(frozen, manifest, attempt=attempt, report_path=tmp_path/'report.json')
    assert report['results'][0]['verdict']=='error'
    assert report['results'][0]['detector_matches_expectation'] is False
    assert len(report['gate']['unexpected_detector_trials']) == 48
    assert report['gate']['release_blocked']


async def test_release_source_approval_binds_recorded_revision_and_split(memory):
    manifest, _ = plan(); case = manifest['lesson_source'][0]
    revision = server_revision([case['after']])
    memory.store.record_observation('source/'+case['id'], revision, [case['after']])
    source = {'observation_id':memory.store.observations()[-1]['observation_id']}
    proposal = {'case_id':case['id'], 'revision':'wrong-matching-proposal', 'family':case['family'],
                'summary':'An earlier tool required private notes for an unrelated advertising recipient.'}
    review = {'case_id':case['id'], 'revision':proposal['revision'], 'actor':'human'}
    with pytest.raises(ValueError, match='exact recorded'):
        validate_source_review(memory, manifest, case['id'], review, proposal, source)
    proposal['revision'] = review['revision'] = revision
    validate_source_review(memory, manifest, case['id'], review, proposal, source)
    with pytest.raises(ValueError, match='lesson-source'):
        validate_source_review(memory, manifest, manifest['held_out'][0]['id'], review, proposal, source)
    with pytest.raises(ValueError, match='held-out'):
        reject_heldout_summary(manifest['held_out'][0]['after']['description'], manifest)


async def test_release_manifest_pin_and_active_source_whitelist(memory):
    manifest, _ = plan(); validate_manifest(manifest)
    manifest['held_out'][0]['expected_outcome'] = 'pending_review'
    with pytest.raises(ValueError, match='independently frozen'):
        validate_manifest(manifest)
    manifest, _ = plan()
    await active(memory)  # generic library example is not an approved release source case
    with pytest.raises(ValueError, match='source split'):
        validate_active_sources(memory, manifest, memory.snapshot(enabled=True))


async def test_native_async_review_cancels_network_and_closes_on_monitor_stop(env):
    started, cancelled, closed = asyncio.Event(), asyncio.Event(), asyncio.Event()
    class Responses:
        async def create(self, **request):
            assert request['store'] is False and 'tools' not in request
            assert request['text']['format']['strict'] is True
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
    class Client:
        responses = Responses()
        async def close(self):
            closed.set()
    class AsyncSource(PolicySource):
        async def search_context_async(self, query, content_ids, max_results=20):
            return super().search_context(query, content_ids, max_results)
    adapter = reviewer(source=AsyncSource(), assessor=lambda key, model, **kw:
        AsyncOpenAIAssessor(key, model, client=Client(), **kw))
    cfg = replace(config(env), reviewer=adapter)
    async with TrustMonitor(cfg) as monitor:
        await monitor.start_monitor()
        await asyncio.wait_for(started.wait(), 3)
        await asyncio.wait_for(monitor.stop_monitor(), .8)
        assert cancelled.is_set() and closed.is_set()
        assert not any(e['event_type']=='model_assessment_recorded' for e in monitor.events(LOOKUP))


@pytest.mark.parametrize('kind', ['timeout', 'refusal', 'incomplete', 'malformed'])
async def test_async_response_metadata_is_per_attempt_even_on_failure(kind):
    ctx = context()
    good = fake_response(output=[message(SimpleNamespace(type='output_text', text=json.dumps(raw(ctx))))])
    good.id = 'first'; good.model = 'test'; good.usage = {'total_tokens':1}
    if kind == 'timeout':
        bad = TimeoutError('private credentials must not appear')
    elif kind == 'refusal':
        bad = fake_response(output=[message(SimpleNamespace(type='refusal', refusal='private refusal'))])
    elif kind == 'incomplete':
        bad = fake_response(status='incomplete')
    else:
        bad = fake_response(output=[message(SimpleNamespace(type='output_text', text='not JSON'))])
    if not isinstance(bad, Exception):
        bad.id = 'second'; bad.model = 'test'; bad.usage = {'total_tokens':2}
    class Responses:
        values = [good, bad]
        async def create(self, **kwargs):
            result = self.values.pop(0)
            if isinstance(result, Exception):
                raise result
            return result
    assessor = AsyncOpenAIAssessor('unused', client=SimpleNamespace(responses=Responses()))
    assert (await assessor.assess(ctx, (), retrieved_policy()))['recommendation'] == 'quarantine'
    assert assessor.response_metadata()['response_id'] == 'first'
    with pytest.raises(ModelError) as exc:
        await assessor.assess(ctx, (), retrieved_policy())
    assert 'private' not in str(exc.value)
    metadata = assessor.response_metadata()
    assert metadata['response_id'] == (None if kind=='timeout' else 'second')
    assert metadata['usage'] == (None if kind=='timeout' else {'total_tokens':2})


async def test_quarantine_has_explicit_assessment_chain(env):
    class Quarantine(Assessor):
        def assess(self, ctx, previous, policy):
            return {**super().assess(ctx, previous, policy), 'recommendation':'quarantine',
                    'policy_ids':['POL-001'], 'evidence':[{'tool':ctx.tools[0]['name'],
                                                         'text':ctx.tools[0]['description']}]}
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        result = await reviewer(assessor=Quarantine)(monitor, LOOKUP)
        assert result.outcome == 'quarantined'
        requested = next(e for e in monitor.events(LOOKUP) if e['event_type']=='quarantine_requested')
        assert requested['detail']['assessment_event_id'] == result.assessment_event_id


async def test_failed_model_retains_validated_memory_sources_without_claiming_citations(env):
    class Fails(Assessor):
        def assess(self, *args):
            raise ModelError('api_error', 'private service detail')
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        memory = MemoryService(monitor.store, monitor.policy, rule_ids=('POL-001','POL-002'))
        lesson, backend = await active(memory)
        result = await reviewer(assessor=Fails, backend=backend)(monitor, LOOKUP)
        assert result.outcome == 'failed' and result.memory_status == 'returned'
        assert result.precedent_ids == ()
        detail = monitor.events(LOOKUP)[-1]['detail']
        assert detail['memory']['requested_content_ids'] == [lesson.content_id]
        assert detail['memory']['passages'][0]['lesson_id'] == lesson.lesson_id
        assert detail['policy_returned_content_ids'] == ['policy-source']
        assert 'private service' not in json.dumps(detail)
