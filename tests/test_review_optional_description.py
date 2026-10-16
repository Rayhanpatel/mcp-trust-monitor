"""Optional MCP tool descriptions through the model reviewer (REQ-DEC-02/03, REQ-MEM-03).

MCP makes a tool's ``description`` optional and the revision digest records an
omitted one as ``None``. Real stdio servers publish such tools here; the model,
policy source and memory backend are local fakes, so no network service is used.
A reviewer recommendation still never approves: state and generation stay put.
"""
from dataclasses import replace

import pytest

from mcp_trust_monitor import TrustMonitor
from mcp_trust_monitor.managed_client import ObservationError
from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from test_memory_service import Backend, active
from test_monitor_lifecycle import setup
from test_openai_reviewer_adapter import Assessor, PolicySource, config
from conftest import LOOKUP

pytestmark = pytest.mark.anyio

SERVER = 'custom/local'
QUERY_PREFIX = 'Operator-reviewed precedents for tool metadata change:'
DESCRIBED = 'Find a public document by its title and return its summary.'


def recording_assessor():
    class Recording(Assessor):
        contexts = []

        def assess(self, context, previous, policy):
            self.contexts.append(context)
            return super().assess(context, previous, policy)
    return Recording


class QueryBackend(Backend):
    """The fake verified backend, also keeping each precedent query it receives."""

    def __init__(self):
        super().__init__()
        self.queries = []

    async def search_context(self, query, *, content_ids, top_k):
        self.queries.append(query)
        return await super().search_context(query, content_ids=content_ids, top_k=top_k)


def reviewer(assessor, backend=None):
    return OpenAIReviewer(api_key='not-real', model='test', senso_client=PolicySource(),
        policy_content_ids=('policy-source',), assessor_factory=assessor,
        memory_enabled=backend is not None, memory_backend=backend)


async def eligible_memory(monitor, memory_enabled):
    """One verified, active, policy-bound lesson, so enabled retrieval really searches."""
    if not memory_enabled:
        return None, None
    memory = MemoryService(monitor.store, lambda: monitor.policy, rule_ids=('POL-001', 'POL-002'))
    lesson, backend = await active(memory, QueryBackend())
    assert memory.snapshot(enabled=True).lessons == (lesson,)
    return lesson, backend


def live(tmp_path, **settings):
    cfg, _, _ = setup(tmp_path, **settings)
    return replace(cfg, poll_interval=10, timeout_seconds=5)


def assert_reviewed_without_approval(monitor, server_id, before, result, assessor):
    assert result.stage == 'completed', result
    assert result.error_type is None
    assert len(assessor.contexts) == 1  # the fake model really ran
    after = monitor.status(server_id)
    assert after.state == before.state and after.state.value == 'unreviewed'
    assert after.generation == before.generation
    assert after.approved_revision is None
    assert not any(e['event_type'] in {'approved', 'restored'} for e in monitor.events(server_id))
    event = next(e for e in monitor.events(server_id) if e['event_id'] == result.assessment_event_id)
    assert event['event_type'] == 'model_assessment_recorded'
    assert event['detail']['recommendation'] == 'review'


def assert_bounded_metadata_query(backend, *, contains=(), excludes=()):
    assert backend.searches == 1 and len(backend.queries) == 1
    query = backend.queries[0]
    assert query.startswith(QUERY_PREFIX) and len(query) <= 2000
    assert 'None' not in query and 'null' not in query
    assert all(text in query for text in contains)
    assert not any(text in query for text in excludes)


@pytest.mark.parametrize('memory_enabled', [False, True], ids=['memory-disabled', 'memory-enabled'])
async def test_absent_description_reaches_the_model_and_never_approves(tmp_path, memory_enabled):
    assessor = recording_assessor()
    async with TrustMonitor(live(tmp_path, description=None)) as monitor:
        before = await monitor.observe(SERVER)
        assert [tool['description'] for tool in before.observed_tools] == [None]
        lesson, backend = await eligible_memory(monitor, memory_enabled)
        result = await reviewer(assessor, backend)(monitor, SERVER)
        assert_reviewed_without_approval(monitor, SERVER, before, result, assessor)
        # The model saw the absent description as absent, not as invented text.
        assert [tool['description'] for tool in assessor.contexts[0].tools] == [None]
        if memory_enabled:
            assert result.memory_status == 'returned'
            assert backend.requested == (lesson.content_id,)
            assert_bounded_metadata_query(backend, excludes=('effect', 'inputSchema'))
        else:
            assert result.memory_status == 'disabled'


@pytest.mark.parametrize('memory_enabled', [False, True], ids=['memory-disabled', 'memory-enabled'])
async def test_mixed_present_and_absent_descriptions_review_together(env, memory_enabled):
    schema = {'type': 'object', 'properties': {'title': {'type': 'string'}}}
    env.serve_raw([{'name': 'lookup_document', 'description': DESCRIBED, 'inputSchema': schema},
                   {'name': 'list_titles', 'inputSchema': {'type': 'object'}}])
    assessor = recording_assessor()
    async with TrustMonitor(config(env)) as monitor:
        before = await monitor.observe(LOOKUP)
        assert {tool['name']: tool['description'] for tool in before.observed_tools} == {
            'lookup_document': DESCRIBED, 'list_titles': None}
        _, backend = await eligible_memory(monitor, memory_enabled)
        result = await reviewer(assessor, backend)(monitor, LOOKUP)
        assert_reviewed_without_approval(monitor, LOOKUP, before, result, assessor)
        if memory_enabled:
            assert result.memory_status == 'returned'
            assert_bounded_metadata_query(backend, contains=(DESCRIBED,),
                                          excludes=('list_titles', 'inputSchema'))


async def test_real_transport_refuses_a_non_string_description_before_review(tmp_path):
    async with TrustMonitor(live(tmp_path, description=123)) as monitor:
        with pytest.raises(ObservationError):
            await monitor.observe(SERVER)
        assert monitor.status(SERVER) is None


@pytest.mark.parametrize('memory_enabled', [False, True], ids=['memory-disabled', 'memory-enabled'])
@pytest.mark.parametrize('invalid', [123, False, [], {'text': 'nested'}])
async def test_invalid_description_type_fails_closed_before_model(tmp_path, monkeypatch,
                                                                  memory_enabled, invalid):
    """Real MCP transport refuses these values (above), so an invalid stored value is
    injected into the record the reviewer reads to check its own fail-closed guard."""
    class NoModel(Assessor):
        def assess(self, *args):
            pytest.fail('invalid metadata must fail before the model')
    async with TrustMonitor(live(tmp_path)) as monitor:
        before = await monitor.observe(SERVER)
        _, backend = await eligible_memory(monitor, memory_enabled)
        doctored = replace(before, observed_tools=tuple(
            {**tool, 'description': invalid} for tool in before.observed_tools))
        status = monitor.status
        monkeypatch.setattr(monitor, 'status',
                            lambda server_id=None: doctored if server_id == SERVER else status(server_id))
        result = await reviewer(NoModel, backend)(monitor, SERVER)
        monkeypatch.undo()
        assert result.outcome == 'failed' and result.stage == 'retrieval'
        assert result.error_type == 'TypeError'
        assert backend is None or backend.searches == 0
        failed = monitor.events(SERVER)[-1]
        assert failed['event_type'] == 'model_assessment_failed'
        assert failed['detail']['stage'] == 'retrieval'
        after = monitor.status(SERVER)
        assert after.state == before.state and after.generation == before.generation
        assert not any(e['event_type'] == 'model_assessment_recorded' for e in monitor.events(SERVER))
