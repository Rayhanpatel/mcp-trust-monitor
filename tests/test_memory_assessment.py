"""Precedents stay separate from policy authority and current metadata evidence."""
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mcp_trust_monitor.assessor import (AssessmentRejected, OpenAIAssessor, INSTRUCTIONS,
    assessment_schema, build_input)
from mcp_trust_monitor.memory import (MemoryIntegrityError, MemorySnapshot,
    RetrievedMemory, RetrievedPrecedent)
from mcp_trust_monitor.memory.assessment import (MEMORY_INSTRUCTIONS, memory_schema,
    memory_input, validate_memory_assessment)
from test_model_review import context, raw, retrieved_policy, FakeResponses, fake_response, message


def memory():
    return RetrievedMemory(MemorySnapshot('client', 'scope', 'policy', 4, (), True),
        (RetrievedPrecedent('lesson-1', 1, 'sha256:abc', 'precedent-content', '1',
                            'An earlier description moved private content externally.'),),
        ('precedent-content', 'eligible-not-returned'), 'returned')


def test_valid_separate_citations_and_policy_only_empty_precedents():
    ctx = context()
    result = validate_memory_assessment({**raw(ctx), 'precedent_ids':['lesson-1']}, ctx, memory())
    assert result.recommendation == 'quarantine'
    assert result.precedent_ids == ('lesson-1',)
    assert result.assessment.source_content_ids == ctx.source_content_ids
    empty = replace(memory(), passages=(), status='none_returned')
    assert validate_memory_assessment({**raw(ctx), 'precedent_ids':[]}, ctx, empty).precedent_ids == ()


@pytest.mark.parametrize('change', [
    {'precedent_ids':['eligible-not-returned']},
    {'precedent_ids':['lesson-1', 'lesson-1']},
    {'precedent_ids':'lesson-1'},
    {'source_content_ids':['precedent-content']},
    {'source_content_ids':[]},
    {'evidence':[{'tool':'lookup_document', 'text':'An earlier description moved private content externally.'}]},
    {'recommendation':'approve'},
])
def test_historical_context_cannot_replace_current_evidence_or_authority(change):
    ctx = context()
    with pytest.raises(AssessmentRejected):
        validate_memory_assessment({**raw(ctx), 'precedent_ids':['lesson-1'], **change}, ctx, memory())


def test_even_misconfigured_overlapping_content_ids_cannot_merge_authority():
    ctx = replace(context(), source_content_ids=('precedent-content',))
    with pytest.raises(AssessmentRejected, match='operator-policy'):
        validate_memory_assessment({**raw(ctx), 'precedent_ids':['lesson-1']}, ctx, memory())


def test_missing_precedent_field_and_false_empty_claim_are_rejected():
    ctx = context()
    with pytest.raises(AssessmentRejected, match='required'):
        validate_memory_assessment(raw(ctx), ctx, memory())
    with pytest.raises(AssessmentRejected, match='unretrieved'):
        validate_memory_assessment({**raw(ctx), 'precedent_ids':['lesson-1']}, ctx,
            replace(memory(), passages=(), status='none_returned'))


def test_bounded_context_rejects_oversize_without_mutating_exact_evidence():
    ctx = context()
    result = memory_input(ctx, (), retrieved_policy(), memory())
    assert ctx.tools[0]['description'] in result
    assert '<untrusted_precedents>' in result
    assert 'eligible-not-returned' not in result
    with pytest.raises(MemoryIntegrityError, match='100-tool'):
        memory_input(replace(ctx, tools=ctx.tools*101), (), retrieved_policy(), memory())
    with pytest.raises(MemoryIntegrityError, match='65536-character'):
        memory_input(context('x'*65537), (), retrieved_policy(), memory())
    with pytest.raises(MemoryIntegrityError, match='context limit'):
        memory_input(ctx, (), retrieved_policy(), replace(memory(), passages=memory().passages*21))


def test_assessor_default_requests_unchanged_and_memory_customization_explicit():
    ctx = context(); policy = retrieved_policy(); retrieved = memory()
    response = fake_response(output=[message(SimpleNamespace(type='output_text', text=json.dumps(raw(ctx))))])
    responses = FakeResponses(response)
    OpenAIAssessor('unused', client=SimpleNamespace(responses=responses)).assess(ctx, (), policy)
    baseline = responses.calls[-1]
    assert baseline['instructions'] == INSTRUCTIONS
    assert baseline['input'] == build_input(ctx, (), policy)
    assert baseline['text']['format']['schema'] == assessment_schema(ctx.rule_ids)
    assessor = OpenAIAssessor('unused', client=SimpleNamespace(responses=responses),
        instructions=MEMORY_INSTRUCTIONS,
        input_builder=lambda c, previous, p: memory_input(c, previous, p, retrieved),
        schema_builder=lambda rules: memory_schema(rules, retrieved.lesson_ids))
    assessor.assess(ctx, (), policy)
    request = responses.calls[-1]
    schema = request['text']['format']['schema']
    assert request['instructions'] == MEMORY_INSTRUCTIONS
    assert 'precedent_ids' in schema['required']
    assert schema['properties']['precedent_ids']['items']['enum'] == ['lesson-1']
    assert schema['properties']['recommendation']['enum'] == ['review', 'quarantine']
    assert request['store'] is False and 'tools' not in request
