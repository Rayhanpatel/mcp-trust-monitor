"""External consumer checked against the installed wheel, never the source tree."""
from mcp.types import CallToolResult
from mcp_trust_monitor import (
    AssessmentContext,
    CallBlocked,
    CatalogEntry,
    DecisionRecord,
    DecisionRecords,
    MonitorConfig,
    MonitorHealth,
    PolicyRef,
    ReviewResult,
    SelectionToken,
    StorageFaultError,
    TrustMonitor,
    TrustRecord,
    export_decision_records,
)


def inspect_evidence(records: DecisionRecords) -> int:
    version: int = records['schema_version']
    for record in records['records']:
        decision: DecisionRecord = record
        before: int | None = decision['evidence']['received_before']
        requested: list[str] | None = decision['retrieval']['policy']['requested_content_ids']
        used: list[str] | None = decision['retrieval']['memory']['cited_lesson_ids']
        source: str | None = decision['context']['policy_digest']
        applied: bool = decision['decision']['action_applied']
        tokens: int | None = decision['model_response']['usage']['input_tokens']
        linked: str | None = decision['links'].get('assessment_event_id')
        _ = before, requested, used, source, applied, tokens, linked
    return version


async def use_monitor(config: MonitorConfig) -> DecisionRecords:
    async with TrustMonitor(config) as monitor:
        all_records: tuple[TrustRecord, ...] = monitor.status()
        single = monitor.status('example')
        # The legacy empty-string selector also returns a tuple, so str selectors
        # have an honest union instead of an unsound single-record annotation.
        if isinstance(single, TrustRecord):
            generation: int = single.generation
            _ = generation
        health: MonitorHealth = monitor.health()
        connected: bool = health['servers']['example']['connected']
        errors: dict[str, str] = health['errors']
        policy: PolicyRef = monitor.policy
        observed: TrustRecord = await monitor.observe('example')
        context: AssessmentContext = monitor.assessment_context('example')
        reason: str | None = monitor.assessment_stale_reason(context)
        review: ReviewResult = await monitor.review_once('example', observe=False)
        catalog: tuple[CatalogEntry, ...] = monitor.catalog('example')
        if catalog:
            selection: SelectionToken = catalog[0].selection
            try:
                result: CallToolResult = await monitor.call_tool(
                    'example', 'read', {'path': 'approved.txt'}, selection=selection)
                _ = result.isError
            except (CallBlocked, StorageFaultError):
                pass
        if observed.observed_revision is not None:
            approved: TrustRecord = await monitor.approve('example',
                revision=observed.observed_revision, expected_generation=observed.generation,
                actor='operator')
            _ = approved
        next_revision: int = await monitor.wait_for_catalog_change(
            monitor.catalog_revision, timeout=0.1)
        _ = all_records, connected, errors, policy, reason, review, next_revision
        return export_decision_records(monitor)
