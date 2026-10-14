"""Deliberate errors: the checker must reject these, with no ignores/casts."""
from mcp_trust_monitor import TrustMonitor, export_decision_records


async def invalid(monitor: TrustMonitor) -> None:
    revision: str = monitor.catalog_revision
    monitor.health()['servers']['example']['connected'] = 'yes'
    export = export_decision_records(monitor)
    export['schema_version'] = 1
    missing = export['records'][0]['missing_field']
    tokens: int = export['records'][0]['model_response']['usage']['input_tokens']
    await monitor.approve('example', revision='rev', expected_generation='one', actor='operator')
    await monitor.call_tool('example', 'read', selection='not-a-selection-token')
    _ = revision, missing, tokens
