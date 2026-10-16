#!/usr/bin/env python3
"""Post-evaluation live retrieval/revocation rehearsal; never resumes the frozen run.

Requires the completed, acceptable 48-trial evaluation and its unchanged live
owner. Makes exactly one additional model assessment attempt, disclosed outside
that evaluation. A real provider response is held before local validation; one
actually retrieved lesson is then revoked. This proves stale assessment rejection,
not that a network request was still pending at the instant of revocation.

No verdict/lesson approval, publication, remote deletion, tool call or restoration
is performed. Existing reports and failed attempts are never overwritten/retried.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp_trust_monitor import TrustMonitor, export_decision_records
from mcp_trust_monitor.async_assessor import AsyncOpenAIAssessor
from mcp_trust_monitor.history import sanitize
from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.memory_senso import SensoMemoryBackend
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer, _precedent_query
from mcp_trust_monitor.paired_evaluation import _gate, _verdict, digest, freeze_plan, summarize
from mcp_trust_monitor.policy import policy_rule_ids
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.senso import SensoClient
from scripts.release_memory import (REVIEW_CONFIG, configuration, read_settings,
    opaque_server_id, reject_heldout_summary, validate_active_sources,
    validate_evaluation_artifacts, validate_evaluation_id, validate_manifest)

REPORT = 'memory-rehearsal.json'


def file_digest(path):
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def validate_evaluation(directory, manifest):
    """Read-only gate. Never accept a claimed success without recomputing it."""
    if not directory.is_dir():
        raise ValueError('an existing release directory is required')
    validate_manifest(manifest)
    plan = json.loads((directory / 'paired-plan.json').read_text())
    report = json.loads((directory / 'paired-results.json').read_text())
    expected = freeze_plan(manifest, model=plan['model'], policy_binding=plan['policy_binding'],
        rules_digest=plan['rules_digest'], memory_digest=plan['memory_digest'],
        max_retries=plan['max_retries'], pairs=plan['pairs_per_case'],
        review_config=plan['review_config'])
    if (plan != expected or report.get('plan') != plan or len(plan['trials']) != 48
            or plan['max_retries'] != 0 or plan['review_config'] != REVIEW_CONFIG
            or report.get('complete') is not True or len(report.get('results', [])) != 48):
        raise ValueError('frozen evaluation is not complete or internally consistent')
    for scheduled, actual in zip(plan['trials'], report['results']):
        if (any(actual.get(key) != value for key, value in scheduled.items())
                or actual.get('status') != 'completed' or actual.get('model_status') != 'completed'
                or actual.get('detector_status') not in {'clean', 'matched'}
                or actual.get('model_name') != plan['model'] or actual.get('max_retries') != 0
                or actual.get('verdict') != _verdict(scheduled['expected_outcome'], actual.get('applied_outcome'))
                or actual.get('model_only_verdict') != _verdict(scheduled['expected_outcome'], actual.get('model_outcome'))
                or sorted(actual.get('detector_ids', [])) != sorted(scheduled['expected_detector'])
                or actual.get('detector_matches_expectation') is not True):
            raise ValueError('frozen trial evidence is inconsistent or failed')
    gate = _gate(report)
    if (report.get('gate') != gate or report.get('summary') != summarize(report['results'])
            or gate['release_blocked'] or gate['semantic_regressions_requiring_review']):
        raise ValueError('evaluation gate or unresolved semantic regressions block this rehearsal')
    return plan


def existing_configuration(directory, manifest, *, evaluation_id=None):
    """Reuse release configuration only when every fixture/state already exists."""
    if evaluation_id is not None:
        validate_evaluation_id(evaluation_id)
    paths = [directory / 'source' / case['id'] / 'definition.json'
             for case in manifest['lesson_source']]
    for pair in range(1, 4):
        for case in manifest['held_out']:
            for mode in ('off', 'on'):
                trial = f"{case['id']}/{pair}/{mode}"
                local = (directory / 'heldout' / trial if evaluation_id is None else
                    directory / 'evaluations' / evaluation_id / 'servers' /
                    opaque_server_id(evaluation_id, trial))
                paths.append(local / 'definition.json')
    database = directory / 'state/trust.sqlite3'
    if (not database.is_file() or (directory / 'state/owner.unclean').exists()
            or any(not path.is_file() for path in paths)):
        raise ValueError('release owner must be complete and cleanly closed')
    # All selected source/trial paths already exist; configuration cannot create
    # missing fixture definitions or silently replace an evaluated identity.
    config = configuration(directory, manifest, evaluation_id=evaluation_id)
    # Refuse a different Python executable/worktree before SDK identity handling
    # could invalidate a release record. Read-only SQLite includes committed WAL.
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
        identities = dict(db.execute('SELECT server_id, launch_identity FROM trust_records WHERE client_id=?',
                                     (config.client_id,)))
    # Other completed evaluations may legitimately share this owner. They are
    # not selected, launched or rewritten by this rehearsal.
    if not set(config.servers).issubset(identities) or any(
            identities[sid] != profile.launch_identity for sid, profile in config.servers.items()):
        raise ValueError('rehearsal launch configuration differs from the evaluated owner')
    return config


def selected_evaluation(directory, manifest, evaluation_id=None):
    """Read-only selection; the default retains the original root-report format."""
    if evaluation_id is None:
        return directory, validate_evaluation(directory, manifest), None
    validate_evaluation_id(evaluation_id)
    parent = directory / 'evaluations'
    output = parent / evaluation_id
    if parent.is_symlink() or output.is_symlink():
        raise ValueError('evaluation namespace cannot be a symlink')
    plan = validate_evaluation(output, manifest)
    protocol = json.loads((output / 'protocol.json').read_text())
    snapshot = json.loads((output / 'active-memory.json').read_text())
    if protocol.get('evaluation_id') != evaluation_id:
        raise ValueError('selected evaluation identity differs from its protocol')
    validate_evaluation_artifacts(output, directory, protocol, plan, snapshot)
    rows = json.loads((output / 'paired-results.json').read_text())['results']
    if any(row.get('server_id') != protocol['trial_servers'][row['trial_id']]
           or row.get('evaluation_id') != evaluation_id
           or row.get('protocol_digest') != protocol['protocol_digest'] for row in rows):
        raise ValueError('completed trials do not bind the selected opaque protocol')
    return output, plan, protocol


class TracedBackend:
    """Read-only delegation. No publication or deletion method is exposed here."""
    def __init__(self, backend):
        self.backend = backend
        self.capability_verified = backend.capability_verified
        self.capability_evidence = backend.capability_evidence
        self.searches = []

    async def node_content(self, node_id, *, version=None):
        return await self.backend.node_content(node_id, version=version)

    async def search_context(self, query, *, content_ids, top_k):
        attempt = {'requested_content_ids': list(content_ids), 'returned_content_ids': None,
                   'status': 'started'}
        self.searches.append(attempt)
        try:
            passages = await self.backend.search_context(query, content_ids=content_ids, top_k=top_k)
            attempt.update(status='completed', returned_content_ids=sorted({p.content_id for p in passages}))
            return passages
        except BaseException as exc:
            attempt.update(status='failed', error_type=type(exc).__name__)
            raise


def held_response_factory(*, parent=AsyncOpenAIAssessor):
    """Factory identity stays fixed throughout the review's configuration guard."""
    class HeldResponse(parent):
        response_ready = asyncio.Event()
        release_response = asyncio.Event()
        attempts = 0
        instance = None

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            HeldResponse.instance = self

        async def assess(self, *args):
            HeldResponse.attempts += 1
            raw = await super().assess(*args)
            HeldResponse.response_ready.set()
            # Only the locally delivered response is held. The real async request
            # has completed and its response metadata remains on this instance.
            await HeldResponse.release_response.wait()
            return raw
    return HeldResponse


def retrieval_evidence(retrieved):
    return {'status': retrieved.status, 'requested_content_ids': list(retrieved.requested_content_ids),
            'returned_content_ids': list(retrieved.returned_content_ids),
            'lessons': [{key: getattr(p, key) for key in
                ('lesson_id', 'version', 'digest', 'content_id', 'remote_version', 'source_version_id')}
                for p in retrieved.passages]}


def validate_prior_assessment(monitor, server_id, trial_result, policy_ids, revision):
    """Bind this extra assessment to the actual accepted trial/source configuration."""
    recorded = next((event for event in monitor.events(server_id)
                     if event['event_id'] == trial_result.get('assessment_event_id')), None)
    if recorded is None or recorded['event_type'] != 'model_assessment_recorded':
        raise ValueError('selected evaluation assessment is not recorded in this owner')
    detail = recorded['detail']
    if (recorded['server_id'] != server_id or detail.get('assessed_revision') != revision
            or tuple(detail.get('policy_requested_content_ids', ())) != tuple(policy_ids)
            or detail.get('response') != trial_result.get('response')):
        raise ValueError('selected assessment revision, policy sources or provider evidence differ')
    return recorded['event_id']


def checkpoint(path, report, secrets):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(sanitize(json.dumps(report, indent=2) + '\n', secrets))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


async def demonstrate(monitor, memory, backend, reviewer, factory, server_id, report, save):
    """One model attempt; failures remain recorded and never trigger a retry."""
    before = memory.snapshot(enabled=True)
    if len(before.lessons) < 2:
        raise ValueError('two active lessons are required for a nonempty post-revocation search')
    quarantines = {r.server_id: r.generation for r in monitor.status() if r.state.value == 'quarantined'}
    if not quarantines:
        raise ValueError('an existing quarantine is required to demonstrate preservation')
    report['quarantines_before'] = quarantines
    await monitor.observe(server_id)  # No approval or change to fixture bytes.
    context = monitor.assessment_context(server_id)
    baseline_events = {event['event_id'] for event in monitor.events()}
    task = asyncio.create_task(reviewer(monitor, server_id))
    ready = asyncio.create_task(factory.response_ready.wait())
    try:
        completed, _ = await asyncio.wait({task, ready}, timeout=reviewer.timeout_seconds + 60,
                                           return_when=asyncio.FIRST_COMPLETED)
        if ready not in completed or task.done():
            if task.done():
                report['assessment'] = asdict(task.result())
            raise RuntimeError('assessment did not reach the held completed-provider response')
        monitor_error = monitor.assessment_stale_reason(context)
        if monitor_error or memory.guard(before):
            raise RuntimeError('context changed before controlled revocation')
        returned = backend.searches[-1]['returned_content_ids'] if backend.searches else []
        candidates = [lesson for lesson in before.lessons if lesson.content_id in (returned or [])]
        if not candidates:
            raise RuntimeError('no active lesson was actually retrieved for the different case')
        lesson = candidates[0]  # Snapshot order, independent of model recommendation/outcomes.
        report['at_revocation_boundary'] = {'provider_completed': True,
            'assessment_application_pending': True, 'network_request_pending': False,
            'response': factory.instance.response_metadata()}
        report['revocation_intent'] = {'lesson_id': lesson.lesson_id, 'content_id': lesson.content_id,
            'reason': 'explicit post-evaluation live revocation rehearsal'}
        save()
        revoked = memory.revoke_lesson(lesson.lesson_id, actor='operator-live-rehearsal',
                                       reason=report['revocation_intent']['reason'])
        report['revocation'] = {'lesson_id': revoked.lesson_id, 'content_id': revoked.content_id,
            'state': revoked.state, 'remote_delete_requested': False}
        report['old_snapshot_invalidated'] = memory.guard(before) is not None
        save()
        factory.release_response.set()
        result = await task
        report['assessment'] = asdict(result)
        new_events = [e for e in monitor.events() if e['event_id'] not in baseline_events]
        stale = [e for e in new_events if e['event_type'] == 'assessment_stale' and e['server_id'] == server_id]
        accepted = [e for e in new_events if e['event_type'] in
                    {'model_assessment_recorded', 'quarantine_requested', 'quarantine_applied'}]
        report['stale_event_ids'] = [e['event_id'] for e in stale]
        report['accepted_decision_event_ids'] = [e['event_id'] for e in accepted]
        if (result.outcome != 'stale' or result.stage != 'model' or not stale or accepted
                or result.error_type != 'MemoryStale' or monitor.assessment_stale_reason(context)
                or not report['old_snapshot_invalidated'] or not result.response.get('response_id')):
            raise RuntimeError('old memory snapshot response was not demonstrably discarded')
        # The stale audit event retains validated retrieval evidence without
        # claiming that the discarded model result supplied accepted citations.
        retrieved = stale[-1]['detail']['memory']
        report['different_case_retrieval'] = {'status': retrieved['status'],
            'requested_content_ids': retrieved['requested_content_ids'],
            'lessons': [{key: p[key] for key in ('lesson_id', 'version', 'digest', 'content_id',
                                               'remote_version', 'source_version_id')}
                        for p in retrieved['passages']]}
        if lesson.lesson_id not in {p['lesson_id'] for p in retrieved['passages']}:
            raise RuntimeError('revoked lesson absent from validated model context')
        save()
        query = _precedent_query(monitor.status(server_id).observed_tools)
        remaining = memory.snapshot(enabled=True)
        expected_ids = {item.content_id for item in remaining.lessons}
        searches_before = len(backend.searches)
        after = await memory.retrieve(query, backend, enabled=True, top_k=reviewer.top_k)
        report['post_revocation_retrieval'] = retrieval_evidence(after)
        report['next_search_excluded_revoked'] = (len(backend.searches) == searches_before + 1
            and set(backend.searches[-1]['requested_content_ids']) == expected_ids
            and lesson.content_id not in after.requested_content_ids
            and lesson.content_id not in after.returned_content_ids)
        if not report['next_search_excluded_revoked']:
            raise RuntimeError('next actual search did not exclude revoked memory')
        remote = await backend.node_content(lesson.node_id, version=lesson.remote_version)
        report['remote_document_retained'] = (remote.content_id == lesson.content_id
            and remote.node_id == lesson.node_id and remote.version == lesson.remote_version
            and remote.text == lesson.body)
        report['quarantines_preserved'] = all(monitor.status(sid).state.value == 'quarantined'
                                              for sid in quarantines)
        report['new_approval_or_restore_events'] = [e['event_id'] for e in new_events
            if e['event_type'] in {'approved', 'restored', 'verdict_recorded', 'lesson_approved'}]
        if (not quarantines or not report['quarantines_preserved'] or not report['remote_document_retained']
                or report['new_approval_or_restore_events'] or factory.attempts != 1):
            raise RuntimeError('revocation boundary invariant failed')
        report['status'] = 'completed'
    finally:
        factory.release_response.set()
        ready.cancel()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, ready, return_exceptions=True)
        report['additional_model_attempts_outside_frozen_run'] = factory.attempts
        report['memory_searches'] = backend.searches
        save()


async def run(args):
    directory = args.directory.resolve()
    manifest = json.loads((ROOT / 'fixtures/memory_cases.json').read_text())
    evaluation_id = getattr(args, 'evaluation_id', None)
    output, plan, protocol = selected_evaluation(directory, manifest, evaluation_id)
    report_path = output / REPORT
    if report_path.exists():
        raise FileExistsError('rehearsal evidence already exists; retain it, including failures')
    config = existing_configuration(directory, manifest, evaluation_id=evaluation_id)
    if config.detector.rules_digest != plan['rules_digest']:
        raise ValueError('detector differs from the frozen evaluation')
    frozen_paths = [output / name for name in ('paired-plan.json', 'paired-results.json')]
    if protocol is not None:
        frozen_paths += [output / name for name in ('protocol.json', 'active-memory.json')]
    frozen_before = {p.name: file_digest(p) for p in frozen_paths}
    # Deterministic case selection uses schedule only, never model outcomes/labels.
    trial = next(t for t in plan['trials'] if t['memory'] == 'on')
    trial_result = next(row for row in json.loads((output / 'paired-results.json').read_text())['results']
                        if row['trial_id'] == trial['trial_id'])
    if trial_result['detector_status'] != 'clean' or trial['expected_detector']:
        raise ValueError('this rehearsal requires a previously detector-clean model assessment')
    sid = 'heldout/' + trial['trial_id'] if protocol is None else protocol['trial_servers'][trial['trial_id']]
    case = next(c for c in manifest['held_out'] if c['id'] == trial['case_id'])
    definition = (directory / sid / 'definition.json' if protocol is None else
                  output / 'servers' / sid / 'definition.json')
    if json.loads(definition.read_text()) != case['after']:
        raise ValueError('different-case metadata differs from its evaluated revision')
    settings = read_settings(args.env_file)
    secrets = [settings['OPENAI_API_KEY'], settings['SENSO_API_KEY']]
    report = {'schema': 'mcp-trust-monitor.memory-rehearsal', 'schema_version': 1,
        'origin': 'synthetic_fixture', 'started_at': datetime.now(timezone.utc).isoformat(),
        'status': 'started', 'gate_passed': False, 'error_type': None,
        'case_id': case['id'], 'server_id': sid, 'plan_digest': plan['plan_digest'],
        'evaluation_id': evaluation_id,
        'protocol_digest': protocol['protocol_digest'] if protocol else None,
        'paired_artifacts_before': frozen_before,
        'scope': 'Post-evaluation integrity demonstration, not another held-out accuracy trial.',
        'boundary': 'Provider completed; response held before local validation and application.',
        'model_configuration': {'model': plan['model'], 'max_retries': 0, **REVIEW_CONFIG},
        'additional_model_attempts_outside_frozen_run': 0, 'memory_searches': []}
    with report_path.open('x', encoding='utf-8') as file:
        json.dump(report, file, indent=2)
    save = lambda: checkpoint(report_path, report, secrets)
    try:
        senso = SensoClient(settings['SENSO_API_KEY'], attempts=1)
        backend = TracedBackend(SensoMemoryBackend(senso, capability_evidence=args.capability_evidence))
        factory = held_response_factory()
        reviewer = OpenAIReviewer(api_key=settings['OPENAI_API_KEY'], model=plan['model'],
            senso_client=senso, policy_content_ids=tuple(value.strip() for value in
                settings['SENSO_POLICY_CONTENT_IDS'].split(',') if value.strip()),
            memory_enabled=True, memory_backend=backend, memory_scope='release-evaluation',
            assessor_factory=factory, max_retries=0, **REVIEW_CONFIG)
        async with TrustMonitor(config) as monitor:
            memory = MemoryService(monitor.store, lambda: monitor.policy,
                rule_ids=policy_rule_ids(config.policy_path), scope='release-evaluation',
                excluded_revisions=tuple(server_revision([c['after']]) for c in manifest['held_out']),
                summary_validator=lambda summary: reject_heldout_summary(summary, manifest))
            before = memory.snapshot(enabled=True)
            if (monitor.policy.binding != plan['policy_binding']
                    or digest(before.as_dict()) != plan['memory_digest']):
                raise ValueError('active policy or memory differs from frozen evaluation')
            if protocol is not None:
                validate_evaluation_artifacts(output, directory, protocol, plan, before)
            validate_active_sources(memory, manifest, before)
            report['prior_assessment_event_id'] = validate_prior_assessment(monitor, sid, trial_result,
                reviewer.policy_content_ids, server_revision([case['after']]))
            try:
                await demonstrate(monitor, memory, backend, reviewer, factory, sid, report, save)
            finally:
                report['decision_records'] = export_decision_records(monitor)
    except BaseException as exc:
        report['status'], report['error_type'] = 'failed', type(exc).__name__
        if not isinstance(exc, Exception):
            raise
    finally:
        report['paired_artifacts_after'] = {p.name: file_digest(p) for p in frozen_paths}
        report['frozen_evaluation_unchanged'] = report['paired_artifacts_after'] == frozen_before
        report['gate_passed'] = report['status'] == 'completed' and report['frozen_evaluation_unchanged']
        save()
    print(json.dumps({'report': str(report_path), 'gate_passed': report['gate_passed'],
                      'error_type': report['error_type']}), flush=True)
    return 0 if report['gate_passed'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--evaluation-id', help='select a completed nested opaque evaluation; default is legacy root reports')
    parser.add_argument('--capability-evidence', type=Path,
                        default=ROOT / 'runtime/release/senso-capability.json')
    args = parser.parse_args(argv)
    try:
        return asyncio.run(run(args))
    except Exception as exc:
        print(json.dumps({'status': 'refused_or_failed', 'error_type': type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
