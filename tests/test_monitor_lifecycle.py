import asyncio
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
import pytest
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import ServerConfig, CallBlocked, ToolOutcomeUnknown
from mcp_trust_monitor.trust_store import TrustState
from conftest import POLICY_PATH

pytestmark = pytest.mark.anyio


def setup(tmp_path, **settings):
    path = tmp_path/'server.json'
    path.write_text(json.dumps(settings))
    log = tmp_path/'calls.jsonl'
    profile = ServerConfig('custom/local', sys.executable,
        (str(Path(__file__).parent/'helpers'/'monitored_server.py'),str(path),str(log)),
        origin='synthetic_fixture')
    cfg = MonitorConfig(tmp_path/'state', POLICY_PATH, {profile.server_id:profile},
                        poll_interval=.1, timeout_seconds=1)
    return cfg,path,log

async def approve(m):
    record = await m.observe('custom/local')
    await m.approve('custom/local',revision=record.observed_revision,
                    expected_generation=record.generation,actor='operator')

async def until(predicate, seconds=2):
    end = time.monotonic()+seconds
    while not predicate():
        if time.monotonic()>end:
            raise AssertionError('condition did not become true')
        await asyncio.sleep(.01)

async def test_notification_during_list_cannot_clear_later_dirty_epoch(tmp_path):
    cfg,path,log=setup(tmp_path)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        path.write_text(json.dumps({'notify_during_list':True}))
        await m.observe('custom/local')
        assert m.catalog()==()
        with pytest.raises(CallBlocked,match='session_dirty'):
            await m.call_tool('custom/local','effect')
        assert not log.exists()
        path.write_text('{}')
        await m.observe('custom/local')
        assert m.catalog()
        assert 'annotations' not in m.catalog()[0].definition

async def test_notification_and_quarantine_while_call_response_is_pending(tmp_path):
    cfg,path,log=setup(tmp_path,notify_during_call=True,call_delay=10)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        task=asyncio.create_task(m.call_tool('custom/local','effect'))
        await until(lambda:log.exists())
        await until(lambda:m.health()['servers']['custom/local']['freshness']=='session_dirty')
        assert not task.done()
        assert m.catalog()==()
        await asyncio.wait_for(m.quarantine('custom/local',actor='operator',reason='test'),2)
        assert m.status('custom/local').state is TrustState.QUARANTINED
        await asyncio.gather(task,return_exceptions=True)
        with pytest.raises(CallBlocked):
            await m.call_tool('custom/local','effect')
        assert len(log.read_text().splitlines())==1
        kinds=[row['event_type'] for row in m.events()]
        assert 'call_dispatch_started' in kinds and 'call_completed' in kinds
        assert next(row for row in m.events() if row['event_type']=='call_completed')['detail']['outcome']=='outcome_unknown'

async def test_side_effect_lost_response_is_never_replayed(tmp_path):
    cfg,path,log=setup(tmp_path,drop_response=True)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        with pytest.raises(ToolOutcomeUnknown):
            await m.call_tool('custom/local','effect')
        assert len(log.read_text().splitlines())==1
        assert m.client.dispatch_count('custom/local')==1

async def test_polling_detects_change_without_notifications_and_stops(tmp_path):
    cfg,path,log=setup(tmp_path)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        await m.start_monitor()
        path.write_text(json.dumps({'description':'The description changed.'}))
        await until(lambda:m.status('custom/local').state is TrustState.PENDING_REVIEW)
        assert m.catalog()==()
        await m.stop_monitor()
        assert m.health()['status']=='stopped'
        assert not m._loop.tasks

async def test_async_review_does_not_block_quarantine_or_repeat_unchanged(tmp_path):
    from dataclasses import replace
    cfg,path,log=setup(tmp_path)
    entered,finish=asyncio.Event(),asyncio.Event()
    calls=[]
    async def reviewer(m,sid):
        calls.append(sid)
        entered.set()
        await finish.wait()
        return SimpleNamespace(outcome='review')
    async with TrustMonitor(replace(cfg,reviewer=reviewer)) as m:
        await m.start_monitor()
        await asyncio.wait_for(entered.wait(),2)
        await asyncio.wait_for(m.quarantine('custom/local',actor='operator',reason='test'),2)
        finish.set()
        await asyncio.sleep(.35)
        await m.stop_monitor()
        assert len(calls)==1
        assert m.status('custom/local').state is TrustState.QUARANTINED

async def test_observation_invalidation_continues_while_model_is_blocked(tmp_path):
    from dataclasses import replace
    cfg,path,log=setup(tmp_path)
    entered,finish=asyncio.Event(),asyncio.Event()
    async def reviewer(m,sid):
        entered.set()
        await finish.wait()
        return SimpleNamespace(outcome='review')
    async with TrustMonitor(replace(cfg,reviewer=reviewer,max_concurrency=1)) as m:
        await approve(m)
        await m.start_monitor()
        await asyncio.wait_for(entered.wait(),2)
        path.write_text(json.dumps({'description':'A different definition while model awaits.'}))
        await until(lambda:m.status('custom/local').state is TrustState.PENDING_REVIEW)
        assert not finish.is_set()
        assert m.catalog()==()
        finish.set()
        await m.stop_monitor()

async def test_missing_secret_reference_is_bounded_and_invalidates_observation(tmp_path,monkeypatch):
    from dataclasses import replace
    from mcp_trust_monitor.managed_client import ObservationError
    cfg,path,log=setup(tmp_path)
    profile=replace(cfg.servers['custom/local'],secret_env={'AUTH':'MISSING_MTM_TEST_CREDENTIAL'})
    monkeypatch.delenv('MISSING_MTM_TEST_CREDENTIAL',raising=False)
    async with TrustMonitor(replace(cfg,servers={profile.server_id:profile})) as m:
        with pytest.raises(ObservationError):
            await asyncio.wait_for(m.observe('custom/local'),2)
        assert m.events('custom/local')[-1]['event_type']=='observation_failed'
        assert not m.client.is_connected('custom/local')

async def test_monitor_refreshes_each_live_session_without_launching_unused_sessions(tmp_path):
    cfg,path,log=setup(tmp_path)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        other=m.new_session()
        unused=m.new_session()
        await other.observe('custom/local')
        original=other._connections['custom/local'].observed_at
        await m.start_monitor()
        await until(lambda:other._connections['custom/local'].observed_at>original)
        await asyncio.sleep(.25)
        assert other.catalog('custom/local')
        assert not unused.is_connected('custom/local')
        await m.stop_monitor()

async def test_catalog_change_waits_for_expiry_and_approval(tmp_path):
    cfg,path,log=setup(tmp_path)
    async with TrustMonitor(cfg) as m:
        record=await m.observe('custom/local')
        previous=m.catalog_revision
        waiting=asyncio.create_task(m.wait_for_catalog_change(previous,timeout=1))
        await m.approve('custom/local',revision=record.observed_revision,
                        expected_generation=record.generation,actor='operator')
        assert await waiting>previous
        assert m.catalog()
        await m.wait_for_catalog_change(m.catalog_revision,timeout=1)
        assert not m.catalog()

async def test_guarded_quarantine_disconnects_all_owned_sessions(tmp_path):
    cfg,path,log=setup(tmp_path)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        other=m.new_session()
        await other.observe('custom/local')
        current=m.status('custom/local')
        result=await other.apply_hard_deny('custom/local',revision=current.observed_revision,
            generation=current.generation,policy_context=m.policy.binding,
            active_policy_context=lambda:m.policy.binding,detection={'matched':True})
        assert result.status=='applied'
        assert not other.is_connected('custom/local')
        assert not m.client.is_connected('custom/local')

async def test_notification_then_identical_refresh_stales_assessment_snapshot(tmp_path):
    cfg,path,log=setup(tmp_path,notify_during_call=True)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        snapshot=m.assessment_context('custom/local')
        await m.call_tool('custom/local','effect')
        await until(lambda:m.health()['servers']['custom/local']['freshness']=='session_dirty')
        assert m.assessment_stale_reason(snapshot)
        await m.observe('custom/local')
        assert m.catalog()
        assert m.assessment_stale_reason(snapshot)
        result=await m.client.record_assessment_if_current('custom/local',
            revision=snapshot.revision,generation=snapshot.generation,
            policy_context=m.policy.binding,active_policy_context=lambda:m.policy.binding,
            detail={'recommendation':'review'},context_guard=lambda:m.assessment_stale_reason(snapshot))
        assert result.status=='stale'

async def test_hard_deny_skips_optional_model_without_reopening_transport(tmp_path):
    from dataclasses import replace
    cfg,path,log=setup(tmp_path)
    calls=[]
    async def reviewer(m,sid):
        calls.append(sid)
    result=SimpleNamespace(matches=('match',),as_dict=lambda:{'matched':True})
    detector=SimpleNamespace(validate=lambda path:None,scan=lambda tools,path:result,rules_digest='rules-v1')
    async with TrustMonitor(replace(cfg,detector=detector,reviewer=reviewer)) as m:
        reviewed=await m.review_once('custom/local')
        assert reviewed.detector=='matched'
        assert reviewed.assessment=='skipped_hard_deny'
        assert reviewed.outcome=='quarantined'
        assert not calls
        assert not m.client.is_connected('custom/local')

async def test_cancelled_observation_invalidates_shared_approval(tmp_path,monkeypatch):
    cfg,path,log=setup(tmp_path)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        entered=asyncio.Event()
        async def hang(*args):
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(m.client,'_list_tools',hang)
        task=asyncio.create_task(m.observe('custom/local'))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert m.status('custom/local').state is TrustState.PENDING_REVIEW
        assert m.status('custom/local').observation_failed_at
        assert not m.catalog()

async def test_stopping_monitor_reaps_active_builtin_scanner(tmp_path,monkeypatch):
    import os
    from dataclasses import replace
    from mcp_trust_monitor.policy import DetectorBinding,load_policy
    from mcp_trust_monitor.detector import DEFAULT_RULES,rules_digest_of
    cfg,path,log=setup(tmp_path)
    pidfile=tmp_path/'scanner.pid'
    scanner=tmp_path/'slow-scanner'
    scanner.write_text(f'#!{sys.executable}\nimport os,time\nopen({str(pidfile)!r},"w").write(str(os.getpid()))\ntime.sleep(30)\n')
    scanner.chmod(0o755)
    monkeypatch.setenv('MCP_TRUST_SEMGREP',str(scanner))
    # This lifecycle proof uses a simple declared JSON rule inventory; the fake
    # scanner only tests process cancellation, never detection correctness.
    rules=tmp_path/'rules.json'
    rules.write_text(json.dumps({'rules':[
        {'id':'r1','metadata':{'policy_id':'POL-001'}},
        {'id':'r2','metadata':{'policy_id':'POL-002'}}]}))
    detector=DetectorBinding(rules,load_policy(POLICY_PATH).digest,rules_digest_of(rules.read_bytes()),
                             {'r1':'POL-001','r2':'POL-002'})
    async with TrustMonitor(replace(cfg,detector=detector,timeout_seconds=20)) as m:
        await m.start_monitor()
        await until(pidfile.exists)
        pid=int(pidfile.read_text())
        await asyncio.wait_for(m.stop_monitor(),2)
        with pytest.raises(ProcessLookupError):
            os.kill(pid,0)
        assert not m._loop.review_tasks

async def test_changed_executable_symlink_reconnects_before_new_identity_observation(tmp_path):
    import shlex
    from dataclasses import replace
    cfg,path,log=setup(tmp_path)
    first=tmp_path/'first-launcher'
    second=tmp_path/'second-launcher'
    for target in (first,second):
        target.write_text('#!/bin/sh\nexec '+shlex.quote(sys.executable)+' "$@"\n')
        target.chmod(0o755)
    link=tmp_path/'launcher';link.symlink_to(first)
    profile=replace(cfg.servers['custom/local'],command=str(link))
    async with TrustMonitor(replace(cfg,servers={profile.server_id:profile})) as m:
        await approve(m)
        old_session=m.health()['servers']['custom/local']['session_id']
        old_identity=m.status('custom/local').launch_identity
        link.unlink();link.symlink_to(second)
        changed=await m.observe('custom/local')
        assert changed.launch_identity!=old_identity
        assert changed.state is TrustState.PENDING_REVIEW
        assert m.health()['servers']['custom/local']['session_id']!=old_session
        assert not m.catalog()

async def test_owner_close_cancels_and_joins_caller_started_review(tmp_path):
    from dataclasses import replace
    cfg,path,log=setup(tmp_path)
    entered=asyncio.Event()
    stopped=asyncio.Event()
    async def reviewer(m,sid):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()
    monitor=await TrustMonitor(replace(cfg,reviewer=reviewer)).__aenter__()
    task=asyncio.create_task(monitor.review_once('custom/local'))
    await asyncio.wait_for(entered.wait(),2)
    await asyncio.wait_for(monitor.aclose(),2)
    assert task.cancelled() and stopped.is_set()
    assert not (cfg.state_dir/'owner.unclean').exists()
    # Ownership can be acquired again after all old review work stopped.
    async with TrustMonitor(cfg):
        pass

async def test_owner_close_cancels_manual_observation_and_reaps_process(tmp_path):
    import os
    started=tmp_path/'observation.pid'
    cfg,path,log=setup(tmp_path,list_delay=20,list_started=str(started))
    monitor=await TrustMonitor(cfg).__aenter__()
    other=monitor.new_session()
    task=asyncio.create_task(other.observe('custom/local'))
    await until(started.exists)
    pid=int(started.read_text())
    await asyncio.wait_for(monitor.aclose(),2)
    assert task.cancelled()
    with pytest.raises(ProcessLookupError):
        os.kill(pid,0)
    assert not (cfg.state_dir/'owner.unclean').exists()

async def test_notification_flood_is_bounded_and_does_not_starve_control(tmp_path):
    from dataclasses import replace
    cfg,path,log=setup(tmp_path,notify_during_list=True)
    control_path=tmp_path/'control.json';control_path.write_text('{}')
    control_log=tmp_path/'control.calls'
    control=ServerConfig('control',sys.executable,
        (str(Path(__file__).parent/'helpers'/'monitored_server.py'),str(control_path),str(control_log)),
        origin='synthetic_fixture')
    servers={**cfg.servers,control.server_id:control}
    async with TrustMonitor(replace(cfg,servers=servers,max_concurrency=1,poll_interval=.5)) as m:
        await m.start_monitor()
        await until(lambda:m.status('control') is not None)
        record=m.status('control')
        await m.approve('control',revision=record.observed_revision,
                        expected_generation=record.generation,actor='operator')
        await m.call_tool('control','effect')
        assert len(control_log.read_text().splitlines())==1
        for _ in range(10):
            assert len(m._loop.pending)<=len(servers)
            assert len(m._loop.queue)<=len(servers)
            await asyncio.sleep(.01)
        assert m.catalog('control')
        assert not m.catalog('custom/local')
        await m.stop_monitor()
