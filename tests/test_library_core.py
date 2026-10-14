"""Strict installed-library behavior; real stdio transport, no cloud services."""
import asyncio
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
import pytest
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.managed_client import CallBlocked, ServerConfig
from mcp_trust_monitor.trust_store import (TrustStore, TrustState, StorageFaultError,
    SchemaCompatibilityError, ObservationRequiredError, StaleDecisionError)
from mcp_trust_monitor.ownership import OwnershipError
from mcp_trust_monitor import demo_server as demo
from conftest import LOOKUP, CONTROL, POLICY_PATH, FIXTURE_PATH

pytestmark = pytest.mark.anyio


def config(env, **kwargs):
    return MonitorConfig(env.state_dir, POLICY_PATH,
        {sid: demo.server_config(sid, env.state_dir, FIXTURE_PATH) for sid in demo.DEMO_SERVERS},
        **kwargs)

async def approve(m, sid=LOOKUP):
    record = await m.observe(sid)
    return await m.approve(sid, revision=record.observed_revision,
                           expected_generation=record.generation, actor='operator')

async def test_catalog_and_selection_guard_and_plain_new_session(env):
    cfg = config(env)
    async with TrustMonitor(cfg) as m:
        assert m.catalog() == ()
        record = await approve(m)
        entry, = m.catalog(LOOKUP)
        assert set(entry.definition) == {'name', 'description', 'inputSchema'}
        with pytest.raises(TypeError):
            entry.definition['description'] = 'replacement'
        assert not (await m.call_tool(LOOKUP, 'lookup_document', {'title':'x'}, selection=entry.selection)).isError
        second = m.new_session()
        with pytest.raises(CallBlocked, match='session_refresh_required'):
            await second.call_tool(LOOKUP, 'lookup_document')
        assert not second.is_connected(LOOKUP)
        blocked=m.events(LOOKUP)[-1]
        assert blocked['event_type']=='call_blocked'
        assert blocked['detail']['local_nondispatch'] is True
        assert blocked['detail']['independent_verification']=='verification_unavailable'
        assert 'verified' not in blocked['detail']
        assert env.received_calls(LOOKUP)==1
        await second.observe_and_call(LOOKUP, 'lookup_document', {'title':'x'})
        assert env.received_calls(LOOKUP) == 2
        await m.quarantine(LOOKUP, actor='operator', reason='test')
        assert m.catalog(LOOKUP) == ()
        current = m.status(LOOKUP)
        await m.restore(LOOKUP, revision=current.observed_revision,
                        expected_generation=current.generation, actor='operator')
        with pytest.raises(CallBlocked, match='stale_selection'):
            await m.observe_and_call(LOOKUP, 'lookup_document', selection=entry.selection)
        assert env.received_calls(LOOKUP) == 2

async def test_cli_style_owner_reopen_requires_explicit_refresh(env):
    cfg = config(env)
    async with TrustMonitor(cfg) as m:
        observed = await m.observe(LOOKUP)
    async with TrustMonitor(cfg) as m:
        await m.approve(LOOKUP, revision=observed.observed_revision,
                        expected_generation=observed.generation, actor='operator')
    async with TrustMonitor(cfg) as m:
        with pytest.raises(CallBlocked, match='session_refresh_required'):
            await m.call_tool(LOOKUP, 'lookup_document')
        assert not m.client.is_connected(LOOKUP)
        await m.observe_and_call(LOOKUP, 'lookup_document', {'title':'x'})
        assert env.received_calls(LOOKUP) == 1

async def test_identity_change_invalidates_identical_metadata_before_launch(env):
    cfg = config(env)
    async with TrustMonitor(cfg) as m:
        await approve(m)
    changed = dict(cfg.servers)
    changed[LOOKUP] = replace(changed[LOOKUP], env={'NONSECRET_SETTING':'new'})
    async with TrustMonitor(replace(cfg, servers=changed)) as m:
        assert m.status(LOOKUP).state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await m.observe_and_call(LOOKUP, 'lookup_document')
        assert not m.client.is_connected(LOOKUP)
        record = m.status(LOOKUP)
        with pytest.raises(ObservationRequiredError):
            await m.approve(LOOKUP, revision=record.observed_revision,
                            expected_generation=record.generation, actor='operator')
        await approve(m)
        await m.call_tool(LOOKUP, 'lookup_document', {'title':'x'})

async def test_freshness_is_per_session_and_survives_monitor_stop(env):
    async with TrustMonitor(config(env, poll_interval=.05)) as m:
        await approve(m)
        other = m.new_session()
        await other.observe(LOOKUP)
        await asyncio.sleep(.11)
        await m.observe(LOOKUP)
        assert m.catalog(LOOKUP)
        assert other.catalog(LOOKUP) == ()
        with pytest.raises(CallBlocked, match='session_stale'):
            await other.call_tool(LOOKUP, 'lookup_document')
        await m.stop_monitor()
        await asyncio.sleep(.11)
        assert not m.catalog(LOOKUP)

async def test_owner_and_future_schema_refusal_before_marker_change(env):
    cfg = config(env)
    async with TrustMonitor(cfg):
        with pytest.raises(OwnershipError):
            async with TrustMonitor(cfg):
                pass
    db = sqlite3.connect(env.state_dir/'trust.sqlite3')
    db.execute('PRAGMA user_version=999'); db.close()
    marker = env.state_dir/'owner.unclean'
    marker.write_text('old marker')
    before = (env.state_dir/'trust.sqlite3').read_bytes()
    with pytest.raises(SchemaCompatibilityError):
        async with TrustMonitor(cfg):
            pass
    assert marker.read_text() == 'old marker'
    assert (env.state_dir/'trust.sqlite3').read_bytes() == before

async def test_authoritative_write_fault_blocks_every_session_and_recovers(env):
    cfg = config(env)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        await approve(m, CONTROL)
        other = m.new_session()
        await other.observe(CONTROL)
        m.store._db.execute('PRAGMA query_only=ON')
        with pytest.raises(StorageFaultError):
            await m.quarantine(LOOKUP, actor='operator', reason='test')
        with pytest.raises(StorageFaultError):
            await other.call_tool(CONTROL, 'health_check')
        with pytest.raises(StorageFaultError):
            m.catalog()
    assert (env.state_dir/'owner.unclean').exists()
    async with TrustMonitor(cfg) as m:
        for sid in (LOOKUP, CONTROL):
            record = m.status(sid)
            assert record.state is TrustState.PENDING_REVIEW
            assert record.observation_failed_at
            with pytest.raises(ObservationRequiredError):
                await m.approve(sid, revision=record.observed_revision,
                                expected_generation=record.generation, actor='operator')
        await approve(m)
        await m.call_tool(LOOKUP, 'lookup_document', {'title':'x'})

async def test_transaction_seams_reject_stale_review_and_nested_registry(env):
    async with TrustMonitor(config(env)) as m:
        record = await m.observe(LOOKUP)
        with m.store.atomic() as db:
            db.execute('CREATE TABLE memory_test(value TEXT)')
            with m.store.atomic() as nested:
                nested.execute("INSERT INTO memory_test VALUES ('x')")
            m.store.emit_event_in_transaction(db, None, 'lesson_test', 'operator', {'value':'x'})
        result = await m.client.record_assessment_if_current(LOOKUP,
            revision=record.observed_revision, generation=record.generation,
            policy_context=m.policy.binding, active_policy_context=lambda:m.policy.binding,
            detail={'recommendation':'review'}, context_guard=lambda:'memory changed')
        assert result.status == 'stale'
        assert m.store.events(LOOKUP)[-1]['event_type'] == 'assessment_stale'
        assert any(row['payload']['event_type']=='lesson_test' for row in m.store.pending_outbox())

async def test_corrupt_authoritative_record_latches_catalog_and_dispatch(env):
    async with TrustMonitor(config(env)) as m:
        await approve(m)
        m.store._db.execute("UPDATE trust_records SET observed_tools='not-json'")
        with pytest.raises(StorageFaultError):
            m.status(LOOKUP)
        with pytest.raises(StorageFaultError):
            await m.call_tool(LOOKUP, 'lookup_document')

async def test_config_freezes_launch_cwd_and_path(env, monkeypatch, tmp_path):
    cfg = config(env)
    identities = {sid: profile.launch_identity for sid, profile in cfg.servers.items()}
    other = tmp_path/'another-directory';other.mkdir()
    async with TrustMonitor(cfg) as m:
        await approve(m)
        monkeypatch.chdir(other)
        monkeypatch.setenv('PATH','/no/executables')
        await m.observe(LOOKUP)
        assert {sid: profile.launch_identity for sid, profile in cfg.servers.items()} == identities
        assert m.status(LOOKUP).state is TrustState.APPROVED
        await m.call_tool(LOOKUP,'lookup_document',{'title':'x'})

async def test_policy_reload_rejects_bad_detector_without_losing_active_pair(env,tmp_path):
    from mcp_trust_monitor.policy import DetectorBinding,load_policy
    from mcp_trust_monitor.detector import rules_digest_of
    from mcp_trust_monitor.config import ConfigurationError
    rules=tmp_path/'rules.json'
    rules.write_text(json.dumps({'rules':[
        {'id':'r1','metadata':{'policy_id':'POL-001'}},
        {'id':'r2','metadata':{'policy_id':'POL-002'}}]}))
    binding=DetectorBinding(rules,load_policy(POLICY_PATH).digest,
                            rules_digest_of(rules.read_bytes()),{'r1':'POL-001','r2':'POL-002'})
    cfg=config(env,detector=binding)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        original=m.policy
        path=tmp_path/'changed-policy.json'
        document=json.loads(POLICY_PATH.read_text());document['revision']='next'
        path.write_text(json.dumps(document))
        with pytest.raises(ConfigurationError):
            await m.reload_policy(path)
        assert m.policy==original and m.status(LOOKUP).state is TrustState.APPROVED
        updated=replace(binding,policy_digest=load_policy(path).digest)
        await m.reload_policy(path,updated)
        assert m.policy_path==path.resolve()
        assert m.status(LOOKUP).state is TrustState.PENDING_REVIEW
        assert not m.catalog()

async def test_supported_migration_is_atomic_and_preserves_quarantine(tmp_path,monkeypatch):
    from mcp_trust_monitor import trust_store as module
    path=tmp_path/'legacy.sqlite3'
    db=sqlite3.connect(path)
    db.execute("CREATE TABLE trust_records (client_id TEXT NOT NULL,server_id TEXT NOT NULL,state TEXT NOT NULL,observed_revision TEXT,observed_tools TEXT NOT NULL DEFAULT '[]',approved_revision TEXT,approved_policy_revision TEXT,generation INTEGER NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(client_id,server_id))")
    db.execute("INSERT INTO trust_records VALUES('default','s','quarantined',NULL,'[]',NULL,NULL,4,'old')")
    db.execute('PRAGMA user_version=1');db.commit();db.close()
    read=TrustStore.open_readonly(path,'default')
    assert read.get('s').state is TrustState.QUARANTINED
    read.close()
    execute=module._GuardedConnection.execute
    def interrupted(self,sql,*args,**kwargs):
        if 'ADD COLUMN origin' in sql:
            raise RuntimeError('migration interrupted')
        return execute(self,sql,*args,**kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(module._GuardedConnection,'execute',interrupted)
        with pytest.raises(RuntimeError):
            TrustStore(path,'default')
    db=sqlite3.connect(path)
    assert db.execute('PRAGMA user_version').fetchone()[0]==1
    assert 'observation_failed_at' not in {row[1] for row in db.execute('PRAGMA table_info(trust_records)')}
    db.close()
    store=TrustStore(path,'default')
    assert store.get('s').state is TrustState.QUARANTINED
    assert store.get('s').generation==4
    store.close()
    read=TrustStore.open_readonly(path,'default')
    assert read.get('s').state is TrustState.QUARANTINED
    read.close()

async def test_closed_authoritative_connection_faults_before_registry_transaction(env):
    async with TrustMonitor(config(env)) as m:
        await approve(m)
        m.store._db.close()
        with pytest.raises(StorageFaultError):
            with m.store.atomic():
                pass
        assert m.store.faulted
        with pytest.raises(StorageFaultError):
            await m.call_tool(LOOKUP,'lookup_document')

async def test_unchanged_policy_reopen_does_not_repeat_reload_audit(env):
    cfg=config(env)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        await m.quarantine(LOOKUP,actor='operator',reason='test')
    async with TrustMonitor(cfg) as m:
        previous=[row['event_id'] for row in m.events() if row['event_type']=='policy_reloaded']
        generation=m.status(LOOKUP).generation
    async with TrustMonitor(cfg) as m:
        assert [row['event_id'] for row in m.events() if row['event_type']=='policy_reloaded']==previous
        assert m.status(LOOKUP).generation==generation
        assert m.status(LOOKUP).state is TrustState.QUARANTINED

async def test_marker_durability_failure_refuses_store_creation(env,monkeypatch):
    from mcp_trust_monitor.ownership import StateOwner
    def fail(self):
        raise OSError('directory durability unavailable')
    monkeypatch.setattr(StateOwner,'_sync_directory',fail)
    with pytest.raises(OSError,match='durability'):
        async with TrustMonitor(config(env)):
            pytest.fail('owner opened before durable marker')
    assert not (env.state_dir/'trust.sqlite3').exists()

async def test_unclean_owner_recovery_preserves_quarantine_and_requires_new_observation(env):
    cfg=config(env)
    async with TrustMonitor(cfg) as m:
        await approve(m)
        await m.quarantine(LOOKUP,actor='operator',reason='keep blocked')
        await m.observe(CONTROL)
    (env.state_dir/'owner.unclean').write_text('simulated interrupted owner')
    async with TrustMonitor(cfg) as m:
        assert m.status(LOOKUP).state is TrustState.QUARANTINED
        for sid in (LOOKUP,CONTROL):
            record=m.status(sid)
            assert record.observation_failed_at
            with pytest.raises(ObservationRequiredError):
                await m.restore(sid,revision=record.observed_revision,
                    expected_generation=record.generation,actor='operator')
        record=await m.observe(LOOKUP)
        await m.restore(LOOKUP,revision=record.observed_revision,
            expected_generation=record.generation,actor='operator')
        assert m.catalog(LOOKUP)

async def test_detector_rejects_rules_snapshot_that_differs_from_declared_binding(tmp_path,monkeypatch):
    from types import SimpleNamespace
    from mcp_trust_monitor.policy import DetectorBinding,load_policy
    from mcp_trust_monitor.detector import DetectorError,rules_digest_of
    from mcp_trust_monitor import detector as module
    rules=tmp_path/'rules.json'
    rules.write_text(json.dumps({'rules':[
        {'id':'r1','metadata':{'policy_id':'POL-001'}},
        {'id':'r2','metadata':{'policy_id':'POL-002'}}]}))
    mapping={'r1':'POL-001','r2':'POL-002'}
    binding=DetectorBinding(rules,load_policy(POLICY_PATH).digest,
                            rules_digest_of(rules.read_bytes()),mapping)
    mapping.clear()
    assert len(binding.rule_mapping)==2
    monkeypatch.setattr(module,'scan_tools',lambda *args,**kwargs:SimpleNamespace(rules_digest='different'))
    with pytest.raises(DetectorError,match='scanned rules changed'):
        binding.scan([],POLICY_PATH)

async def test_valid_json_metadata_corruption_cannot_reuse_old_approval_digest(env):
    async with TrustMonitor(config(env)) as m:
        await approve(m)
        record=m.status(LOOKUP)
        corrupt=[dict(tool) for tool in record.observed_tools]
        corrupt[0]['name']='unreviewed_tool'
        m.store._db.execute('UPDATE trust_records SET observed_tools=? WHERE server_id=?',
                            (json.dumps(corrupt),LOOKUP))
        with pytest.raises(StorageFaultError,match='invalid authoritative'):
            m.catalog(LOOKUP)
        with pytest.raises(StorageFaultError):
            await m.call_tool(LOOKUP,'unreviewed_tool')
        assert env.received_calls(LOOKUP)==0
