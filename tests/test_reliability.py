"""Integration regressions: reports, events, persistence and command outcomes.

All control/notification commands are replaced; these tests never touch a fleet.
"""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'collector'))
import acks
import alerts
import hub
import issues
import probe
import settings
import storage
import suppressions


def host(**extra):
    return dict(id='server', name='server', addr='192.0.2.1', agent='linux',
                reachable=True, **extra)


def test_degraded_raid_reaches_finding_and_check():
    parsed = probe._post_process(probe.parse_report('kind\tsynology\n@raid\tmd0\traid1\tU_\nok\t1\n'))
    node = dict(parsed, id='nas', agent='synology', reachable=True)
    issues.annotate([node], {}, None)
    issues.annotate_checks([node], {})
    assert any(i['key'] == 'raid:md0' and i['level'] == 'bad' for i in node['issues'])
    assert any(c['status'] == 'bad' and 'raid' in c['keys'] for c in node['checks'])


def postman(tmp_path):
    return alerts.Alerts({'telegram': {'enabled': True, 'chats': ['test'],
        'startup_summary': False, 'digest_hour': -1, 'state_file': str(tmp_path / 'alerts.json')}})


def event(stamp=100):
    return host(polled_at=stamp, issues=[{'key':'rebooted','level':'bad','text':'restarted','episodic':True}])


def test_one_poll_event_delivered_immediately_once(tmp_path):
    post = postman(tmp_path)
    sent = []
    post._send = lambda text: sent.append(text) or True
    post.process([event()])
    post.process([event()])
    post.process([host(issues=[])])
    post.process([host(issues=[])])
    assert len(sent) == 1 and 'restarted' in sent[0]
    post.process([event(200)])
    assert len(sent) == 2


def test_event_survives_failure_disappearance_and_restart(tmp_path):
    post = postman(tmp_path)
    post._send = lambda text: False
    post.process([event()])
    post.process([host(issues=[])])
    assert len(post.events) == 1
    restored = postman(tmp_path)
    sent = []
    restored._send = lambda text: sent.append(text) or True
    restored.process([host(issues=[])])
    assert len(sent) == 1 and not restored.events
    again = postman(tmp_path)
    again._send = lambda text: pytest.fail('duplicate event')
    again.process([event()])


def test_normal_one_poll_state_still_debounced(tmp_path):
    post = postman(tmp_path)
    post._send = lambda text: pytest.fail('transient state must not alert')
    post.process([host(issues=[{'key':'disk:/','level':'bad','text':'full'}])])
    post.process([host(issues=[])])


def test_muting_freezes_existing_problem_through_restart(tmp_path):
    post = postman(tmp_path)
    broken = host(issues=[{'key':'disk:/','level':'bad','text':'full'}])
    post._send = lambda text: True
    post.process([broken]); post.process([broken])
    assert post.active
    post.mute('server', 900)
    post = postman(tmp_path)
    post._send = lambda text: pytest.fail('mute must not report recovery')
    post.process([broken]); post.process([broken]); post.process([broken])
    post.muted = {}
    post.process([broken])
    assert post.active


def test_telegram_test_reports_delivery_failure(tmp_path):
    post = postman(tmp_path)
    post._send = lambda text: False
    post.delivery = {'ok':False,'error':'connection failed'}
    assert post.test() == (False, 'connection failed')


def test_settings_rollback_and_entire_form_atomic(tmp_path, monkeypatch):
    store = settings.Settings(str(tmp_path / 'settings.json'))
    store.set_auto_security({'enabled':False})
    before = Path(store.path).read_bytes()
    monkeypatch.setattr(storage.os, 'replace', lambda *args: (_ for _ in ()).throw(PermissionError()))
    with pytest.raises(storage.StateSaveError):
        with store.transaction():
            store.set_auto_security({'enabled':True})
            store.set_name('server','new name')
    assert store.auto_security()['enabled'] is False
    assert store.names() == {}
    assert Path(store.path).read_bytes() == before
    assert store.storage_error


def test_background_ack_expiry_stays_expired_on_disk_failure(tmp_path, monkeypatch):
    store = acks.Acks(str(tmp_path / 'acks.json'))
    store.add('server','reboots','restarted')
    monkeypatch.setattr(storage, 'write_json', lambda *args: (_ for _ in ()).throw(storage.StateSaveError()))
    store.forget_stale([])
    assert store.for_host('server') == {}
    with pytest.raises(storage.StateSaveError):
        store.add('server','different','new')
    assert store.for_host('server') == {}


def handler(tmp_path, payload, token='secret', path='/api/settings'):
    obj = hub.Handler.__new__(hub.Handler)
    raw = json.dumps(payload).encode()
    obj.path = path
    obj.headers = {'Host':'dashboard:8816','Content-Length':str(len(raw))}
    if token is not None:
        obj.headers['X-Health-Zoo-Token'] = token
    obj.rfile = io.BytesIO(raw)
    obj.connection = SimpleNamespace(settimeout=lambda seconds:None)
    store = settings.Settings(str(tmp_path / 'settings.json'))
    state = {'hosts': []}
    obj.fleet = SimpleNamespace(cfg={'action_token':'secret'}, settings=store,
        alerts=SimpleNamespace(timezone=''), suppressions=None, acks=None,
        apply_camera_limits=lambda hosts:None, get=lambda:state)
    obj.response = None
    obj._json = lambda payload, code=200: setattr(obj, 'response', (code,payload))
    return obj


@pytest.mark.parametrize('path', ['/api/settings','/api/reboot','/api/update','/api/service/remove','/api/refresh'])
def test_post_without_auth_never_reaches_mutation(tmp_path, path):
    obj = handler(tmp_path, {}, token=None, path=path)
    obj.do_POST()
    assert obj.response[0] == 403
    assert obj.response[1]['code'] == 'token_required'


def test_auth_fails_closed_and_supports_secret_file(tmp_path):
    obj = handler(tmp_path,{})
    obj.fleet.cfg = {}
    assert obj._authorized() == 'actions_disabled'
    secret = tmp_path / 'key'; secret.write_text('secret\n')
    obj.fleet.cfg = {'action_token_file':str(secret)}
    assert obj._authorized() == ''
    obj.headers['Origin'] = 'https://untrusted.example'
    assert obj._authorized().startswith('cross-origin')
    secret.unlink(); obj.headers.pop('Origin')
    assert obj._authorized() == 'actions_disabled'


def test_api_returns_failure_without_applying_partial_settings(tmp_path, monkeypatch):
    obj = handler(tmp_path, {'auto_security':{'enabled':True}, 'auto_cleanup':{'enabled':False}})
    before = copy.deepcopy(obj.fleet.settings.data)
    monkeypatch.setattr(storage, 'write_json', lambda *args: (_ for _ in ()).throw(storage.StateSaveError('not saved')))
    obj.do_POST()
    assert obj.response[0] == 503
    assert obj.fleet.settings.data == before


def update_script(cleanup=True):
    jobs = hub.Jobs({}); captured = []
    jobs._exec = lambda job, node, key, script: captured.append(script) or 0
    jobs._update_host('test', {'id':'server','user':'root'}, None, cleanup=cleanup)
    return captured[0]


def test_update_refuses_removal_even_when_cleanup_disabled():
    script = update_script(False)
    assert '--no-remove --no-install-recommends' in script
    assert 'autoremove' not in script


def test_later_apt_failure_is_not_reported_as_success(tmp_path):
    fake = tmp_path / 'apt-get'
    fake.write_text('''#!/bin/sh
case "$*" in
 *autoremove*) exit 100;;
 *upgrade*) if [ -f "$HZ_REVIEW_COUNT" ]; then exit 100; fi; : > "$HZ_REVIEW_COUNT";;
esac
exit 0
''')
    fake.chmod(0o700)
    apt = tmp_path / 'apt'; apt.write_text('#!/bin/sh\nprintf "Listing...\\n"\n'); apt.chmod(0o700)
    env = dict(os.environ, PATH=str(tmp_path)+os.pathsep+'/usr/bin:/bin', HZ_REVIEW_COUNT=str(tmp_path/'count'))
    result = subprocess.run(['sh','-c',update_script()],env=env,capture_output=True)
    assert result.returncode == 100


def test_failed_service_job_has_terminal_host_state_and_log():
    jobs = hub.Jobs({})
    jobs.jobs['job1'] = {'id':'job1','kind':'restart','state':'running','targets':['server'],'log':[],'results':{}}
    def execute(job, node, key, remote):
        jobs._log(job,'E: failed restart')
        return 1
    jobs._exec = execute
    jobs._worker(jobs._run_service_action, 'job1', host(), 'demo.service', 'restart', SimpleNamespace(refresh_hosts=lambda ids:None))
    result = jobs.get('job1')
    assert result['state'] == 'done'
    assert result['hosts']['server']['state'] == 'failed'
    assert any('failed restart' in x for x in result['hosts']['server']['log'])


def test_worker_exception_releases_slot_and_camera_logs_follow_target():
    jobs = hub.Jobs({})
    jobs.jobs['job1'] = {'id':'job1','kind':'reboot','state':'running','targets':['server'],'log':[],'results':{}}
    def operation(job, node):
        jobs._log(job,'recorder output','recorder')
        raise RuntimeError('worker failed')
    jobs._worker(operation,'job1',host())
    result = jobs.get('job1')
    assert result['state'] == 'done'
    assert result['hosts']['server']['reason'] == 'worker failed'
    assert 'recorder output' in result['hosts']['server']['log']


def test_reboot_refused_before_reserving_slot_if_state_cannot_save():
    jobs = hub.Jobs({})
    def cannot_save(*args):
        raise storage.StateSaveError('read only')
    fleet = SimpleNamespace(settings=SimpleNamespace(note_reboot=cannot_save))
    with pytest.raises(storage.StateSaveError):
        jobs.start_reboot(host(), fleet)
    assert jobs.active is None and jobs.jobs == {}


def test_check_suppression_references_removable_prefix(tmp_path):
    store = suppressions.Suppressions(str(tmp_path/'suppressions.json'))
    store.add('server','raid','expected maintenance')
    node = host(degraded_raid=[{'dev':'md0','state':'U_'}], raids=[{'dev':'md0','state':'U_'}])
    issues.annotate([node],{},store)
    finding = next(i for i in node['issues'] if i['key']=='raid:md0')
    assert finding['suppression_id']=='server/raid'
    assert store.remove(finding['suppression_id'])


def test_installer_expands_home_without_evaluating_shell(tmp_path):
    installer = (Path(__file__).resolve().parents[1]/'install.sh').read_text()
    start = installer.index('KEY_REAL="$KEY_PATH"')
    end = installer.index('as_user()',start)
    literal = '$(touch '+str(tmp_path/'should-not-exist')+')'
    result = subprocess.run(['bash','-c',installer[start:end]+'\nprintf "%s" "$KEY_REAL"'],
        env=dict(os.environ,KEY_PATH=literal,USER_DIR=str(tmp_path)),capture_output=True,text=True)
    assert result.returncode == 0 and result.stdout == literal
    assert not (tmp_path/'should-not-exist').exists()


@pytest.mark.parametrize('cfg', [
    {'hosts':[{'id':'same','addr':'192.0.2.1'},{'id':'same','addr':'192.0.2.2'}]},
    {'port':0}, {'hosts':[{'id':'srv','addr':'-oProxyCommand=x'}]},
    {'subnets':[{'cidr':'192.0.2.0/24','parent':'192.0.2.0/24'}]},
])
def test_bad_configuration_rejected_before_polling(cfg):
    with pytest.raises(ValueError):
        hub.validate_config(cfg)


def test_example_configuration_valid():
    hub.validate_config(json.loads((Path(__file__).resolve().parents[1]/'collector/config.example.json').read_text()))


def test_getter_cannot_observe_uncommitted_automatic_setting(tmp_path, monkeypatch):
    store = settings.Settings(str(tmp_path/'settings.json'))
    store.set_auto_security({'enabled':False})
    writing = threading.Event(); release = threading.Event(); read_done = threading.Event()
    def fail_write(*args):
        writing.set(); release.wait(2)
        raise storage.StateSaveError('not saved')
    monkeypatch.setattr(storage,'write_json',fail_write)
    def writer():
        with pytest.raises(storage.StateSaveError):
            with store.transaction():
                store.set_auto_security({'enabled':True})
    observed=[]
    def reader():
        observed.append(store.auto_security()['enabled']); read_done.set()
    a=threading.Thread(target=writer);a.start();assert writing.wait(2)
    b=threading.Thread(target=reader);b.start()
    assert not read_done.wait(.05)
    release.set();a.join(2);b.join(2)
    assert observed == [False]


@pytest.mark.parametrize('body',['[]','null','{"auto_security":true}'])
def test_malformed_settings_fail_safe(tmp_path,body):
    target=tmp_path/'settings.json';target.write_text(body)
    store=settings.Settings(str(target))
    assert store.auto_security()['enabled'] is False
    assert store.auto_reboot()['enabled'] is False
    assert store.storage_error


def test_migration_preserves_existing_policy_and_key(tmp_path):
    import migrate
    import pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    state = tmp_path / 'state'; state.mkdir()
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'hosts': [], 'listen': '0.0.0.0'}))
    original = {'auto_reboot': {'enabled': True, 'from_hour': 8, 'to_hour': 9,
                'timezone': 'Europe/Moscow', 'exclude': ['nas']},
                'auto_cleanup': {'enabled': True}, 'last_update': {'server': 123}}
    (state / 'settings.json').write_text(json.dumps(original))
    migrate.prepare(config, user, legacy=True, state_dir=state)
    saved = json.loads((state / 'settings.json').read_text())
    assert saved.pop('auto_security') == {'enabled': True}
    assert saved == original
    key = (state / 'action-token').read_text()
    assert len(key.strip()) == 64
    assert (state / 'action-token').stat().st_mode & 0o777 == 0o600
    migrate.prepare(config, user, legacy=True, state_dir=state)
    assert (state / 'action-token').read_text() == key
    assert json.loads(config.read_text())['listen'] == '0.0.0.0'


def test_new_install_stays_opt_in_on_later_upgrade(tmp_path):
    import migrate
    import pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    config = tmp_path / 'config.json'; config.write_text('{"hosts":[]}')
    state = tmp_path / 'state'
    migrate.prepare(config, user, state_dir=state)
    migrate.prepare(config, user, legacy=True, state_dir=state)
    assert json.loads((state / 'settings.json').read_text())['auto_security']['enabled'] is False


def test_api_reports_running_version_with_restored_observations(tmp_path):
    obj = object.__new__(hub.Handler)
    obj.path = '/api/state'
    store = SimpleNamespace(storage_error='')
    obj.fleet = SimpleNamespace(version={'commit':'current'}, cfg={}, settings=store,
        suppressions=store, acks=store, alerts=store,
        get=lambda: {'generated': 100, 'restored': True, 'version': {'commit':'old'}})
    obj._json = lambda data, code=200: setattr(obj, 'response', data)
    obj.do_GET()
    assert obj.response['version']['commit'] == 'current'
    assert obj.response['generated'] == 100 and obj.response['restored']
