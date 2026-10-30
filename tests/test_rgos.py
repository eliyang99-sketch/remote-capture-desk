import json
import struct
from dataclasses import asdict
from pathlib import Path
import pytest
from capturedesk.models import Server, Task, CaptureOptions, Secrets
from capturedesk.storage import Store
from capturedesk.rgos_options import capture_arguments
from capturedesk.rgos import RgosRemote, parse_status, validate_pcap, DeviceTransport
from capturedesk.controller import Controller


def device_task(root):
    server = Server(host='192.0.2.1', username='admin', device_type='rgos', interface='control-plane', remote_base='tmp:')
    return Task.create(server, CaptureOptions(device={'filters': {'etype': '0x88cc'}}), 'test', str(root))


def test_legacy_data_and_secret_redaction(tmp_path):
    store = Store(tmp_path)
    store.data['servers'] = [{'name':'old', 'host':'192.0.2.3'}]
    store.flush()
    assert Store(tmp_path).servers()[0].device_type == 'linux'
    original=(tmp_path/'state.pre-v1.1.0.json').read_bytes()
    Store(tmp_path)
    assert (tmp_path/'state.pre-v1.1.0.json').read_bytes()==original
    assert Secrets(enable_password='private').redact('private') == '[已隐藏]'
    assert 'ssh-rsa' in DeviceTransport._preferred_keys
    import paramiko
    assert 'ssh-rsa' not in paramiko.Transport._preferred_keys


@pytest.mark.parametrize('filters', [{'etype':'0x88cc\nreload'}, {'ipv4_dip':'bad'}, {'src_mac':'bad'},
                                      {'ipv4_dport':'65536'}, {'acl':'1'}, {'v4_protocol':'256'},
                                      {'ipv4_sip':'192.0.2.1', 'ipv6_sip':'::1'}])
def test_filters_reject_commands_and_bad_values(filters):
    with pytest.raises(ValueError): capture_arguments({'filters':filters})


def test_filter_cli_and_capabilities():
    value = capture_arguments({'filters':{'ipv4_sip':'192.0.2.0/24','ipv4_dport':'443','v4_protocol':'tcp'}})
    assert value['filter_cli'] == 'ipv4_sip 192.0.2.0 0.0.0.255 ipv4_dport eq 443 v4_protocol 6'
    with pytest.raises(ValueError): capture_arguments({'buffer_mb':16}, {'buffer_mb':15})
    with pytest.raises(ValueError): capture_arguments({'filters':{'etype':'arp'}}, {'fields':[]})


def test_status_and_ownership_reject_external(tmp_path):
    text = 'Capture rules:\n Capture rules own:\nCapture points:\n Capture point own:\n Filename: tmp:own.pcap\n Status: stopped\n'
    status = parse_status(text)
    assert status['rules'] == status['points'] == {'own'} and not status['running']
    remote = RgosRemote.__new__(RgosRemote)
    remote.current = lambda: status
    task = device_task(tmp_path)
    task.id='12345678'+'0'*24
    remote.server=Server(**task.server)
    task.device = dict(file='tmp:cd12345678.pcap', rule='cd12345678', point='cd12345678')
    status.update(file=task.device['file'],rules={task.device['rule']},points={task.device['point']})
    remote.check_owner(task)
    status['points'].add('manual')
    with pytest.raises(RuntimeError): remote.check_owner(task)
    with pytest.raises(ValueError): parse_status('Status: unrecognized')


def test_status_failed_packet_counter_is_not_command_failure():
    remote=RgosRemote.__new__(RgosRemote)
    remote.channel=type('Channel',(),{'send':lambda *a:None})()
    remote.read=lambda *a,**k:'packets captured(all - failed): 1\nStatus: stopped\n'
    remote.command('show packet capture status')
    remote.secrets=Secrets()
    remote.read=lambda *a,**k:'Copy failed.\n'
    with pytest.raises(RuntimeError):remote.command('copy tmp:x tftp:')


def test_partial_cleanup_is_idempotent_and_precise(tmp_path):
    remote = RgosRemote.__new__(RgosRemote)
    task = device_task(tmp_path)
    task.id='12345678'+'0'*24
    remote.server=Server(**task.server)
    task.device = dict(intent=True, file='tmp:cd12345678.pcap', rule='cd12345678', point='cd12345678',
                       stopped=True, launch_intent=True, cleanup='pending')
    status = dict(running=False, file=task.device['file'], rules={task.device['rule']}, points={task.device['point']})
    remote.current = lambda: dict(status)
    calls = []
    exists = [True]
    def command(cmd, **kwargs):
        calls.append(cmd)
        if cmd.startswith('clear packet capture point '): status['points'] = set()
        if cmd.startswith('clear packet capture rule '): status['rules'] = set()
        if cmd == 'clear packet capture file': status['file'] = ''
        if cmd.startswith('delete '): exists[0] = False
        return ''
    remote.command = command
    remote.file_info = lambda t: {'exact':24} if exists[0] else None
    remote.cleanup(task, lambda:None)
    remote.cleanup(task, lambda:None)
    assert calls.count('delete tmp:cd12345678.pcap') == 1
    assert task.device['cleanup'] == 'done'
    assert all('*' not in c for c in calls)


def test_unlaunched_file_never_deleted(tmp_path):
    remote = RgosRemote.__new__(RgosRemote)
    task = device_task(tmp_path)
    task.id='12345678'+'0'*24
    remote.server=Server(**task.server)
    task.device = dict(intent=True, file='tmp:cd12345678.pcap', rule='cd12345678', point='cd12345678', cleanup='pending')
    remote.current = lambda: dict(running=False, file='', rules=set(), points=set())
    remote.command = lambda *a, **k: pytest.fail('must not delete')
    remote.file_info = lambda t: {'exact':24}
    with pytest.raises(RuntimeError): remote.cleanup(task, lambda:None)


def test_tampered_task_path_rejected_before_device_commands(tmp_path):
    remote=RgosRemote.__new__(RgosRemote)
    task=device_task(tmp_path);remote.server=Server(**task.server)
    task.device=dict(file='flash:config.text',rule='x',point='x')
    remote.current=lambda:pytest.fail('no CLI must be called')
    with pytest.raises(ValueError):remote.check_owner(task)


@pytest.mark.parametrize('bad_hash',[False,True])
def test_download_integrity_never_publishes_invalid_file(tmp_path,bad_hash):
    import hashlib
    from types import SimpleNamespace
    payload=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    remote=RgosRemote.__new__(RgosRemote)
    remote.secrets=Secrets()
    task=device_task(tmp_path)
    task.device=dict(file='tmp:test.pcap',stopped=True)
    uploads=[]
    receiver=SimpleNamespace(address=('127.0.0.1',69),register=uploads.append,unregister=lambda _:None)
    remote.receiver=receiver
    remote.acquire_receiver=lambda:None
    remote.check_owner=lambda _:{}
    remote.source_ips=lambda:['192.0.2.1']
    remote.file_info=lambda _:{'value':len(payload),'unit':'B','exact':len(payload)}
    def command(cmd,**kw):
        if cmd.startswith('verify '):return '0'*32 if bad_hash else hashlib.md5(payload).hexdigest()
        upload=uploads[-1];upload.path.write_bytes(payload);upload.size=len(payload);upload.done.set()
        return 'Copy success.'
    remote.command=command
    if bad_hash:
        with pytest.raises(RuntimeError):remote.download(task,lambda _:None,lambda:False)
        assert len(uploads)==3 and not list(tmp_path.glob('*.pcap'))
    else:
        path,digest=remote.download(task,lambda _:None,lambda:False)
        assert Path(path).read_bytes()==payload and digest==hashlib.sha256(payload).hexdigest()


def test_pcap_boundaries(tmp_path):
    path = tmp_path/'文件.pcap'
    path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    validate_pcap(path)
    path.write_bytes(path.read_bytes()+struct.pack('<IIII',0,0,10,10)+b'x')
    with pytest.raises(ValueError): validate_pcap(path)


@pytest.mark.parametrize('failure', ['', 'download', 'cleanup', 'configure', 'replacement'])
def test_controller_device_lifecycle(tmp_path, failure):
    events = []
    class Fake:
        is_device = True
        def __init__(self,*a): pass
        def connect(self): pass
        def inspect(self): return {}
        def prepare_intent(self,t,info):
            t.device = dict(intent=True, cleanup='pending', transfer='pending')
            t.remote_dir = 'tmp:test.pcap'
        def configure(self,t,persist):
            events.append('configure')
            if failure == 'configure': raise RuntimeError('config failed')
        def launch(self,t): events.append('launch')
        def check_owner(self,t): return {'running':False}
        def stop(self,t): events.append('stop');t.device['stopped']=True
        def download(self,t,progress,cancelled):
            assert t.device['stopped']
            events.append('download')
            if failure == 'download': raise RuntimeError('copy failed')
            t.device['transfer']='verified'
            return 'test.pcap','a'*64
        def reconnect(self): pass
        def cleanup(self,t,persist):
            events.append('cleanup')
            if failure in {'cleanup','replacement'}: raise RuntimeError('ownership/cleanup failed')
            t.device['cleanup']='done'
        def close(self): pass
    store = Store(tmp_path)
    controller = Controller(store,None,lambda t:None,Fake)
    task = device_task(tmp_path)
    controller._device_work(task,Secrets(),__import__('threading').Event(),False)
    saved = Store(tmp_path).tasks()[0]
    assert 'cleanup' in events
    if failure in {'cleanup','replacement'}:
        assert saved.pending_cleanup() and saved.state == '已取回，待清理'
    elif failure:
        assert saved.state == '取回失败，远端已清理'
    else:
        assert saved.state == '完成' and events.index('stop') < events.index('download') < events.index('cleanup')
    controller.close()


def test_duplicate_device_and_pending_cleanup_block_submit(tmp_path):
    store = Store(tmp_path)
    old = device_task(tmp_path)
    old.device = dict(intent=True,cleanup='pending')
    store.save_task(old)
    controller = Controller(store,None,lambda _:None)
    new = device_task(tmp_path)
    with pytest.raises(ValueError): controller.submit(new,Secrets())
    controller.close()
