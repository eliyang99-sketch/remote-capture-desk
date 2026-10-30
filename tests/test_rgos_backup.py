import copy
from pathlib import Path
import pytest
from capturedesk.rgos import RgosRemote,parse_status
from capturedesk.rgos_backup import snapshot,signature,restore_commands
from capturedesk.models import Server,Task,CaptureOptions


RAW='''Capture rules:
  Capture rules rdp:
  Capture rules dhcp:
Capture points:
  Capture point rdp:
    Capture rules: rdp
    Location: Gi1/0/2
    Direction: all
    Packets captured(all): 31
Capture file:
  Filename: tmp:rdp_cli01.pcap
  Buffer size: 2(MB)
Capture Statistic:
  Status: stopped
  Timeout: 10(minutes)
  Packets limit: 1024
'''


def render(cfg):
    lines=['Capture rules:']
    for name,filters in cfg['rules'].items():
        lines+=['  Capture rules '+name+':']
        if filters.get('etype'):lines+=['    Etype: '+filters['etype']]
        for k in ('v4_protocol','v6_protocol'):
            if filters.get(k):lines+=['    Protocol: '+hex(int(filters[k]))]
    lines+=['Capture points:']
    for name,p in cfg['points'].items():
        lines+=['  Capture point '+name+':']+['    '+k+': '+v for k,v in p.items()]
    if cfg['file']:
        f=cfg['file'];lines+=['Capture file:','  Filename: '+f['path'],f"  Buffer size: {f['buffer_mb']}(MB)"]
    f=cfg['file'] or dict(minutes=0,packets=0)
    lines+=['Capture Statistic:','  Status: stopped',f"  Timeout: {f['minutes']}(minutes)",f"  Packets limit: {f['packets']}"]
    return '\n'.join(lines)+'\n'


def test_snapshot_round_trip_and_no_start_or_delete():
    old=snapshot(parse_status(RAW))
    assert old['points']['rdp']['Location']=='GigabitEthernet 1/0/2'
    assert signature(snapshot(parse_status(render(old))))==signature(old)
    commands=restore_commands(old)
    assert len(commands)==4 and all('start' not in cmd and 'delete' not in cmd for _,_,cmd in commands)


@pytest.mark.parametrize('raw',[RAW.replace('Status: stopped','Status: running'),RAW.replace('Capture rules dhcp:','Capture rules dhcp:\n    Unsupported field: 1'),RAW.replace('Direction: all','Direction: strange')])
def test_unrestorable_or_running_configuration_is_rejected(raw):
    with pytest.raises(ValueError):snapshot(parse_status(raw))


@pytest.mark.parametrize('partial',[False,True,'interrupted_restore'])
def test_restore_is_idempotent_after_partial_takeover(tmp_path,partial):
    original=snapshot(parse_status(RAW))
    state=copy.deepcopy(original)
    if partial:state['points']={};state['rules']={'rdp':{}}
    interrupt=[partial=='interrupted_restore']
    remote=RgosRemote.__new__(RgosRemote)
    remote.server=Server(host='192.0.2.1',device_type='rgos',remote_base='tmp:',interface='control-plane')
    task=Task.create(remote.server,CaptureOptions(),'test',str(tmp_path))
    name='cd'+task.id[:8]
    task.device=dict(intent=True,file='tmp:'+name+'.pcap',point=name,rule=name,cleanup='pending',
                     takeover=dict(previous=original,raw=RAW,phase='removing'))
    calls=[]
    remote.current=lambda:parse_status(render(state))
    remote.file_info=lambda _:None
    def command(cmd,**kwargs):
        calls.append(cmd)
        if cmd.startswith('packet capture point ') and interrupt[0]:
            interrupt[0]=False
            raise ConnectionError('connection lost while restoring')
        for kind,identifier,restore in restore_commands(original):
            if cmd==restore:
                if kind=='file':state['file']=copy.deepcopy(original['file'])
                else:state[kind+'s'][identifier]=copy.deepcopy(original[kind+'s'][identifier])
        return ''
    remote.command=command
    if partial=='interrupted_restore':
        with pytest.raises(ConnectionError):remote.cleanup(task,lambda:None)
        assert task.device['cleanup']=='pending'
    remote.cleanup(task,lambda:None)
    assert state==original and task.device['takeover']['phase']=='restored'
    count=len(calls);remote.cleanup(task,lambda:None)
    assert len(calls)==count and task.device['cleanup']=='done'
    assert all(not c.startswith(('delete ','packet capture start','clear ')) for c in calls)


def test_external_config_change_prevents_restoration(tmp_path):
    original=snapshot(parse_status(RAW));changed=copy.deepcopy(original);changed['rules']['external']={}
    remote=RgosRemote.__new__(RgosRemote)
    remote.server=Server(host='192.0.2.1',device_type='rgos',remote_base='tmp:',interface='control-plane')
    task=Task.create(remote.server,CaptureOptions(),'test',str(tmp_path));name='cd'+task.id[:8]
    task.device=dict(intent=True,file='tmp:'+name+'.pcap',point=name,rule=name,cleanup='pending',
                     takeover=dict(previous=original,raw=RAW,phase='removing'))
    remote.current=lambda:parse_status(render(changed))
    remote.command=lambda *a,**k:pytest.fail('Must not modify external configuration')
    with pytest.raises(RuntimeError):remote.cleanup(task,lambda:None)


def test_old_configuration_changed_after_preview_is_rejected():
    remote=RgosRemote.__new__(RgosRemote)
    remote.server=Server(host='192.0.2.1',device_type='rgos',remote_base='tmp:',interface='control-plane')
    approved=snapshot(parse_status(RAW));changed=RAW.replace('Packets limit: 1024','Packets limit: 2048')
    opts=CaptureOptions(device={'takeover':True,'approved_backup':approved})
    with pytest.raises(ValueError):remote.plan(opts,{'capabilities':{},'conflict':True,'status':parse_status(changed),'interfaces':['control-plane']})
