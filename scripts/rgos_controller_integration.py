"""Real RGOS controller scenarios; all capture files/config are cleaned individually."""
import argparse
import json
import os
import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from capturedesk.models import Server,Secrets,Task,CaptureOptions
from capturedesk.remote import HostKeys
from capturedesk.rgos import RgosRemote,validate_pcap
from capturedesk.controller import Controller
from capturedesk.storage import Store


def wait(predicate, seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate(): return
        time.sleep(.1)
    raise TimeoutError('Scenario deadline exceeded')


def main():
    p=argparse.ArgumentParser();p.add_argument('--host',required=True)
    p.add_argument('--scenarios',nargs='+',default=['manual','packet_count','duration','recovery','transfer_failure'])
    a=p.parse_args()
    root=(Path('.local-test/rgos-controller')/datetime.now().strftime('%Y%m%d_%H%M%S')).resolve()
    store=Store(root);keys=HostKeys(root/'known_hosts',lambda h,*x:h==a.host)
    secret=Secrets(password=os.environ.pop('CAPTURE_TEST_PASSWORD'))
    server=Server(host=a.host,username='admin',device_type='rgos',interface='control-plane',remote_base='tmp:')
    reports=[]
    for scenario in a.scenarios:
        time.sleep(2)
        task=Task.create(server,CaptureOptions(device=dict(minutes=1,packets=4 if scenario=='packet_count' else 64,
                                                          buffer_mb=2,filters={'v4_protocol':'icmp'})),scenario,str(root/scenario))
        control=RgosRemote(server,secret,keys)
        class StimulusRemote(RgosRemote):
            def launch(self,t):
                super().launch(t)
                self.command('ping '+self.client.get_transport().sock.getsockname()[0],check=False,timeout=15)
        controller=Controller(store,keys,lambda _:None,StimulusRemote)
        try:
            if scenario=='transfer_failure':
                class CopyFailure(StimulusRemote):
                    def download(self,*args): raise RuntimeError('Simulated transfer failure, real cleanup')
                controller.remote_factory=CopyFailure
            if scenario=='recovery':
                control.connect()
                control.prepare_intent(task,control.inspect());store.save_task(task)
                control.configure(task,lambda:store.save_task(task));control.launch(task);store.save_task(task)
                control.command('ping '+control.client.get_transport().sock.getsockname()[0],check=False,timeout=15)
                control.close()  # Mimic loss of the creator; no cleanup on this standalone backend close.
                control=RgosRemote(server,secret,keys)
                time.sleep(1)
                controller.submit(task,secret,resume=True)
            else:
                store.save_task(task);controller.submit(task,secret)
            wait(lambda:task.state=='抓包中' or not controller.active_ids(),25)
            if not controller.active_ids():
                assert scenario=='packet_count' and task.state=='完成',task.error
            if scenario in {'manual','recovery','transfer_failure'}: controller.stop(task.id)
            wait(lambda:not controller.active_ids(),110)
            expected='取回失败，远端已清理' if scenario=='transfer_failure' else '完成'
            assert task.state==expected,(task.state,task.error)
            assert task.device['cleanup']=='done'
            if task.local_file:validate_pcap(task.local_file)
            time.sleep(1)
            control.connect()
            status=control.current()
            assert not status['running'] and not status['file'] and not status['rules'] and not status['points']
            assert control.file_info(task) is None
            reports.append(dict(scenario=scenario,passed=True,state=task.state,task=task.__dict__))
            print(scenario,'passed',task.size,'bytes',flush=True)
        finally:
            controller.close();controller.pool.shutdown(wait=True)
            control.close()
            (root/'report.json').write_text(json.dumps(reports,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Report:',root/'report.json',flush=True)


if __name__=='__main__':main()
