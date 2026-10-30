"""Authorized Linux + RGOS GUI batch, with bounded ICMP stimulus and automatic stop."""
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from PySide6.QtCore import Qt,QTimer
from PySide6.QtWidgets import QApplication,QDialog,QMessageBox,QTabWidget
from capturedesk.models import Server,Secrets
from capturedesk.storage import Store
from capturedesk.ui import MainWindow,STYLE
from capturedesk.remote import Remote
from capturedesk.rgos import RgosRemote


def main():
    linux,device=sys.argv[1:3]
    password=os.environ.pop('CAPTURE_TEST_PASSWORD')
    root=(Path('.local-test/gui-rgos')/datetime.now().strftime('%Y%m%d_%H%M%S')).resolve()
    store=Store(root)
    servers=[Server(name='Linux test',host=linux,interface='lo'),
             Server(name='RGOS test',host=device,username='admin',device_type='rgos',interface='control-plane',remote_base='tmp:')]
    store.save_servers(servers)
    app=QApplication([]);app.setStyle('Fusion');app.setStyleSheet(STYLE)
    window=MainWindow(store)
    window.host_keys.confirm=lambda host,*a:host in {linux,device}
    for server in servers:window.credentials.session[server.id]=Secrets(password=password)
    class Stimulus(RgosRemote):
        def launch(self,task):
            super().launch(task)
            self.command('ping '+self.client.get_transport().sock.getsockname()[0],check=False,timeout=15)
    window.controller.remote_factory=lambda s,sec,keys:(Stimulus if s.device_type=='rgos' else Remote)(s,sec,keys)
    window.duration.setValue(3);window.size.setValue(2)
    window.mode.setCurrentIndex(1);window.bpf.setText('icmp')
    window.device_packets.setValue(64)
    window.device_takeover.setChecked('--takeover' in sys.argv)
    window.device_filters={'v4_protocol':'icmp'}
    window.findChild(QTabWidget).setCurrentIndex(1)
    window.output.setText(str(root/'抓包文件'))
    for row in range(2):window.server_table.item(row,0).setCheckState(Qt.CheckState.Checked)
    state={'success':False,'preview':False,'errors':[]}
    def poll():
        for widget in app.topLevelWidgets():
            if isinstance(widget,QMessageBox) and widget.isVisible():
                state['errors'].append(widget.text());widget.reject()
            elif isinstance(widget,QDialog) and widget.isVisible() and widget.windowTitle()=='确认实际抓包条件':
                state['preview']=True;widget.accept()
        tasks=list(window.tasks.values())
        for t in tasks:
            if t.server.get('device_type')=='rgos' and t.state=='抓包中':window.controller.stop(t.id)
        if len(tasks)==2 and not window.controller.active_ids() and all(t.state=='完成' for t in tasks):
            state['success']=True
            window.task_table.selectRow(0);window.grab().save(str(root/'mixed-completed.png'))
            timer.stop();window.close()
    timer=QTimer();timer.timeout.connect(poll);timer.start(100)
    window.show();QTimer.singleShot(150,window.start_preview);QTimer.singleShot(80000,app.quit)
    app.exec();window.controller.close();window.controller.pool.shutdown(wait=True);window.background_pool.shutdown(wait=True)
    (root/'report.json').write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
    print(state,'Report:',root/'report.json',flush=True)
    assert state['success'] and state['preview'] and not state['errors']


if __name__=='__main__':main()
