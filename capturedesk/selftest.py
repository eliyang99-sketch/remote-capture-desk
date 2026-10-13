"""Offline frozen-executable capture workflow check; never connects to a server."""
import hashlib
import json
import time
from pathlib import Path
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QDialog
from .models import Server
from . import ui


def start(window, app, rounds=20):
    if window.servers or window.tasks:
        raise ValueError("自检必须使用全新空数据目录")
    class Remote:
        def __init__(self, *args): pass
        def connect(self):
            hashlib.pbkdf2_hmac('sha256', b'fake', b'fake', 10000)
        def inspect(self):
            return {'interfaces': ['any'], 'connection': '192.0.2.1 12345 192.0.2.2 22'}
        def prepare(self, task, info): task.remote_dir = '/offline-test/' + task.id
        def launch(self, task): pass
        def status(self, task):
            return dict(phase='finished', size=24, elapsed=1, reason='duration', code=0)
        def download(self, task, progress, cancelled):
            progress(100)
            return 'offline-test.pcap', '0' * 64
        def close(self): pass
        def stop(self, task): pass
    ui.Remote = Remote
    window.controller.remote_factory = Remote
    window.servers = [Server(name='离线自检 '+str(i), host='192.0.2.'+str(i+1)) for i in range(10)]
    window.render_servers()
    for i in range(10):
        window.server_table.item(i, 0).setCheckState(Qt.CheckState.Checked)
    window.output.setText(str((window.store.root / 'offline-output').resolve()))
    state = {'rounds': 0, 'passed': False}
    deadline = time.monotonic() + 120
    timer = QTimer(window)
    def finish(ok):
        state['passed'] = ok
        (window.store.root / 'selftest.json').write_text(json.dumps(state), encoding='utf-8')
        timer.stop()
        window.closing.set()
        window.controller.close()
        window.background_pool.shutdown(wait=False, cancel_futures=True)
        app.exit(0 if ok else 2)
    def tick():
        if time.monotonic() > deadline:
            finish(False)
            return
        for widget in app.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.isVisible() and widget.windowTitle() == '确认实际抓包条件':
                widget.accept()
                return
        if window.preview_busy or window.controller.active_ids(): return
        if any(t.state != '完成' for t in window.tasks.values()): return
        if state['rounds'] >= rounds:
            finish(True)
        else:
            state['rounds'] += 1
            window.start_preview()
    timer.timeout.connect(tick)
    timer.start(30)
    return timer
