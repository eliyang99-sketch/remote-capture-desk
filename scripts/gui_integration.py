"""Qt UI integration test: preview, confirm, capture and automatic download."""
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox
from capturedesk.models import Server, Secrets
from capturedesk.storage import Store
from capturedesk.ui import MainWindow, STYLE


def main():
    app = QApplication([])
    app.setStyle('Fusion')
    app.setStyleSheet(STYLE)
    root = Path('.local-test/gui-integration').resolve()
    store = Store(root)
    # A pre-verified host key from the authorized integration session, not auto-trust.
    shutil.copyfile('.local-test/integration/known_hosts', root / 'known_hosts')
    server = Server(name='授权测试服务器', host=sys.argv[1], interface='lo')
    store.save_servers([server])
    window = MainWindow(store)
    window.credentials.session[server.id] = Secrets(password=os.environ.pop('CAPTURE_TEST_PASSWORD'))
    window.duration.setValue(3)
    window.size.setValue(2)
    window.mode.setCurrentIndex(1)
    window.bpf.setText('icmp and host 127.0.0.1')
    window.output.setText(str(root / '抓包文件'))
    window.server_table.item(0, 0).setCheckState(Qt.CheckState.Checked)
    window.show()
    result = {'success': False, 'preview': False}

    def poll():
        for widget in app.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.isVisible() and widget.windowTitle() == '确认实际抓包条件':
                result['preview'] = True
                widget.accept()
            elif isinstance(widget, QMessageBox) and widget.isVisible():
                print('Unexpected dialog:', widget.text(), flush=True)
                widget.reject()
        tasks = list(window.tasks.values())
        if tasks and all(t.state.startswith('完成') for t in tasks) and not window.controller.active_ids():
            assert all(Path(t.local_file).is_file() and t.sha256 for t in tasks)
            window.task_table.selectRow(0)
            window.grab().save(str(root / 'actual-window.png'))
            result['success'] = True
            timer.stop()
            window.close()

    timer = QTimer()
    timer.timeout.connect(poll)
    timer.start(200)
    QTimer.singleShot(100, window.start_button.click)
    QTimer.singleShot(45000, app.quit)
    app.exec()
    window.closing.set()
    window.controller.close()
    window.background_pool.shutdown(wait=False, cancel_futures=True)
    assert result['success'] and result['preview'], 'GUI integration did not complete'
    print('GUI preview, confirmation, capture, automatic download and screenshot passed', flush=True)


if __name__ == '__main__':
    main()
