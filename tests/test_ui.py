import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

from capturedesk.models import Server, Task, CaptureOptions
from capturedesk.storage import Store
from capturedesk.ui import MainWindow, STYLE


def test_window_modes_and_task_history(tmp_path):
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLE)
    store = Store(tmp_path)
    server = Server(name="测试服务器", host="192.0.2.1")
    store.save_servers([server])
    task = Task.create(server, CaptureOptions(), "batch", str(tmp_path))
    task.state = "抓包中"
    task.remote_dir = "/tmp/capturedesk-example"
    store.save_task(task)
    window = MainWindow(store)
    window.show()
    app.processEvents()
    assert window.server_table.rowCount() == 1
    assert window.task_table.item(0, 1).text() == "状态未知"
    assert not window.bpf.isEnabled() and window.filter_host.isEnabled()
    window.mode.setCurrentIndex(1)
    assert window.bpf.isEnabled() and not window.filter_host.isEnabled()
    window.task_table.selectRow(0)
    assert window.selected_tasks()[0].id == task.id
    assert "远端" in window.details.toPlainText()
    window.close()
    app.processEvents()
