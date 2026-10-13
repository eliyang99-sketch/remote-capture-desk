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


def pump_until(app, predicate):
    import time
    deadline = time.monotonic() + 5
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate()


def test_worker_callback_is_queued_to_gui_thread(tmp_path):
    import threading
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Store(tmp_path))
    worker_threads, callback_threads = [], []
    def work():
        worker_threads.append(threading.get_ident())
        return 42
    def done(result, error):
        assert result == 42 and error is None
        callback_threads.append(threading.get_ident())
    window.background(work, done)
    window.background_pool.shutdown(wait=True)
    assert not callback_threads
    pump_until(app, lambda: bool(callback_threads))
    assert callback_threads == [threading.get_ident()]
    assert worker_threads[0] != callback_threads[0]
    window.close()


def test_late_callbacks_are_ignored_after_close(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Store(tmp_path))
    called = []
    window.background(lambda: 42, lambda *args: called.append(True))
    window.background_pool.shutdown(wait=True)
    window.close()
    app.processEvents()
    assert not called


def test_callback_exception_does_not_break_next_callback(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Store(tmp_path))
    def fail(*args):
        raise RuntimeError('simulated UI error')
    called = []
    window.background(lambda: None, fail)
    window.background(lambda: None, lambda *args: called.append(True))
    pump_until(app, lambda: bool(called))
    assert window.start_button.isEnabled()
    window.close()


def test_closed_dialog_callback_is_ignored(tmp_path):
    from PySide6.QtWidgets import QDialog
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Store(tmp_path))
    dialog = QDialog(window)
    dialog.show()
    called = []
    window.background(lambda: 1, lambda *args: called.append(True), owner=dialog)
    window.background_pool.shutdown(wait=True)
    dialog.reject()
    app.processEvents()
    assert not called
    window.close()


def test_ten_server_preview_capture_download_flow(tmp_path, monkeypatch):
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QDialog
    from tests.test_core import FakeRemote
    import capturedesk.ui as ui
    class PreviewRemote(FakeRemote):
        def inspect(self):
            return {'interfaces': ['any'], 'connection': '192.0.2.10 50000 192.0.2.1 22'}
    monkeypatch.setattr(ui, 'Remote', PreviewRemote)
    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path)
    store.save_servers([Server(name=f'server-{i}', host=f'192.0.2.{i+1}') for i in range(10)])
    window = MainWindow(store)
    window.controller.remote_factory = PreviewRemote
    window.output.setText(str(tmp_path / 'captures'))
    for row in range(10):
        window.server_table.item(row, 0).setCheckState(Qt.CheckState.Checked)
    timer = QTimer()
    def accept_preview():
        for widget in app.topLevelWidgets():
            if isinstance(widget, QDialog) and widget.windowTitle() == '确认实际抓包条件':
                widget.accept()
    timer.timeout.connect(accept_preview)
    timer.start(10)
    try:
        window.start_preview()
        window.start_preview()  # Repeated click must not enqueue a second batch.
        pump_until(app, lambda: len(window.tasks) == 10 and all(t.state == '完成' for t in window.tasks.values()))
        assert window.task_table.rowCount() == 10
    finally:
        timer.stop()
        window.close()


def test_wireshark_button_reports_failure_and_allows_retry(tmp_path, monkeypatch):
    import capturedesk.ui as ui
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Store(tmp_path))
    capture = tmp_path / '中文 文件.pcap'
    capture.write_bytes(b'test')
    task = Task.create(Server(host='192.0.2.1'), CaptureOptions(), 'batch', str(tmp_path))
    task.local_file = str(capture)
    task.state = '完成'
    window.tasks[task.id] = task
    window.render_tasks()
    window.task_table.selectRow(0)
    monkeypatch.setattr(ui, 'find_wireshark', lambda _: 'test/Wireshark.exe')
    errors, calls = [], []
    monkeypatch.setattr(ui.QMessageBox, 'warning', lambda *args: errors.append(args[2]))
    def fail(executable, path):
        calls.append(path)
        raise RuntimeError('exit code 0xC0000135')
    monkeypatch.setattr(ui, 'open_capture', fail)
    window.open_wireshark()
    window.open_wireshark()
    pump_until(app, lambda: bool(errors))
    assert calls == [str(capture)]
    assert 'C0000135' in errors[0]
    assert not window.wireshark_busy
    monkeypatch.setattr(ui, 'open_capture', lambda *args: '已发送打开请求')
    window.open_wireshark()
    pump_until(app, lambda: not window.wireshark_busy)
    assert window.statusBar().currentMessage() == '已发送打开请求'
    window.close()


def test_delete_history_preserves_files_and_ignores_late_update(tmp_path, monkeypatch):
    from dataclasses import asdict
    import capturedesk.ui as ui
    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path)
    tasks = [Task.create(Server(host='192.0.2.1'), CaptureOptions(), 'batch', str(tmp_path)) for _ in range(2)]
    for t in tasks:
        t.state = '完成'
        t.local_file = str(tmp_path / (t.id + '.pcap'))
        __import__('pathlib').Path(t.local_file).write_bytes(b'keep')
        store.save_task(t)
    window = MainWindow(store)
    monkeypatch.setattr(ui.QMessageBox, 'question', lambda *args: ui.QMessageBox.StandardButton.Yes)
    window.task_table.selectAll()
    window.delete_history()
    assert not window.tasks and not Store(tmp_path).tasks()
    assert all(__import__('pathlib').Path(t.local_file).read_bytes() == b'keep' for t in tasks)
    window.task_changed(asdict(tasks[0]))
    assert not window.tasks
    window.close()


def test_delete_unknown_task_and_server_blocked(tmp_path, monkeypatch):
    import capturedesk.ui as ui
    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path)
    server = Server(host='192.0.2.1')
    store.save_servers([server])
    task = Task.create(server, CaptureOptions(), 'batch', str(tmp_path))
    task.state = '状态未知'
    task.remote_dir = '/tmp/existing'
    store.save_task(task)
    window = MainWindow(store)
    warnings = []
    monkeypatch.setattr(ui.QMessageBox, 'warning', lambda *args: warnings.append(args[2]))
    window.task_table.selectRow(0)
    window.delete_history()
    window.server_table.selectRow(0)
    window.delete_server()
    assert len(warnings) == 2
    assert len(store.tasks()) == len(store.servers()) == 1
    window.close()


def test_delete_server_preserves_task_snapshot(tmp_path, monkeypatch):
    import capturedesk.ui as ui
    app = QApplication.instance() or QApplication([])
    store = Store(tmp_path)
    server = Server(host='192.0.2.1')
    store.save_servers([server])
    task = Task.create(server, CaptureOptions(), 'batch', str(tmp_path))
    task.state = '完成'
    store.save_task(task)
    window = MainWindow(store)
    deleted = []
    monkeypatch.setattr(window.credentials, 'delete', deleted.append)
    monkeypatch.setattr(ui.QMessageBox, 'question', lambda *args: ui.QMessageBox.StandardButton.No)
    window.server_table.selectRow(0)
    window.delete_server()
    assert len(store.servers()) == 1
    monkeypatch.setattr(ui.QMessageBox, 'question', lambda *args: ui.QMessageBox.StandardButton.Yes)
    window.delete_server()
    assert not Store(tmp_path).servers()
    assert Store(tmp_path).tasks()[0].server['id'] == server.id
    assert deleted == [server.id]
    window.close()


def test_queue_batches_updates_and_keeps_existing_cells(tmp_path, monkeypatch):
    from dataclasses import asdict
    app = QApplication.instance() or QApplication([])
    window = MainWindow(Store(tmp_path))
    task = Task.create(Server(host='192.0.2.1'), CaptureOptions(), 'batch', str(tmp_path))
    window.tasks[task.id] = task
    window.render_tasks()
    cell = window.task_table.item(0, 0)
    calls = []
    render = window.render_tasks
    def counted():
        calls.append(True)
        render()
    monkeypatch.setattr(window, 'render_tasks', counted)
    for elapsed in range(30):
        task.elapsed = elapsed
        window.events.put(('task', asdict(task)))
    window.drain_events()
    assert len(calls) == 1
    assert window.tasks[task.id].elapsed == 29
    assert window.task_table.item(0, 0) is cell
    window.close()
