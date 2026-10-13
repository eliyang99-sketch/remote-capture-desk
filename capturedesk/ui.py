from __future__ import annotations

import os
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QUrl, QStandardPaths, QPointF
from shiboken6 import isValid
from PySide6.QtGui import QDesktopServices, QPainter, QPen, QColor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox as BaseComboBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QSpinBox, QSplitter, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QAbstractItemView, QAbstractSpinBox,
)

from .controller import Controller
from .credentials import Credentials
from .models import CaptureOptions, Secrets, Server, Task, identifier, safe_name
from .remote import HostKeys, Remote
from .storage import Store
from .diagnostics import record_exception, set_secret_provider
from .wireshark import find_wireshark, open_capture


STYLE = """
QMainWindow, QDialog { background: #f3f6fb; }
QWidget { font-family: 'Microsoft YaHei UI', 'Segoe UI'; font-size: 10pt; color: #1c2d46; }
QGroupBox { background: white; border: 1px solid #dce4ef; border-radius: 8px; margin-top: 0; padding: 6px; }
QLabel#sectionTitle { color: #173366; font-size: 11pt; font-weight: bold; padding: 2px 0 8px; }
QPushButton { padding: 7px 14px; background: white; border: 1px solid #cbd7e7; border-radius: 5px; }
QPushButton:hover { background: #edf3ff; border-color: #7d9ee1; }
QPushButton:disabled { color: #9da7b6; background: #edf0f5; }
QPushButton#primary { background: #245ee8; color: white; border-color: #245ee8; font-weight: bold; }
QPushButton#primary:disabled { background: #93abe4; }
QLineEdit, QComboBox, QSpinBox { padding: 5px; border: 1px solid #ccd8e7; border-radius: 4px; background: white; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus { border: 1px solid #245ee8; }
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled { background: #f1f4f8; color: #8491a3; border-color: #e0e6ee; }
QComboBox { padding-right: 26px; }
QComboBox::drop-down { subcontrol-origin: padding; subcontrol-position: top right; width: 24px; border: none; background: transparent; }
QComboBox::down-arrow { image: none; }
QSpinBox QLineEdit { border: none; padding: 0; background: transparent; }
QTableWidget, QTextEdit { background: white; border: 1px solid #dce4ef; border-radius: 5px; selection-background-color: #e0ebff; selection-color: #163667; }
QHeaderView::section { background: #eaf0f8; padding: 7px; border: 0; border-bottom: 1px solid #d5deeb; }
QLabel#title { font-size: 20pt; font-weight: bold; color: #173366; }
QLabel#muted { color: #64748b; }
"""


def button(text, callback, primary=False):
    result = QPushButton(text)
    if primary:
        result.setObjectName("primary")
    result.clicked.connect(callback)
    return result


def section(title):
    card = QGroupBox()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(14, 12, 14, 14)
    layout.setSpacing(8)
    label = QLabel(title)
    label.setObjectName("sectionTitle")
    layout.addWidget(label)
    return card, layout


class QComboBox(BaseComboBox):
    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#64748b" if self.isEnabled() else "#a6b1c0"), 1.6))
        x, y = self.width() - 14, self.height() / 2
        painter.drawLine(QPointF(x - 4, y - 2), QPointF(x, y + 2))
        painter.drawLine(QPointF(x, y + 2), QPointF(x + 4, y - 2))
        painter.end()


class NumericInput(QSpinBox):
    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Some Qt stylesheet/native style combinations collapse the editor when
        # NoButtons is used. Keep an explicit inset for the buttonless field.
        self.lineEdit().setGeometry(self.rect().adjusted(8, 4, -8, -4))


def spin(low, high, value, suffix=""):
    result = NumericInput()
    result.setRange(low, high)
    result.setValue(value)
    result.setSuffix(suffix)
    result.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
    result.setMinimumHeight(32)
    result.setToolTip("直接输入数值；聚焦后可用键盘 ↑ / ↓ 调整")
    return result


def table(headers):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.verticalHeader().hide()
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    widget.horizontalHeader().setStretchLastSection(True)
    widget.setAlternatingRowColors(True)
    return widget


class ServerDialog(QDialog):
    def __init__(self, parent, server: Server | None = None):
        super().__init__(parent)
        self.main = parent
        self.server = server or Server()
        self.setWindowTitle("服务器配置")
        self.resize(540, 680)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        s = self.server
        self.name, self.host, self.username = QLineEdit(s.name), QLineEdit(s.host), QLineEdit(s.username)
        self.port = spin(1, 65535, s.port)
        self.auth = QComboBox()
        self.auth.addItem("密码登录", "password")
        self.auth.addItem("私钥登录", "key")
        self.auth.setCurrentIndex(self.auth.findData(s.auth))
        self.key = QLineEdit(s.key_path)
        key_row = QHBoxLayout()
        key_row.addWidget(self.key)
        key_row.addWidget(button("浏览", self.choose_key))
        self.password, self.passphrase, self.sudo_password = QLineEdit(), QLineEdit(), QLineEdit()
        for field in (self.password, self.passphrase, self.sudo_password):
            field.setEchoMode(QLineEdit.EchoMode.Password)
        self.privilege = QComboBox()
        for text, data in (("直接执行（root / 已授予抓包权限）", "direct"), ("免密 sudo", "sudo"), ("需要密码的 sudo", "sudo_password")):
            self.privilege.addItem(text, data)
        self.privilege.setCurrentIndex(self.privilege.findData(s.privilege))
        self.interface = QComboBox()
        self.interface.setEditable(True)
        self.interface.addItem(s.interface)
        self.base = QLineEdit(s.remote_base)
        self.remember = QCheckBox("安全记住凭据（Windows 凭据管理器）")
        try:
            secrets = self.main.credentials.get(s.id)
            self.password.setText(secrets.password)
            self.passphrase.setText(secrets.passphrase)
            self.sudo_password.setText(secrets.sudo_password)
            self.remember.setChecked(self.main.credentials.remembered(s.id))
        except Exception as exc:
            QMessageBox.warning(self, "读取凭据失败", str(exc))
        for label, widget in (("名称", self.name), ("IP / 主机名", self.host), ("SSH 端口", self.port),
                              ("用户名", self.username), ("认证方式", self.auth), ("SSH 密码", self.password),
                              ("私钥文件", key_row), ("私钥口令", self.passphrase), ("抓包权限", self.privilege),
                              ("sudo 密码", self.sudo_password), ("网卡", self.interface), ("远端临时目录", self.base)):
            form.addRow(label, widget)
        layout.addLayout(form)
        layout.addWidget(self.remember)
        self.test_button = button("测试连接并读取网卡", self.test)
        layout.addWidget(self.test_button)
        self.status = QLabel("支持直连 Linux SSH；测试不会启动抓包。")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("保存")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.auth.currentIndexChanged.connect(self.toggle)
        self.privilege.currentIndexChanged.connect(self.toggle)
        self.toggle()

    def toggle(self):
        key = self.auth.currentData() == "key"
        self.password.setEnabled(not key)
        self.key.setEnabled(key)
        self.passphrase.setEnabled(key)
        self.sudo_password.setEnabled(self.privilege.currentData() == "sudo_password")

    def choose_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择 SSH 私钥")
        if path:
            self.key.setText(path)

    def values(self):
        server = Server(name=self.name.text().strip(), host=self.host.text().strip(), port=self.port.value(),
                        username=self.username.text().strip(), auth=self.auth.currentData(), key_path=self.key.text().strip(),
                        privilege=self.privilege.currentData(), interface=self.interface.currentText().strip(),
                        remote_base=self.base.text().strip().rstrip("/") or "/", id=self.server.id)
        server.validate()
        secrets = Secrets(self.password.text() if server.auth == "password" else "",
                          self.passphrase.text() if server.auth == "key" else "",
                          self.sudo_password.text() if server.privilege == "sudo_password" else "")
        if "\n" in secrets.sudo_password or "\r" in secrets.sudo_password:
            raise ValueError("sudo 密码不能包含换行符")
        return server, secrets

    def test(self):
        try:
            server, secrets = self.values()
        except Exception as exc:
            QMessageBox.warning(self, "配置错误", str(exc))
            return
        self.test_button.setEnabled(False)
        self.status.setText("正在测试 SSH、sudo 权限、tcpdump 和网卡…")

        def work():
            remote = Remote(server, secrets, self.main.host_keys)
            try:
                remote.connect()
                return remote.inspect()
            except Exception as exc:
                raise RuntimeError(secrets.redact(str(exc))) from None
            finally:
                remote.close()

        def done(result, error):
            self.test_button.setEnabled(True)
            if error:
                self.status.setText("连接测试失败：" + error)
            else:
                selected = self.interface.currentText()
                self.interface.clear()
                self.interface.addItems(result["interfaces"])
                if selected in result["interfaces"]:
                    self.interface.setCurrentText(selected)
                self.status.setText("连接成功，tcpdump 可用。已读取网卡，请确认选择。")

        self.main.background(work, done, owner=self)

    def save(self):
        try:
            server, secrets = self.values()
            self.main.credentials.set(server.id, secrets, self.remember.isChecked())
            if self.main.credentials.warning:
                QMessageBox.warning(self, "凭据存储提示", self.main.credentials.warning)
            self.server = server
            self.accept()
        except Exception as exc:
            QMessageBox.warning(self, "无法保存", str(exc))


class MainWindow(QMainWindow):
    def __init__(self, store: Store | None = None):
        super().__init__()
        self.setWindowTitle("远程抓包 · Capture Desk")
        self.resize(1320, 900)
        self.store = store or Store()
        self.credentials = Credentials()
        set_secret_provider(lambda: tuple(self.credentials.session.copy().values()))
        self.events = queue.SimpleQueue()
        self.closing = threading.Event()
        self.pending_prompts = []
        self.background_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix="probe")
        self.host_keys = HostKeys(self.store.root / "known_hosts", self.confirm_host)
        self.controller = Controller(self.store, self.host_keys,
                                     lambda snapshot: self.events.put(("task", snapshot)))
        self.servers = self.store.servers()
        self.tasks = {t.id: t for t in self.store.tasks()}
        self.deleted_task_ids = set()
        self.preview_busy = False
        for task in self.tasks.values():
            if task.state in {"连接中", "检查环境", "启动中", "抓包中", "停止中", "下载中", "重新连接"}:
                task.state = "状态未知" if task.remote_dir else "失败"
                if not task.remote_dir:
                    task.error = "上次启动在创建远端任务之前中断，可以重新发起抓包"
                self.store.save_task(task)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(22, 16, 22, 16)
        title = QLabel("远程抓包")
        title.setObjectName("title")
        layout.addWidget(title)
        subtitle = QLabel("多台 Linux 并行抓包  /  停止后自动下载  /  Wireshark 分析")
        subtitle.setObjectName("muted")
        layout.addWidget(subtitle)
        split = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(split, 2)
        server_group, left = section("1  选择服务器")
        row = QHBoxLayout()
        row.addWidget(button("添加服务器", self.add_server))
        row.addWidget(button("编辑 / 凭据", self.edit_server))
        row.addWidget(button("删除服务器", self.delete_server))
        row.addStretch()
        left.addLayout(row)
        self.server_table = table(["选择", "名称", "地址", "用户", "网卡", "权限"])
        self.server_table.cellDoubleClicked.connect(lambda *_: self.edit_server())
        left.addWidget(self.server_table)
        left.addWidget(QLabel("勾选要抓包的服务器，最多 10 台。双击可编辑配置。"))
        split.addWidget(server_group)
        config_group, config = section("2  设置抓包")
        form = QFormLayout()
        self.duration = spin(1, 86400, 600, " 秒")
        self.size = spin(1, 102400, 500, " MiB")
        self.count = spin(0, 2147483647, 0)
        self.count.setSpecialValueText("不限包数")
        self.mode = QComboBox()
        self.mode.addItem("表单过滤", "form")
        self.mode.addItem("高级 BPF 表达式", "bpf")
        self.filter_host = QLineEdit()
        self.filter_host.setPlaceholderText("可选，如 10.0.0.1")
        self.filter_port = QLineEdit()
        self.filter_port.setPlaceholderText("可选，如 443")
        self.protocol = QComboBox()
        for label, data in (("全部", "any"), ("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp"), ("ICMPv6", "icmp6")):
            self.protocol.addItem(label, data)
        self.bpf = QLineEdit()
        self.bpf.setPlaceholderText("host 10.0.0.1 and port 443")
        for label, field in (("最长时长", self.duration), ("大小保护阈值", self.size), ("包数上限", self.count),
                             ("过滤方式", self.mode), ("IP", self.filter_host), ("端口", self.filter_port),
                             ("协议", self.protocol), ("BPF", self.bpf)):
            form.addRow(label, field)
        config.addLayout(form)
        self.exclude = QCheckBox("排除本机与目标服务器之间的 SSH 流量")
        self.exclude.setChecked(True)
        config.addWidget(self.exclude)
        note = QLabel("任一上限满足即停止；大小阈值可能因检查间隔略有超出。\n断网后服务器继续抓包至保护上限。")
        note.setWordWrap(True)
        note.setObjectName("muted")
        config.addWidget(note)
        split.addWidget(config_group)
        split.setSizes([750, 480])
        self.mode.currentIndexChanged.connect(self.filter_mode)
        self.filter_mode()
        output = QHBoxLayout()
        output.addWidget(QLabel("保存目录"))
        documents = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
        self.output = QLineEdit(self.store.setting("output", str(Path(documents) / "远程抓包")))
        output.addWidget(self.output, 1)
        output.addWidget(button("选择目录", self.choose_output))
        self.start_button = button("预览并开始抓包", self.start_preview, True)
        output.addWidget(self.start_button)
        layout.addLayout(output)
        tasks_group, task_layout = section("3  抓包任务与历史")
        actions = QHBoxLayout()
        for text, handler in (("停止所选", self.stop_selected), ("停止全部", self.stop_all),
                              ("恢复连接 / 重试下载", self.resume_selected), ("打开目录", self.open_folder),
                              ("Wireshark 打开", self.open_wireshark), ("设置 Wireshark", self.configure_wireshark),
                              ("删除所选历史", self.delete_history)):
            actions.addWidget(button(text, handler))
        actions.addStretch()
        task_layout.addLayout(actions)
        self.task_table = table(["服务器 / 批次", "状态", "时长", "文件大小", "下载", "停止原因 / 提示"])
        self.task_table.itemSelectionChanged.connect(self.show_details)
        task_layout.addWidget(self.task_table)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(105)
        self.details.setPlaceholderText("选择任务查看实际过滤条件、远端文件位置和错误详情。")
        task_layout.addWidget(self.details)
        layout.addWidget(tasks_group, 2)
        self.statusBar().showMessage("就绪 · 服务器文件不会自动删除")
        self.statusBar().addPermanentWidget(button("诊断日志", self.open_diagnostics))
        self.render_servers()
        self.render_tasks()
        self.dispatch_timer = QTimer(self)
        self.dispatch_timer.setInterval(50)
        self.dispatch_timer.timeout.connect(self.drain_events)
        self.dispatch_timer.start()

    def drain_events(self):
        # No worker invokes Qt or crosses its Python-object signal converter.
        # Pause dispatch while a handler opens a nested modal event loop.
        self.dispatch_timer.stop()
        dirty = False
        deadline = time.monotonic() + 0.02
        try:
            for _ in range(100):
                if time.monotonic() >= deadline:
                    break
                if self.closing.is_set():
                    return
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if kind == "done":
                        self.background_done(*payload)
                    elif kind == "task":
                        if payload["id"] not in self.deleted_task_ids:
                            self.tasks[payload["id"]] = Task(**payload)
                            dirty = True
                    elif kind == "host":
                        try:
                            self.host_prompt(payload)
                        finally:
                            payload["event"].set()
                except Exception as exc:
                    record_exception("dispatch_" + kind, exc)
                    self.statusBar().showMessage("界面更新异常，已记录诊断，请检查任务状态。")
        finally:
            if not self.closing.is_set():
                try:
                    if dirty:
                        self.render_tasks()
                except Exception as exc:
                    record_exception("render_tasks", exc)
                finally:
                    self.dispatch_timer.start()

    def background_done(self, destination, result, error):
        callback, owner = destination
        if self.closing.is_set() or not isValid(owner):
            return
        if owner is not self and not owner.isVisible():
            return
        try:
            callback(result, error)
        except Exception as exc:
            record_exception("gui_callback", exc)
            self.preview_busy = False
            self.start_button.setEnabled(True)
            self.statusBar().showMessage("界面操作异常，已记录诊断；请检查任务状态后重试。")

    def background(self, work, callback, owner=None):
        if self.closing.is_set():
            return
        destination = (callback, owner if owner is not None else self)
        def run():
            try:
                result, error = work(), None
            except Exception as exc:
                result, error = None, str(exc)
            if not self.closing.is_set():
                self.events.put(("done", (destination, result, error)))
        self.background_pool.submit(run)

    def confirm_host(self, hostname, algorithm, fingerprint):
        request = dict(host=hostname, algorithm=algorithm, fingerprint=fingerprint, event=threading.Event(), accepted=False)
        self.events.put(("host", request))
        while not request["event"].wait(0.2):
            if self.closing.is_set():
                return False
        return request["accepted"]

    def host_prompt(self, request):
        if not self.closing.is_set():
            box = QMessageBox(self)
            box.setWindowTitle("首次连接：核对服务器指纹")
            box.setIcon(QMessageBox.Icon.Question)
            box.setTextFormat(Qt.TextFormat.PlainText)
            box.setText(f"服务器：{request['host']}\n算法：{request['algorithm']}\n指纹：{request['fingerprint']}\n\n请与管理员提供的指纹核对。是否信任此主机？")
            box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            box.setDefaultButton(QMessageBox.StandardButton.No)
            request["accepted"] = box.exec() == QMessageBox.StandardButton.Yes
        request["event"].set()

    def filter_mode(self):
        advanced = self.mode.currentData() == "bpf"
        self.bpf.setEnabled(advanced)
        for field in (self.filter_host, self.filter_port, self.protocol):
            field.setEnabled(not advanced)

    def render_servers(self):
        checked = {self.server_table.item(row, 0).data(Qt.ItemDataRole.UserRole) for row in range(self.server_table.rowCount())
                   if self.server_table.item(row, 0).checkState() == Qt.CheckState.Checked}
        self.server_table.setRowCount(len(self.servers))
        for row, server in enumerate(self.servers):
            item = QTableWidgetItem()
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable)
            item.setCheckState(Qt.CheckState.Checked if server.id in checked else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, server.id)
            self.server_table.setItem(row, 0, item)
            texts = [server.name, f"{server.host}:{server.port}", server.username, server.interface,
                     {"direct": "直接", "sudo": "免密 sudo", "sudo_password": "密码 sudo"}[server.privilege]]
            for col, text in enumerate(texts, 1):
                self.server_table.setItem(row, col, QTableWidgetItem(text))

    def add_server(self):
        dialog = ServerDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.servers.append(dialog.server)
            self.store.save_servers(self.servers)
            self.render_servers()

    def edit_server(self):
        row = self.server_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "编辑服务器", "请先选择一台服务器。")
            return
        dialog = ServerDialog(self, self.servers[row])
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.servers[row] = dialog.server
            self.store.save_servers(self.servers)
            self.render_servers()

    def protected_task(self, task):
        return (task.id in self.controller.active_ids()
                or task.state not in {"完成", "完成（抓包异常）", "失败", "下载失败"})

    def delete_server(self):
        row = self.server_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "删除服务器", "请先点击选择要删除的服务器行。")
            return
        server = self.servers[row]
        if self.preview_busy or any(t.server["id"] == server.id and self.protected_task(t)
                                    for t in self.tasks.values()):
            QMessageBox.warning(self, "暂不能删除", "该服务器有正在处理或状态未确认的任务。请先停止任务，或恢复连接确认状态。")
            return
        if QMessageBox.question(self, "删除服务器", f"删除服务器“{server.name}”的配置及保存的凭据？\n历史任务和所有抓包文件会保留。",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.store.remove_records("servers", {server.id})
        except Exception as exc:
            QMessageBox.warning(self, "删除失败", str(exc))
            return
        self.servers = [s for s in self.servers if s.id != server.id]
        self.render_servers()
        try:
            self.credentials.delete(server.id)
        except Exception:
            QMessageBox.warning(self, "凭据清理未完成", "服务器配置已删除，但凭据管理器未能清理保存的凭据。请在 Windows 凭据管理器检查对应条目。")
        self.statusBar().showMessage("服务器配置已删除；历史和抓包文件已保留。")

    def delete_history(self):
        tasks = self.selected_tasks()
        if not tasks:
            QMessageBox.information(self, "删除历史", "请先选择历史任务，可按 Ctrl / Shift 多选。")
            return
        if any(self.protected_task(t) for t in tasks):
            QMessageBox.warning(self, "暂不能删除", "所选任务包含正在处理或状态未知的任务，请先停止或恢复连接确认状态。")
            return
        if QMessageBox.question(self, "删除历史", f"删除选中的 {len(tasks)} 条历史记录？\n仅移除列表记录，本地和服务器上的抓包文件均保留。",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        ids = {t.id for t in tasks}
        try:
            self.store.remove_records("tasks", ids)
        except Exception as exc:
            QMessageBox.warning(self, "删除失败", str(exc))
            return
        self.deleted_task_ids.update(ids)
        self.task_table.clearSelection()
        for task_id in ids:
            self.tasks.pop(task_id, None)
        self.render_tasks()
        self.statusBar().showMessage(f"已删除 {len(ids)} 条历史记录，抓包文件已保留。")

    def choose_output(self):
        directory = QFileDialog.getExistingDirectory(self, "选择保存目录", self.output.text())
        if directory:
            self.output.setText(directory)
            self.store.set_setting("output", directory)

    def options(self):
        result = CaptureOptions(self.duration.value(), self.size.value(), self.count.value(), self.mode.currentData(),
                                self.filter_host.text(), self.filter_port.text(), self.protocol.currentData(),
                                self.bpf.text(), self.exclude.isChecked())
        result.validate()
        return result

    def start_preview(self):
        if self.preview_busy or self.closing.is_set():
            return
        try:
            selected = [server for row, server in enumerate(self.servers)
                        if self.server_table.item(row, 0).checkState() == Qt.CheckState.Checked]
            if not selected or len(selected) > 10:
                raise ValueError("请勾选 1–10 台服务器")
            active = self.controller.active_ids()
            if len(active) + len(selected) > 10:
                raise ValueError("与已有任务合计不能超过 10 台")
            # Avoid duplicate capture while an earlier task's remote state is unknown.
            unresolved = {t.server["id"] for t in self.tasks.values() if t.state in {"状态未知", "抓包中", "启动中", "停止中", "连接中", "检查环境", "重新连接"}}
            if any(s.id in unresolved for s in selected):
                raise ValueError("所选服务器有未结束或状态未知的任务，请先恢复连接并确认任务已停止")
            options = self.options()
            directory = Path(self.output.text()).expanduser()
            if not directory.is_absolute():
                raise ValueError("请选择绝对保存路径")
            directory.mkdir(parents=True, exist_ok=True)
            self.store.set_setting("output", str(directory))
            entries = [(s, self.credentials.get(s.id)) for s in selected]
        except Exception as exc:
            QMessageBox.warning(self, "无法开始", str(exc))
            return
        self.start_button.setEnabled(False)
        self.preview_busy = True
        self.statusBar().showMessage("正在连接服务器并解析实际过滤条件…")
        results = []

        def done(result, error):
            results.append(result if result else (None, None, None, error))
            if len(results) == len(entries):
                self.start_button.setEnabled(True)
                self.preview_busy = False
                self.preview_dialog(results, options, directory)

        for server, secrets in entries:
            def work(s=server, sec=secrets):
                remote = Remote(s, sec, self.host_keys)
                try:
                    remote.connect()
                    info = remote.inspect()
                    if s.interface not in info["interfaces"]:
                        raise ValueError(f"网卡 {s.interface} 不存在，请编辑服务器并读取网卡")
                    return s, sec, options.effective_filter(info["connection"]), None
                except Exception as exc:
                    return s, sec, None, sec.redact(str(exc))
                finally:
                    remote.close()
            self.background(work, done)

    def preview_dialog(self, results, options, directory):
        self.statusBar().showMessage("过滤条件已解析，请确认抓包范围")
        dialog = QDialog(self)
        dialog.setWindowTitle("确认实际抓包条件")
        dialog.resize(780, 480)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel(f"最长 {options.duration} 秒 · 大小阈值 {options.size_mib} MiB / 台 · 包数 {options.packet_count or '不限'}"))
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText("\n\n".join(f"{s.name if s else '服务器'} | {s.host if s else ''} | 网卡 {s.interface if s else ''}\n" +
                                    ("无法启动：" + error if error else (expr or "无过滤：捕获全部流量"))
                                    for s, _, expr, error in results))
        layout.addWidget(text)
        valid = [item for item in results if not item[3]]
        layout.addWidget(QLabel(f"将启动 {len(valid)} 台服务器；连接失败的服务器跳过。启动时再次校验过滤表达式与磁盘空间。"))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("开始抓包")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(valid))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        batch = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + identifier()[:8]
        for server, secrets, expression, _ in valid:
            task = Task.create(server, options, batch, str(directory / batch / safe_name(server.name)))
            task.effective_filter = expression
            try:
                self.tasks[task.id] = task
                self.store.save_task(task)
                self.controller.submit(Task(**asdict(task)), secrets)
            except Exception as exc:
                task.state, task.error = "失败", str(exc)
                self.store.save_task(task)
        self.render_tasks()

    def task_changed(self, snapshot):
        if self.closing.is_set() or snapshot["id"] in self.deleted_task_ids:
            return
        task = Task(**snapshot)
        self.tasks[task.id] = task
        self.render_tasks()

    def selected_tasks(self):
        rows = sorted({index.row() for index in self.task_table.selectedIndexes()})
        return [self.tasks[self.task_table.item(row, 0).data(Qt.ItemDataRole.UserRole)] for row in rows]

    def render_tasks(self):
        selected = {t.id for t in self.selected_tasks()} if self.task_table.rowCount() else set()
        self.task_table.blockSignals(True)
        ordered = sorted(self.tasks.values(), key=lambda t: t.created_at, reverse=True)
        self.task_table.setRowCount(len(ordered))
        reasons = {"manual": "手动停止", "duration": "到达时长", "size": "到达大小阈值", "packet_count": "到达包数", "error": "tcpdump 异常", "forced": "强制结束", "running": ""}
        for row, task in enumerate(ordered):
            values = [f"{task.server['name']} / {task.batch}", task.state, f"{task.elapsed} 秒", f"{task.size / 1024 / 1024:.2f} MiB",
                      f"{task.progress}%", task.error or reasons.get(task.reason, task.reason)]
            for col, value in enumerate(values):
                text = value.replace("\n", " ")[:180]
                item = self.task_table.item(row, col)
                if item is None:
                    item = QTableWidgetItem(text)
                    self.task_table.setItem(row, col, item)
                elif item.text() != text:
                    item.setText(text)
                if item.data(Qt.ItemDataRole.UserRole) != task.id:
                    item.setData(Qt.ItemDataRole.UserRole, task.id)
                if item.isSelected() != (task.id in selected):
                    item.setSelected(task.id in selected)
        self.task_table.blockSignals(False)
        self.show_details()

    def show_details(self):
        tasks = self.selected_tasks()
        if not tasks:
            self.details.clear()
            return
        t = tasks[0]
        self.details.setPlainText(f"任务：{t.id}\n过滤：{t.effective_filter or '无'}\n远端：{t.remote_dir}\n本地：{t.local_file or t.local_dir}\nSHA-256：{t.sha256 or '尚未校验'}\n{t.error}")

    def stop_selected(self):
        for task in self.selected_tasks():
            if task.state.startswith("完成"):
                continue
            if not self.controller.stop(task.id):
                self.resume_one(task, stop=True)

    def stop_all(self):
        for task in list(self.tasks.values()):
            if task.id in self.controller.active_ids():
                self.controller.stop(task.id)
            elif task.state == "状态未知" and task.remote_dir:
                self.resume_one(task, stop=True)

    def resume_selected(self):
        for task in self.selected_tasks():
            self.resume_one(task)

    def resume_one(self, task, stop=False):
        if task.id in self.controller.active_ids():
            return
        if not task.remote_dir:
            QMessageBox.information(self, "无法恢复", f"{task.server['name']}：尚未创建远端任务，请重新发起抓包。")
            return
        try:
            secrets = self.credentials.get(task.server["id"])
            needs_credentials = (task.server["auth"] == "password" and not secrets.password)
            if needs_credentials:
                dialog = ServerDialog(self, Server(**task.server))
                dialog.setWindowTitle("恢复任务：输入凭据（连接地址采用任务原始配置）")
                if dialog.exec() != QDialog.DialogCode.Accepted:
                    return
                secrets = self.credentials.get(task.server["id"])
            self.controller.submit(Task(**asdict(task)), secrets, resume=True)
            if stop:
                self.controller.stop(task.id)
        except Exception as exc:
            QMessageBox.warning(self, "恢复失败", str(exc))

    def open_folder(self):
        tasks = self.selected_tasks()
        path = Path(tasks[0].local_dir if tasks else self.output.text())
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def open_diagnostics(self):
        path = self.store.root / "diagnostics"
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def open_wireshark(self):
        tasks = self.selected_tasks()
        if not tasks or not tasks[0].local_file or not Path(tasks[0].local_file).is_file():
            QMessageBox.information(self, "打开抓包文件", "请选择已下载完成的任务。")
            return
        if getattr(self, "wireshark_busy", False):
            self.statusBar().showMessage("正在启动 Wireshark，请稍候…")
            return
        executable = find_wireshark(self.store.setting("wireshark"))
        if not executable:
            executable = self.configure_wireshark()
        if not executable:
            return
        capture = tasks[0].local_file
        self.wireshark_busy = True
        self.statusBar().showMessage("正在启动 Wireshark…")

        def done(result, error):
            self.wireshark_busy = False
            if error:
                self.statusBar().showMessage("Wireshark 启动失败，请检查程序路径或重新选择。")
                QMessageBox.warning(self, "无法打开 Wireshark", f"{error}\n\n程序：{executable}\n文件：{capture}")
            else:
                self.statusBar().showMessage(result)

        self.background(lambda: open_capture(executable, capture), done)

    def configure_wireshark(self):
        executable, _ = QFileDialog.getOpenFileName(
            self, "选择 Wireshark.exe", self.store.setting("wireshark") or "",
            "Wireshark (Wireshark.exe)")
        if not executable:
            self.statusBar().showMessage("已取消选择 Wireshark 程序")
            return None
        if Path(executable).name.lower() != "wireshark.exe" or not Path(executable).is_file():
            QMessageBox.warning(self, "程序路径不正确", "请选择已安装的 Wireshark.exe。")
            return None
        try:
            self.store.set_setting("wireshark", executable)
        except Exception as exc:
            QMessageBox.warning(self, "无法保存程序路径", str(exc))
            return None
        self.statusBar().showMessage("Wireshark 路径已保存")
        return executable

    def closeEvent(self, event):
        if self.controller.active_ids() or self.preview_busy:
            result = QMessageBox.question(self, "退出工具", "退出后，本地监控和下载会暂停。远端抓包仍按保护上限停止；重新打开后可恢复连接并下载。\n\n确定退出？",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if result != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self.closing.set()
        self.dispatch_timer.stop()
        self.controller.close()
        self.background_pool.shutdown(wait=False, cancel_futures=True)
        event.accept()
