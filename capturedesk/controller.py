from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

from .models import Secrets, Server, Task
from .remote import Remote


class Controller:
    """One worker owns each task. GUI receives immutable snapshots only."""

    def __init__(self, store, host_keys, changed, remote_factory=Remote):
        self.store, self.host_keys, self.changed = store, host_keys, changed
        self.remote_factory = remote_factory
        self.pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix="capture")
        self.lock = threading.RLock()
        self.active = {}
        self.connections = {}
        self.shutdown_event = threading.Event()

    def emit(self, task):
        if self.shutdown_event.is_set():
            return
        self.store.save_task(task)
        self.changed(asdict(task))

    def submit(self, task: Task, secrets: Secrets, resume=False):
        with self.lock:
            if task.id in self.active:
                return False
            if len(self.active) >= 10:
                raise ValueError("最多同时管理 10 个任务，请等待或停止已有任务")
            if any(server_id == task.server["id"] for _, server_id in self.active.values()):
                raise ValueError("该服务器已有正在管理的任务")
            stop = threading.Event()
            self.active[task.id] = (stop, task.server["id"])
            self.pool.submit(self._work, task, secrets, stop, resume)
            return True

    def stop(self, task_id):
        with self.lock:
            item = self.active.get(task_id)
            if item:
                item[0].set()
                return True
            return False

    def active_ids(self):
        with self.lock:
            return set(self.active)

    def close(self):
        self.shutdown_event.set()
        with self.lock:
            remotes = list(self.connections.values())
        for remote in remotes:
            client = getattr(remote, "client", None)
            if client:
                client.close()  # Abort pending reads; remote nohup tasks remain independent.
        self.pool.shutdown(wait=False, cancel_futures=True)

    def _work(self, task, secrets, stop, resume):
        remote = None
        phase = "connect"
        try:
            task.error = ""
            task.state = "重新连接" if resume else "连接中"
            self.emit(task)
            remote = self.remote_factory(Server(**task.server), secrets, self.host_keys)
            with self.lock:
                self.connections[task.id] = remote
            remote.connect()
            if self.shutdown_event.is_set():
                return
            if not resume:
                phase = "prepare"
                task.state = "检查环境"
                self.emit(task)
                info = remote.inspect()
                if self.shutdown_event.is_set():
                    return
                remote.prepare(task, info)
                # Durable path BEFORE dispatch, so a dropped launch acknowledgement is recoverable.
                task.state = "启动中"
                self.emit(task)
                phase = "launch"
                if self.shutdown_event.is_set():
                    return
                remote.launch(task)
            elif not task.remote_dir:
                raise ValueError("此任务未创建远端目录，请新建抓包任务")
            phase = "monitor"
            missing = 0
            stop_sent = False
            while not self.shutdown_event.is_set():
                if stop.is_set() and not stop_sent:
                    remote.stop(task)
                    stop_sent = True
                status = remote.status(task)
                if status is None:
                    missing += 1
                    if missing >= 8:
                        raise RuntimeError("未发现远端任务状态，请检查启动权限；" + remote.log(task))
                else:
                    task.size = int(status.get("size", 0))
                    task.elapsed = int(status.get("elapsed", 0))
                    task.reason = status.get("reason", "")
                    if status.get("phase") == "finished":
                        code = int(status.get("code", 1))
                        task.error = remote.log(task) if code or task.reason in {"error", "forced"} else ""
                        break
                    # Compare heartbeat against the server's own clock, never the desktop clock.
                    _, server_now, _ = remote.run("date +%s")
                    if int(server_now) - int(status.get("heartbeat", 0)) > 30:
                        raise RuntimeError("远端任务状态超过 30 秒未更新，无法确认抓包是否仍在运行")
                    task.state = "停止中" if stop_sent else "抓包中"
                    self.emit(task)
                self.shutdown_event.wait(2)
            if self.shutdown_event.is_set():
                task.state = "状态未知"
                task.error = "本地监控已退出；远端仍按保护上限停止，恢复连接后可下载"
                self.emit(task)
                return
            phase = "download"
            task.state = "下载中"
            task.progress = 0
            self.emit(task)
            last_progress = -1

            def progress(value):
                nonlocal last_progress
                if value != last_progress:
                    last_progress = value
                    task.progress = value
                    self.emit(task)

            task.local_file, task.sha256 = remote.download(task, progress, self.shutdown_event.is_set)
            task.state = "完成（抓包异常）" if task.error else "完成"
            self.emit(task)
        except Exception as exc:
            task.state = "下载失败" if phase == "download" else ("状态未知" if phase in {"launch", "monitor"} or resume else "失败")
            task.error = secrets.redact(str(exc) or type(exc).__name__)
            self.emit(task)
        finally:
            try:
                if remote:
                    remote.close()
            finally:
                with self.lock:
                    self.active.pop(task.id, None)
                    self.connections.pop(task.id, None)
