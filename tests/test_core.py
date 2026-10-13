import hashlib
import io
import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest

from capturedesk.controller import Controller
from capturedesk.models import CaptureOptions, Secrets, Server, Task, safe_name
from capturedesk.remote import HostKeys, Remote, build_supervisor
from capturedesk.storage import Store


def task(tmp_path, **options):
    return Task.create(Server(host="192.0.2.1"), CaptureOptions(**options), "batch", str(tmp_path / "中文目录"))


def test_filter_ipv6_and_ssh_exclusion():
    options = CaptureOptions(host="2001:db8::1", port="443", protocol="tcp")
    options.validate()
    assert options.effective_filter("2001:db8::2 54321 2001:db8::3 2222") == (
        "(host 2001:db8::1 and port 443 and tcp) and not (tcp and host 2001:db8::2 and host 2001:db8::3 and port 2222)"
    )


@pytest.mark.parametrize("kwargs", [{"duration": 0}, {"size_mib": 0}, {"host": "example.com;whoami"},
                                     {"port": "65536"}, {"protocol": "shell"}, {"mode": "bpf", "expression": "tcp\nls"}])
def test_invalid_options(kwargs):
    with pytest.raises(ValueError):
        CaptureOptions(**kwargs).validate()


def test_modes_are_exclusive():
    assert CaptureOptions(mode="bpf", expression="udp", host="invalid").base_filter() == "udp"
    assert CaptureOptions(expression="invalid", protocol="tcp").base_filter() == "tcp"
    with pytest.raises(ValueError):
        CaptureOptions().effective_filter("bad SSH environment")


def test_safe_name_windows():
    assert safe_name("CON") == "server_CON"
    assert safe_name("a/b:c") == "a_b_c"
    assert safe_name("上海服务器") == "上海服务器"


def test_store_durable_and_no_secrets(tmp_path):
    store = Store(tmp_path)
    server = Server(host="192.0.2.1")
    store.save_servers([server])
    t = task(tmp_path)
    store.save_task(t)
    t.state = "完成"
    store.save_task(t)
    fresh = Store(tmp_path)
    assert len(fresh.tasks()) == 1
    assert fresh.tasks()[0].state == "完成"
    assert fresh.servers()[0].id == server.id
    assert "password" not in asdict(server)  # auth='password' is a mode, not a secret field.
    assert "sudo_password" not in asdict(t)


def test_corrupt_store_not_overwritten(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("broken", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        Store(tmp_path)
    assert path.read_text() == "broken"


def test_host_fingerprint_changed_is_rejected(tmp_path):
    asked = []
    manager = HostKeys(tmp_path / "known_hosts", lambda *args: asked.append(args) or True)
    policy = manager.policy()
    client = paramiko.SSHClient()
    key1, key2 = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    policy.missing_host_key(client, "example", key1)
    policy.missing_host_key(client, "example", key1)
    assert len(asked) == 1
    with pytest.raises(paramiko.SSHException, match="变化"):
        policy.missing_host_key(client, "example", key2)
    assert len(asked) == 1


def test_host_rejection_does_not_persist(tmp_path):
    manager = HostKeys(tmp_path / "known_hosts", lambda *args: False)
    with pytest.raises(paramiko.SSHException):
        manager.policy().missing_host_key(paramiko.SSHClient(), "example", paramiko.RSAKey.generate(1024))
    assert not manager.path.exists()


def test_supervisor_scopes_process_and_quotes_bpf(tmp_path):
    t = task(tmp_path, mode="bpf", expression="tcp; touch /tmp/injected", exclude_ssh=False)
    t.remote_dir = "/tmp/capturedesk-abc"
    t.effective_filter = t.options["expression"]
    script = build_supervisor(t, ["/usr/bin/tcpdump", "-i", "any"], "/usr/bin/tcpdump")
    assert "'tcp; touch /tmp/injected'" in script
    assert '"$current" = "$identity"' in script
    assert '"$actual" != "$expected_exe"' in script
    assert '"$parent" = "$$"' in script
    assert '"$sink" != "$expected_sink"' in script
    assert "pkill" not in script and "killall" not in script
    assert "mkdir supervisor.lock" in script
    assert "stop.request" in script


class FakeSFTP:
    def __init__(self, payload):
        self.payload = payload

    def stat(self, path):
        return SimpleNamespace(st_size=len(self.payload))

    def file(self, path, mode):
        return io.BytesIO(self.payload)


def download_remote(payload, expected_hash=None):
    remote = Remote.__new__(Remote)
    remote.sftp = FakeSFTP(payload)
    remote.run = lambda *a, **kw: (0, (expected_hash or hashlib.sha256(payload).hexdigest()) + "  capture.pcap", "")
    return remote


def test_download_verifies_hash_and_keeps_existing(tmp_path):
    t = task(tmp_path)
    t.remote_dir = "/tmp/capturedesk-id"
    payload = b"pcap" * 70000
    remote = download_remote(payload)
    progress = []
    path, sha = remote.download(t, progress.append, lambda: False)
    assert Path(path).read_bytes() == payload
    assert sha == hashlib.sha256(payload).hexdigest() and progress[-1] == 100
    assert remote.download(t, progress.append, lambda: False)[0] == path
    Path(path).write_bytes(b"existing user content")
    with pytest.raises(RuntimeError, match="拒绝覆盖"):
        remote.download(t, progress.append, lambda: False)
    assert Path(path).read_bytes() == b"existing user content"


def test_hash_failure_and_cancel_never_publish_pcap(tmp_path):
    t = task(tmp_path)
    t.remote_dir = "/tmp/capturedesk-id"
    remote = download_remote(b"packet", "0" * 64)
    with pytest.raises(RuntimeError, match="校验失败"):
        remote.download(t, lambda _: None, lambda: False)
    assert not list(Path(t.local_dir).glob("*.pcap"))
    remote = download_remote(b"packet")
    with pytest.raises(InterruptedError):
        remote.download(t, lambda _: None, lambda: True)
    assert not list(Path(t.local_dir).glob("*.pcap"))


class FakeRemote:
    started = []
    stopped = []
    lock = threading.Lock()

    def __init__(self, server, secrets, host_keys):
        self.server = server

    def connect(self):
        if self.server.host == "fail":
            raise RuntimeError("test password supersecret")
        return self

    def inspect(self):
        return {}

    def prepare(self, task, info):
        task.remote_dir = "/tmp/" + task.id

    def launch(self, task):
        with self.lock:
            self.started.append(task.id)

    def status(self, task):
        return {"phase": "finished", "size": "24", "elapsed": "1", "reason": "duration", "code": "0"}

    def download(self, task, progress, cancelled):
        progress(100)
        return "test.pcap", "a" * 64

    def stop(self, task):
        self.stopped.append(task.id)

    def close(self):
        pass


def wait_idle(controller):
    deadline = time.monotonic() + 5
    while controller.active_ids() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not controller.active_ids()


def test_parallel_failure_isolation_and_redaction(tmp_path):
    store = Store(tmp_path)
    controller = Controller(store, None, lambda _: None, FakeRemote)
    good = task(tmp_path)
    bad = task(tmp_path)
    bad.server["host"] = "fail"
    controller.submit(good, Secrets())
    controller.submit(bad, Secrets(password="supersecret"))
    wait_idle(controller)
    assert good.state == "完成" and bad.state == "失败"
    assert "supersecret" not in store.path.read_text(encoding="utf-8")
    controller.close()


def test_resume_download_does_not_launch_new_capture(tmp_path):
    t = task(tmp_path)
    t.remote_dir = "/tmp/existing"
    controller = Controller(Store(tmp_path), None, lambda _: None, FakeRemote)
    controller.submit(t, Secrets(), resume=True)
    wait_idle(controller)
    assert t.state == "完成"
    assert t.id not in FakeRemote.started
    controller.close()


def test_concurrency_limit_and_duplicate_server(tmp_path):
    gate = threading.Event()

    class HeldRemote(FakeRemote):
        def inspect(self):
            assert gate.wait(5)
            return {}

    controller = Controller(Store(tmp_path), None, lambda _: None, HeldRemote)
    tasks = [task(tmp_path) for _ in range(11)]
    try:
        controller.submit(tasks[0], Secrets())
        assert controller.submit(tasks[0], Secrets()) is False
        duplicate = task(tmp_path)
        duplicate.server = tasks[0].server.copy()
        with pytest.raises(ValueError, match="已有"):
            controller.submit(duplicate, Secrets())
        for t in tasks[1:10]:
            controller.submit(t, Secrets())
        with pytest.raises(ValueError, match="10"):
            controller.submit(tasks[10], Secrets())
    finally:
        gate.set()
        wait_idle(controller)
        controller.close()


def test_close_during_preflight_never_launches_capture(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class BlockedRemote(FakeRemote):
        def __init__(self, *args):
            super().__init__(*args)
            self.client = SimpleNamespace(close=release.set)

        def inspect(self):
            entered.set()
            assert release.wait(5)
            return {}

    t = task(tmp_path)
    store = Store(tmp_path)
    controller = Controller(store, None, lambda _: None, BlockedRemote)
    controller.submit(t, Secrets())
    assert entered.wait(5)
    controller.close()
    wait_idle(controller)
    assert t.id not in FakeRemote.started
    assert store.tasks()[0].remote_dir == ""


def test_store_failure_is_reported_and_worker_released(tmp_path):
    class BrokenStore:
        def save_task(self, task):
            raise OSError('disk full')
    changed = []
    controller = Controller(BrokenStore(), None, changed.append, FakeRemote)
    controller.submit(task(tmp_path), Secrets())
    wait_idle(controller)
    assert changed and '保存失败' in changed[-1]['error']
    controller.close()


def test_submit_after_close_does_not_leave_active_task(tmp_path):
    controller = Controller(Store(tmp_path), None, lambda _: None, FakeRemote)
    controller.close()
    with pytest.raises(RuntimeError, match='退出'):
        controller.submit(task(tmp_path), Secrets())
    assert not controller.active_ids()


def test_diagnostics_do_not_log_exception_secrets():
    import logging
    from capturedesk.diagnostics import logger, record_exception
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    try:
        try:
            raise RuntimeError('password=very-private-test-secret')
        except RuntimeError as error:
            record_exception('test', error)
        assert 'RuntimeError' in stream.getvalue()
        assert 'very-private-test-secret' not in stream.getvalue()
    finally:
        logger.removeHandler(handler)


def test_delete_metadata_rollback_on_save_failure(tmp_path, monkeypatch):
    store = Store(tmp_path)
    t = task(tmp_path)
    store.save_task(t)
    def fail(): raise OSError('disk full')
    monkeypatch.setattr(store, 'flush', fail)
    with pytest.raises(OSError): store.remove_records('tasks', {t.id})
    assert store.tasks()[0].id == t.id
    assert Store(tmp_path).tasks()[0].id == t.id
