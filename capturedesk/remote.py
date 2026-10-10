from __future__ import annotations

import base64
import hashlib
import posixpath
import shlex
import threading
import time
from pathlib import Path

import paramiko

from .models import CaptureOptions, Secrets, Server, Task


def quote(value) -> str:
    return shlex.quote(str(value))


class HostKeys:
    def __init__(self, path: Path, confirm):
        self.path = path
        self.confirm = confirm
        self.lock = threading.Lock()

    def policy(self):
        manager = self

        class ConfirmPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
                with manager.lock:
                    known = paramiko.HostKeys()
                    if manager.path.exists():
                        known.load(str(manager.path))
                    if hostname in known:
                        if not known.check(hostname, key):
                            raise paramiko.SSHException("服务器主机指纹发生变化，连接已阻止；请核实主机身份")
                    else:
                        if not manager.confirm(hostname, key.get_name(), fingerprint):
                            raise paramiko.SSHException("未确认服务器指纹，连接已取消")
                        known.add(hostname, key.get_name(), key)
                        temp = manager.path.with_suffix(".tmp")
                        known.save(str(temp))
                        temp.replace(manager.path)
                    client.get_host_keys().add(hostname, key.get_name(), key)

        return ConfirmPolicy()


class Remote:
    def __init__(self, server: Server, secrets: Secrets, host_keys: HostKeys):
        self.server, self.secrets = server, secrets
        self.client = paramiko.SSHClient()
        # Read and compare under HostKeys.lock, including already known hosts.
        self.client.set_missing_host_key_policy(host_keys.policy())
        self.sftp = None

    def connect(self):
        self.server.validate()
        kwargs = dict(hostname=self.server.host, port=self.server.port, username=self.server.username,
                      timeout=12, banner_timeout=12, auth_timeout=15, allow_agent=False, look_for_keys=False)
        if self.server.auth == "key":
            kwargs.update(key_filename=self.server.key_path, passphrase=self.secrets.passphrase or None)
        else:
            kwargs["password"] = self.secrets.password
        try:
            self.client.connect(**kwargs)
            self.client.get_transport().set_keepalive(15)
            self.sftp = self.client.open_sftp()
            self.sftp.get_channel().settimeout(30)
        except Exception:
            self.close()
            raise
        return self

    def close(self):
        if self.sftp:
            self.sftp.close()
        self.client.close()

    def run(self, command: str, elevated=False, timeout=30, check=True):
        password = None
        if elevated and self.server.privilege != "direct":
            if self.server.privilege == "sudo_password":
                if not self.secrets.sudo_password:
                    raise ValueError("此服务器需要 sudo 密码，请编辑服务器凭据")
                command = "sudo -k -S -p '' -- sh -c " + quote(command)
                password = self.secrets.sudo_password
            else:
                command = "sudo -n -- sh -c " + quote(command)
        else:
            command = "sh -c " + quote(command)
        channel = self.client.get_transport().open_session(timeout=15)
        try:
            channel.settimeout(timeout)
            channel.exec_command(command)
            if password is not None:
                channel.sendall((password + "\n").encode())
            channel.shutdown_write()
            output, errors = bytearray(), bytearray()
            deadline = time.monotonic() + timeout
            while True:
                while channel.recv_ready():
                    output.extend(channel.recv(65536))
                while channel.recv_stderr_ready():
                    errors.extend(channel.recv_stderr(65536))
                if len(output) + len(errors) > 2_000_000:
                    raise RuntimeError("远端命令输出超出限制")
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError("服务器命令执行超时")
                time.sleep(0.03)
            code = channel.recv_exit_status()
            out = output.decode("utf-8", "replace").strip()
            err = errors.decode("utf-8", "replace").strip()
            if check and code:
                raise RuntimeError(self.secrets.redact(err or out or f"远端命令失败：{code}"))
            return code, out, err
        finally:
            channel.close()

    def inspect(self):
        _, info, _ = self.run("id -un; printf '%s\\n' \"$SSH_CONNECTION\"; uname -s")
        lines = info.splitlines()
        if len(lines) != 3 or lines[2] != "Linux":
            raise RuntimeError("第一版仅支持提供 SSH_CONNECTION 的 Linux 服务器")
        required = "sh nohup awk stat date sleep kill sha256sum df tr grep readlink id chmod mkdir mv cat"
        self.run("for x in " + required + "; do command -v \"$x\" >/dev/null || { echo \"缺少命令: $x\" >&2; exit 1; }; done; test -r /proc/self/stat")
        _, executable, _ = self.run("command -v tcpdump || { echo '未找到 tcpdump，请管理员安装或配置 PATH' >&2; exit 1; }", elevated=True)
        _, executable, _ = self.run("readlink -f " + quote(executable), elevated=True)
        _, devices, _ = self.run(quote(executable) + " -D", elevated=True)
        interfaces = []
        for line in devices.splitlines():
            first = line.split(" ", 1)[0]
            if "." in first:
                number, name = first.split(".", 1)
                if number.isdigit():
                    interfaces.append(name)
        if not interfaces:
            raise RuntimeError("tcpdump 没有返回可用网卡")
        self.run("test -d " + quote(self.server.remote_base) + " && test -w " + quote(self.server.remote_base) + " || { echo '临时目录不存在或不可写' >&2; exit 1; }")
        return {"owner": lines[0], "connection": lines[1], "executable": executable, "interfaces": interfaces}

    def prepare(self, task: Task, info: dict):
        options = CaptureOptions(**task.options)
        options.validate()
        if self.server.interface not in info["interfaces"]:
            raise ValueError(f"网卡 {self.server.interface} 不存在，请重新选择")
        effective = options.effective_filter(info["connection"])
        if task.effective_filter and task.effective_filter != effective:
            raise ValueError("SSH 连接端点已变化，请重新预览后新建抓包任务")
        task.effective_filter = effective
        args = [info["executable"], "-i", self.server.interface, "-s", "0", "-U", "-nn"]
        # -d compiles BPF before starting a task. No user text is executed as shell code.
        self.run(" ".join(map(quote, args + ["-d", "--", task.effective_filter])), elevated=True)
        _, available, _ = self.run("df -Pk " + quote(self.server.remote_base) + " | awk 'NR==2 {print $4}'")
        if not available.isdigit() or int(available) * 1024 < (options.size_mib + 64) * 1024 * 1024:
            raise RuntimeError("远端可用空间不足，需至少大小阈值加 64 MiB")
        expected = posixpath.join(self.server.remote_base, "capturedesk-" + task.id)
        if task.remote_dir and task.remote_dir != expected:
            raise ValueError("任务远端路径不匹配")
        task.remote_dir = expected
        self.sftp.mkdir(expected, mode=0o700)
        self.sftp.chmod(expected, 0o700)
        script = build_supervisor(task, args, info["executable"])
        with self.sftp.file(expected + "/supervisor.sh", "w") as stream:
            stream.write(script.encode())
        self.sftp.chmod(expected + "/supervisor.sh", 0o700)

    def launch(self, task: Task):
        directory = quote(task.remote_dir)
        # The parent shell returns after launch; nohup detaches before SSH closes.
        self.run(f"nohup sh {directory}/supervisor.sh </dev/null >{directory}/supervisor.log 2>&1 &", elevated=True)

    def status(self, task: Task):
        try:
            with self.sftp.file(task.remote_dir + "/status", "r") as stream:
                text = stream.read(8192).decode("utf-8", "replace")
        except FileNotFoundError:
            return None
        return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

    def stop(self, task: Task):
        # No PID from the client is ever passed to kill.
        with self.sftp.file(task.remote_dir + "/stop.request", "w") as stream:
            stream.write(b"stop\n")

    def log(self, task: Task):
        result = []
        for name in ("tcpdump.log", "supervisor.log"):
            try:
                with self.sftp.file(task.remote_dir + "/" + name, "r") as stream:
                    size = stream.stat().st_size
                    stream.seek(max(0, size - 6000))
                    result.append(stream.read(6000).decode("utf-8", "replace"))
            except OSError:
                pass
        return self.secrets.redact("\n".join(result).strip())

    def download(self, task: Task, progress, cancelled):
        remote = task.remote_dir + "/capture.pcap"
        expected_size = self.sftp.stat(remote).st_size
        _, output, _ = self.run("sha256sum -- " + quote(remote), timeout=300)
        expected_hash = output.split()[0]
        if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
            raise RuntimeError("服务器返回的 SHA-256 无效")
        folder = Path(task.local_dir)
        folder.mkdir(parents=True, exist_ok=True)
        final = folder / (task.id + ".pcap")
        part = folder / (task.id + ".pcap.part")
        if final.exists():
            if final.stat().st_size == expected_size and file_hash(final) == expected_hash:
                return str(final), expected_hash
            raise RuntimeError("本地目标文件已存在且校验不匹配，拒绝覆盖；请手动移走该文件后重试")
        digest = hashlib.sha256()
        count = 0
        # Retry from zero: a partial download never masquerades as a complete pcap.
        with self.sftp.file(remote, "rb") as source, part.open("wb") as target:
            while True:
                if cancelled():
                    raise InterruptedError("下载已暂停，重启或重试后可重新下载")
                chunk = source.read(256 * 1024)
                if not chunk:
                    break
                target.write(chunk)
                digest.update(chunk)
                count += len(chunk)
                progress(min(99, int(count * 100 / max(1, expected_size))))
        if count != expected_size or digest.hexdigest() != expected_hash:
            raise RuntimeError("下载大小或 SHA-256 校验失败，远端文件已保留")
        # Windows rename refuses an existing destination; do not replace user files.
        if final.exists():
            raise RuntimeError("本地目标文件已存在，拒绝覆盖")
        part.rename(final)
        progress(100)
        return str(final), expected_hash


def file_hash(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_supervisor(task: Task, args: list[str], executable: str) -> str:
    options = CaptureOptions(**task.options)
    options.validate()
    # Let tcpdump retain its distribution's default privilege drop. The shell opens
    # stdout first, so an unprivileged tcpdump can write into the private task folder.
    args = args + ["-w", "-"]
    if options.packet_count:
        args += ["-c", str(options.packet_count)]
    args += ["--", task.effective_filter]
    header = "\n".join(("#!/bin/sh", "umask 022", "ulimit -c 0", "cd " + quote(task.remote_dir) + " || exit 1",
                        "limit_seconds=" + str(options.duration), "limit_bytes=" + str(options.size_mib * 1024 * 1024),
                        "expected_exe=" + quote(executable), "capture_path=" + quote(task.remote_dir + "/capture.pcap")))
    return header + r'''
# mkdir is an atomic, permanent once-only launch marker. Never remove it.
mkdir supervisor.lock 2>/dev/null || exit 0
started=$(date +%s)
pid=0
identity=0
size=0
elapsed=0
reason=running
code=0
publish() {
    printf 'phase=%s\npid=%s\nidentity=%s\nstarted=%s\nelapsed=%s\nsize=%s\nreason=%s\ncode=%s\nheartbeat=%s\n' \
        "$1" "$pid" "$identity" "$started" "$elapsed" "$size" "$reason" "$code" "$(date +%s)" > status.tmp
    mv status.tmp status
}
matches() {
    [ "$pid" -gt 1 ] && [ -r "/proc/$pid/stat" ] || return 1
    current=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
    [ "$current" = "$identity" ] || return 1
    parent=$(awk '{print $4}' "/proc/$pid/stat" 2>/dev/null)
    [ "$parent" = "$$" ] || return 1
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)
    [ "$state" != Z ] || return 1
    # Restricted /proc mounts can hide exe/fd after tcpdump drops privileges.
    # PID + starttime + our direct child relationship are always mandatory.
    actual=$(readlink "/proc/$pid/exe" 2>/dev/null)
    if [ -n "$actual" ] && [ "$actual" != "$expected_exe" ]; then return 1; fi
    sink=$(readlink "/proc/$pid/fd/1" 2>/dev/null)
    expected_sink=$(readlink -f "$capture_path")
    if [ -n "$sink" ] && [ "$sink" != "$expected_sink" ]; then return 1; fi
    return 0
}
publish starting
''' + " ".join(map(quote, args)) + r''' >capture.pcap 2>tcpdump.log &
pid=$!
identity=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
publish running
while kill -0 "$pid" 2>/dev/null; do
    elapsed=$(( $(date +%s) - started ))
    size=$(stat -c %s capture.pcap 2>/dev/null || printf 0)
    if [ -f stop.request ]; then reason=manual
    elif [ "$elapsed" -ge "$limit_seconds" ]; then reason=duration
    elif [ "$size" -ge "$limit_bytes" ]; then reason=size
    else reason=running
    fi
    publish running
    if [ "$reason" != running ]; then
        if matches; then
            kill -INT "$pid" 2>/dev/null
            n=0
            while matches && [ "$n" -lt 10 ]; do sleep 1; n=$((n + 1)); done
            if matches; then
                reason=forced
                kill -TERM "$pid" 2>/dev/null
                sleep 2
                if matches; then kill -KILL "$pid" 2>/dev/null; fi
            fi
        fi
        break
    fi
    sleep 1
done
wait "$pid"
code=$?
elapsed=$(( $(date +%s) - started ))
size=$(stat -c %s capture.pcap 2>/dev/null || printf 0)
if [ "$reason" = running ]; then
    if [ "$code" -eq 0 ]; then reason=packet_count; else reason=error; fi
fi
publish finished
'''
