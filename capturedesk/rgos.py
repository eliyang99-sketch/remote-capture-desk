"""RGOS interactive capture backend; scoped ownership and explicit cleanup."""
import hashlib
import re
import socket
import struct
import time
import uuid
import ipaddress
import json
import os
from pathlib import Path
import paramiko
from cryptography.hazmat.primitives import hashes
from .rgos_options import capture_arguments, FIELDS
from . import tftp
from . import rgos_backup


class LegacyRSA(paramiko.RSAKey):
    HASHES = {**paramiko.RSAKey.HASHES, "ssh-rsa": hashes.SHA1}


class DeviceTransport(paramiko.Transport):
    # Scoped to RGOS. Retain modern KEX, encryption and MAC preferences.
    _preferred_keys = paramiko.Transport._preferred_keys + ("ssh-rsa",)
    _key_info = {**paramiko.Transport._key_info, "ssh-rsa": LegacyRSA}


def clean(text):
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text).replace("\r", "")
    return re.sub(r"[^\n\x20-\x7e\u0080-\uffff]", "", text)


def parse_status(text):
    match = re.search(r"^\s*Status:\s*(\S+)", text, re.M)
    if not match or match[1].lower() not in {"stopped", "running", "started", "capturing"}:
        raise ValueError("无法识别设备抓包状态")
    filename = re.search(r"Filename:\s*(\S+)", text)
    started = re.search(r"^\s*Start time:\s*(.+)$", text, re.M)
    packets = re.search(r"Write file packet count:\s*(\d+)", text)
    return dict(running=match[1].lower() != "stopped", file=filename[1] if filename else "",
                started=started[1].strip() if started else "", packets=int(packets[1]) if packets else 0,
                rules=set(re.findall(r"^\s*Capture rules ([^:\s]+):", text, re.M)),
                points=set(re.findall(r"^\s*Capture point ([^:\s]+):", text, re.M)), raw=text)


def validate_pcap(path):
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(header[:4])
        if len(header) != 24 or not endian:
            raise ValueError("无效的 pcap 全局头")
        major, minor, _, _, snaplen, _ = struct.unpack(endian+"HHIIII", header[4:])
        if (major, minor) != (2, 4) or not 1 <= snaplen <= 16777216:
            raise ValueError("不支持的 pcap 格式")
        while True:
            record = stream.read(16)
            if not record:
                return
            if len(record) != 16:
                raise ValueError("pcap 记录不完整")
            _, _, size, original = struct.unpack(endian+"IIII", record)
            if size > snaplen or size > original or len(stream.read(size)) != size:
                raise ValueError("pcap 报文不完整")


class RgosRemote:
    is_device = True
    def __init__(self, server, secrets, host_keys):
        self.server, self.secrets, self.host_keys = server, secrets, host_keys
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(host_keys.policy())
        self.channel = None
        self.receiver = None
        self.capabilities = None
        self.prompt = ""
        self.cli_uncertain = False

    def connect(self):
        self.server.validate()
        kwargs = dict(hostname=self.server.host, port=self.server.port, username=self.server.username,
                      timeout=12, banner_timeout=12, auth_timeout=15, look_for_keys=False, allow_agent=False,
                      transport_factory=DeviceTransport)
        if self.server.auth == "key":
            kwargs.update(key_filename=self.server.key_path, passphrase=self.secrets.passphrase or None)
        else:
            kwargs["password"] = self.secrets.password
        try:
            self.client.connect(**kwargs)
            self.client.get_transport().set_keepalive(15)
            self.channel = self.client.invoke_shell(width=240, height=300)
            greeting = self.read(15, discover=True)
            if self.prompt.endswith(">"):
                self.channel.send("enable\n")
                text = self.read(10, password=True)
                if re.search(r"[Pp]assword:\s*$", text):
                    if not self.secrets.enable_password:
                        raise ValueError("设备需要单独的 enable 密码")
                    self.channel.send(self.secrets.enable_password+"\n")
                    self.read(10, discover=True)
            if not self.prompt.endswith("#"):
                raise ValueError("设备未进入特权模式")
            self.cli_uncertain = False
            return self
        except Exception:
            self.close()
            raise

    def read(self, timeout, discover=False, password=False, confirm=False):
        data = ""
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if self.channel.recv_ready():
                chunk = self.channel.recv(65535)
                if not chunk:
                    raise ConnectionError("SSH 会话已关闭")
                data += chunk.decode("utf-8", errors="replace")
                if "--More--" in data:
                    data = data.replace("--More--", "")
                    self.channel.send(" ")
                text = clean(data)
                self.last_text = text
                if confirm and (re.search(r"(?i)\[confirm\]|\[y/n\]|\(y/n\)|\[yes/no\]", text)
                                or re.search(r"(?i)(?:delete|remove).*\?\s*$", text)):
                    self.channel.send("y\n" if re.search(r"(?i)y/n|yes/no", text) else "\n")
                    data = ""
                    continue
                if password and re.search(r"[Pp]assword:\s*$", text):
                    return text
                match = re.search(r"(?:^|\n)([A-Za-z0-9_.:/()\-]+[>#])\s*$", text)
                if match:
                    if discover or not self.prompt or match[1] == self.prompt or self.prompt.endswith(">"):
                        self.prompt = match[1]
                        return text
            elif self.channel.closed:
                raise ConnectionError("SSH 会话已关闭")
            else:
                time.sleep(.03)
        raise TimeoutError("等待设备命令提示符超时")

    def command(self, command, timeout=20, check=True):
        if any(c in command for c in "\r\n\x00"):
            raise ValueError("命令包含控制字符")
        try:
            self.channel.send(command+"\n")
            text = self.read(timeout, confirm=command.startswith("delete "))
        except Exception:
            self.cli_uncertain = True
            raise
        if check and re.search(r"(?im)^\s*%|^\s*(?:copy|dir|verify|operation|command)\s+failed|^\s*(?:error:|permission denied)|unrecognized|invalid input|no such file|too long|can't|cannot|not support", text):
            raise RuntimeError(self.secrets.redact(text[-2000:]))
        return text

    def help(self, command):
        self.channel.send(command+" ?")
        time.sleep(.25)
        result = b""
        while self.channel.recv_ready():
            result += self.channel.recv(65535)
            time.sleep(.03)
        self.channel.send("\x15\n")
        self.read(10)
        return clean(result.decode(errors="replace"))

    def current(self):
        return parse_status(self.command("show packet capture status"))

    def inspect(self):
        version = self.command("show version")
        text = self.command("show interfaces status")
        interfaces = re.findall(r"^((?:GigabitEthernet|TenGigabitEthernet|AggregatePort)\s+\d+(?:/\d+){0,2})\s", text, re.M)
        if not interfaces:
            raise ValueError("未读取到可用接口列表")
        caps = {}
        for name, suffix in (("buffer_mb", "buffer-size"), ("packets", "packet-num")):
            help_text = self.help(f"packet capture file tmp:cd_probe.pcap {suffix}")
            match = re.search(r"<1-(\d+)>", help_text)
            if not match:
                raise ValueError("设备未提供抓包参数范围")
            caps[name] = int(match[1])
        fields = self.help("packet capture rule cd_probe filter")
        caps["fields"] = [field for field in FIELDS if re.search(r"\b"+field+r"\b", fields)]
        caps["source_ips"] = self.source_ips()
        self.capabilities = caps
        status = self.current()
        return dict(interfaces=interfaces+["control-plane"], capabilities=caps, version=version,
                    status=status,
                    conflict=status["running"] or bool(status["file"] or status["points"] or status["rules"]))

    def source_ips(self):
        text = self.command("show ip interface brief")
        addresses = set()
        for value in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d+", text):
            addresses.add(str(ipaddress.IPv4Interface(value).ip))
        addresses.add(self.client.get_transport().sock.getpeername()[0])
        return sorted(addresses)

    def validate_identity(self, task):
        d = task.device
        name = "cd"+task.id[:8]
        if (not re.fullmatch(r"[0-9a-f]{32}", task.id) or d.get("file") != self.server.remote_base+name+".pcap"
                or d.get("rule") != name or d.get("point") != name):
            raise ValueError("任务远端标识无效，禁止执行设备操作")

    def check_owner(self, task):
        self.validate_identity(task)
        d = task.device
        status = self.current()
        if status["file"] and status["file"] != d["file"]:
            raise RuntimeError("设备抓包文件已被外部配置替换，禁止接管")
        if status["rules"] - {d["rule"]} or status["points"] - {d["point"]}:
            raise RuntimeError("发现人工规则/抓包点，禁止接管")
        if status["running"] and (status["file"] != d["file"] or d["point"] not in status["points"]):
            raise RuntimeError("无法确认运行任务归属")
        if status["file"] and d.get("started_identity") and (status["started"] or status["running"]) and status["started"] != d["started_identity"]:
            raise RuntimeError("抓包启动标识已变化，禁止接管")
        return status

    def plan(self, options, info):
        cfg = capture_arguments(options.device, info["capabilities"])
        if options.device.get('approved_backup') and not info['conflict']:
            raise ValueError('预览中的旧配置已变化，请重新预览确认')
        if info["conflict"]:
            if not options.device.get("takeover"):
                raise ValueError("设备已有抓包或人工配置；可勾选临时接管，备份后抓包并恢复旧配置")
            previous = rgos_backup.snapshot(info['status'])
            rgos_backup.restore_commands(previous)  # Refuse unsupported restoration before touching anything.
            approved = options.device.get('approved_backup')
            if approved and rgos_backup.signature(previous) != rgos_backup.signature(approved):
                raise ValueError('旧配置在预览后发生变化，请重新预览确认')
            cfg['previous'] = previous
        if self.server.interface not in info["interfaces"]:
            raise ValueError("所选接口不存在")
        return cfg

    def acquire_receiver(self):
        if self.receiver:
            return
        address = self.server.receiver_ip or self.client.get_transport().sock.getsockname()[0]
        try:
            self.receiver = tftp.acquire(address)
        except OSError as exc:
            raise RuntimeError("无法启动本机 TFTP UDP 69 接收器，请检查地址、端口占用及防火墙") from exc

    def prepare_intent(self, task, info):
        from .models import CaptureOptions
        cfg = self.plan(CaptureOptions(**task.options), info)
        self.acquire_receiver()
        # These RGOS builds limit both the basename (including suffix) and rule to 15 characters.
        name = "cd"+task.id[:8]
        task.device = dict(intent=True, file=self.server.remote_base+name+".pcap", rule=name, point=name,
                           capabilities=info["capabilities"], config=cfg, cleanup="pending", stopped=False,
                           transfer="pending", created=[], version=info["version"], receiver=self.receiver.address[0])
        task.remote_dir = task.device["file"]
        task.effective_filter = cfg["filter_cli"] or "全部报文"
        if self.file_info(task) is not None:
            task.device = {}
            task.remote_dir = ""
            raise ValueError("远端同名文件已存在，拒绝覆盖或清理")
        if cfg.get('previous'):
            previous = cfg.pop('previous')
            if name in previous['rules'] or name in previous['points']:
                task.device = {}
                raise ValueError('旧配置与本任务名称冲突，请重新预览')
            task.device['takeover'] = dict(previous=previous, raw=info['status']['raw'], phase='backup_pending')

    def configure(self, task, persist):
        d, cfg = task.device, task.device["config"]
        self.validate_identity(task)
        if not d.get('takeover'):
            self.check_owner(task)
        capacity = self.command("show file systems")
        match = re.search(r"^\s*\d+\s+(\d+)\s+disk\s+rw\s+"+re.escape(self.server.remote_base)+r"\s*$", capacity, re.M)
        if not match or int(match[1]) < (cfg["buffer_mb"]+16)*1024:
            raise ValueError("设备临时存储空间不足或无法确认容量")
        if self.file_info(task) is not None:
            raise ValueError("设备同名文件已存在，拒绝覆盖")
        if d.get('takeover'):
            self.takeover_previous(task, persist)
        location = "control-plane" if self.server.interface == "control-plane" else "interface "+self.server.interface
        commands = [("file", f"packet capture file {d['file']} buffer-size {cfg['buffer_mb']} packet-num {cfg['packets']} timeout {cfg['minutes']}"),
                    ("rule", f"packet capture rule {d['rule']} filter"+(" "+cfg["filter_cli"] if cfg["filter_cli"] else "")),
                    ("point", f"packet capture point {d['point']} rule {d['rule']} location {location} {self.server.direction}")]
        for kind, cmd in commands:
            d["configuring"] = kind
            persist()
            self.check_owner(task)
            self.command(cmd)
            status = self.check_owner(task)
            if ((kind == "file" and status["file"] != d["file"])
                    or (kind == "rule" and d["rule"] not in status["rules"])
                    or (kind == "point" and d["point"] not in status["points"])):
                raise RuntimeError("设备未确认配置生效："+kind)
            d["created"].append(kind)
            persist()
        self.check_owner(task)

    def launch(self, task):
        self.check_owner(task)
        task.device["launch_intent"] = True
        self.command("packet capture start")
        status = self.check_owner(task)
        if status["file"] != task.device["file"]:
            raise RuntimeError("启动后设备文件配置不匹配")
        task.device["started_identity"] = status["started"]
        task.device["started_local"] = time.time()

    def stop(self, task):
        status = self.check_owner(task)
        # An automatic stop still needs an explicit, scoped stop confirmation.
        if status["file"] == task.device["file"]:
            self.command("packet capture stop")
        if self.check_owner(task)["running"]:
            raise RuntimeError("设备尚未确认停止")
        task.device["stopped"] = True

    def file_info(self, task):
        path = task.device["file"]
        text = self.command("dir "+path, check=False)
        if re.search(r"(?i)not exist|not found|no such|doesn't exist", text):
            return None
        matches = re.findall(r"^\s*\d+\s+[-rwx]+\s+(\d+(?:\.\d+)?)([BkKM]?)\s+.*\s"+re.escape(path.split(":",1)[1])+r"\s*$", text, re.M)
        if not matches:
            raise ValueError("无法识别远端文件元数据")
        value, unit = matches[0]
        return dict(value=float(value), unit=unit, exact=int(value) if unit in {"", "B"} else None)

    def download(self, task, progress, cancelled):
        self.check_owner(task)
        if not task.device.get("stopped"):
            raise RuntimeError("未确认停止")
        self.acquire_receiver()
        metadata = self.file_info(task)
        if metadata is None:
            raise ValueError("抓包文件不存在")
        size = metadata["exact"] or int(metadata["value"]*({"k":1024,"K":1024,"M":1048576}.get(metadata["unit"],1)))
        md5_text = self.command("verify "+task.device["file"], timeout=20)
        hashes_found = re.findall(r"\b[0-9a-fA-F]{32}\b", md5_text)
        if not hashes_found:
            raise ValueError("无法读取设备文件 MD5")
        expected = hashes_found[-1].lower()
        task.device["remote_md5"] = expected
        folder = Path(task.local_dir)
        folder.mkdir(parents=True, exist_ok=True)
        destination = folder/(task.id+".pcap")
        deadline = time.monotonic()+90
        sources = frozenset(self.source_ips())
        errors = []
        for attempt in range(3):
            if cancelled() or time.monotonic() >= deadline:
                break
            self.acquire_receiver()
            self.check_owner(task)
            name = uuid.uuid4().hex+".pcap"
            part = folder/(task.id+"."+uuid.uuid4().hex+".part")
            upload = tftp.Upload(sources, name, part)
            receiver = self.receiver
            receiver.register(upload)
            try:
                response = self.command(f"copy {task.device['file']} tftp://{receiver.address[0]}/{name}",
                                        timeout=max(1, min(27, deadline-time.monotonic())))
                task.device["copy_result"] = response[-2000:]
                while not upload.done.wait(.1):
                    progress(min(99, int(upload.size/max(1,size)*100)))
                    if cancelled() or time.monotonic() >= deadline:
                        raise TimeoutError("取回超时或已取消")
                if upload.error:
                    raise RuntimeError(upload.error)
                lengths = re.findall(r"(?i)(\d+)\s+bytes\s+(?:copied|transferred|copy)", response)
                exact = metadata["exact"] if metadata["exact"] is not None else (int(lengths[-1]) if lengths else None)
                if (exact is not None and upload.size != exact) or hashlib.md5(part.read_bytes()).hexdigest() != expected:
                    raise ValueError("设备文件大小或 MD5 不匹配")
                if exact is None:
                    # RGOS reports a rounded directory size and no copy byte count.
                    # Compare at the reported precision; MD5 is independently checked above.
                    unit = metadata["unit"].lower()
                    factors = (1000, 1024) if unit == "k" else (1000000, 1048576)
                    if not any(round(upload.size/factor, 1) == metadata["value"] for factor in factors):
                        raise ValueError("接收长度与设备目录大小不符")
                task.device["size_verification"] = "exact" if exact is not None else "directory-rounded+MD5"
                validate_pcap(part)
                sha = hashlib.sha256(part.read_bytes()).hexdigest()
                if destination.exists():
                    if hashlib.sha256(destination.read_bytes()).hexdigest() != sha:
                        raise ValueError("本地同名文件冲突，拒绝覆盖")
                else:
                    part.rename(destination)
                task.device["transfer"] = "verified"
                task.size = upload.size
                progress(100)
                return str(destination), sha
            except Exception as exc:
                errors.append(type(exc).__name__+": "+str(exc))
                # Command timeout leaves CLI state uncertain. Reconnect before any retry/cleanup.
                if isinstance(exc, (TimeoutError, ConnectionError, paramiko.SSHException)):
                    break  # A timed-out CLI is not safe to reuse; cleanup reconnects independently.
            finally:
                receiver.unregister(upload)
        task.device["transfer"] = "failed"
        raise RuntimeError("取回失败："+self.secrets.redact("；".join(errors)))

    def cleanup(self, task, persist):
        if task.device.get('takeover'):
            return self.cleanup_takeover(task, persist)
        self.stop(task)
        persist()
        d = task.device
        status = self.check_owner(task)
        if d["point"] in status["points"]:
            self.command("clear packet capture point "+d["point"])
        if d["rule"] in self.check_owner(task)["rules"]:
            self.command("clear packet capture rule "+d["rule"])
        if self.check_owner(task)["file"] == d["file"]:
            self.command("clear packet capture file")
        self.check_owner(task)
        exists = self.file_info(task)
        if exists is not None and not d.get("launch_intent"):
            raise RuntimeError("未发起抓包但发现同名文件，禁止删除")
        if exists is not None:
            self.command("delete "+d["file"])
        if self.file_info(task) is not None:
            raise RuntimeError("远端文件删除未确认")
        status = self.check_owner(task)
        if status["file"] or status["points"] or status["rules"]:
            raise RuntimeError("远端抓包配置清理未确认")
        d["cleanup"] = "done"
        persist()

    def takeover_previous(self, task, persist):
        d = task.device
        takeover = d['takeover']
        previous = takeover['previous']
        current = rgos_backup.snapshot(self.current())
        if rgos_backup.signature(current) != rgos_backup.signature(previous):
            raise RuntimeError('旧配置已发生变化，取消接管，请重新预览')
        folder = Path(task.local_dir)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder/'rgos-previous-config.json'
        contents = dict(version=1,task_id=task.id,host=self.server.host,previous=previous,
                        original_status=takeover['raw'],restore_commands=[list(c) for c in rgos_backup.restore_commands(previous)])
        if not path.exists():
            with path.open('x',encoding='utf-8') as stream:
                json.dump(contents,stream,ensure_ascii=False,indent=2)
                stream.flush();os.fsync(stream.fileno())
        elif json.loads(path.read_text(encoding='utf-8')) != contents:
            raise ValueError('旧配置备份文件冲突，拒绝覆盖')
        takeover['backup_file'] = str(path)
        takeover['phase'] = 'backed_up'
        persist()
        if previous['file']:
            response = self.command('verify '+previous['file']['path'],check=False)
            match = re.search(r'\b[0-9a-fA-F]{32}\b',response)
            takeover['previous_md5'] = match[0].lower() if match else None
            persist()
        for name in sorted(previous['points']):
            rgos_backup.validate_subset(rgos_backup.snapshot(self.current()),previous)
            takeover['phase'] = 'removing';persist()
            self.command('clear packet capture point '+name)
        for name in sorted(previous['rules']):
            rgos_backup.validate_subset(rgos_backup.snapshot(self.current()),previous)
            self.command('clear packet capture rule '+name)
        if previous['file']:
            rgos_backup.validate_subset(rgos_backup.snapshot(self.current()),previous)
            self.command('clear packet capture file')
        current = rgos_backup.snapshot(self.current())
        if any(current.values()):
            raise RuntimeError('旧配置尚未全部临时移除')
        takeover['phase'] = 'removed';persist()

    def previous_remaining(self, task):
        """Remove only our blocks from a read-only view, then validate every old block."""
        self.validate_identity(task)
        status = self.current()
        if status['running']:
            raise RuntimeError('设备仍在抓包，不能恢复旧配置')
        text = status['raw']
        for label, key in (('rules','rule'),('point','point')):
            pattern = (r'(?ms)^[ \t]+Capture '+label+' '+re.escape(task.device[key])+r':[^\n]*\n.*?'
                       r'(?=^[ \t]+Capture '+label+r' [^:\n]+:|^Capture (?:points|file|Statistic):|\Z)')
            text = re.sub(pattern,'',text)
        if status['file'] == task.device['file']:
            text = re.sub(r'(?ms)^Capture file:.*?(?=^Capture Statistic:|\Z)','',text)
        remaining = rgos_backup.snapshot(parse_status(text))
        rgos_backup.validate_subset(remaining,task.device['takeover']['previous'])
        return status,remaining

    def cleanup_takeover(self, task, persist):
        self.validate_identity(task)
        d = task.device
        previous = d['takeover']['previous']
        # The original raw snapshot must independently reconstruct the persisted restore plan.
        if rgos_backup.signature(rgos_backup.snapshot(parse_status(d['takeover']['raw']))) != rgos_backup.signature(previous):
            raise ValueError('旧配置备份不一致，禁止自动恢复')
        status = self.current()
        if status['running']:
            self.stop(task)
        status, _ = self.previous_remaining(task)
        d['stopped'] = True;persist()
        if d['point'] in status['points']:
            self.command('clear packet capture point '+d['point'])
        status,_ = self.previous_remaining(task)
        if d['rule'] in status['rules']:
            self.command('clear packet capture rule '+d['rule'])
        status,_ = self.previous_remaining(task)
        if status['file'] == d['file']:
            self.command('clear packet capture file')
        self.previous_remaining(task)
        if self.file_info(task) is not None:
            if not d.get('launch_intent'):
                raise RuntimeError('没有本任务启动记录，禁止删除同名文件')
            self.command('delete '+d['file'])
        if self.file_info(task) is not None:
            raise RuntimeError('本任务文件删除未确认')
        d['takeover']['phase'] = 'restoring';persist()
        for kind,name,command in rgos_backup.restore_commands(previous):
            _,current = self.previous_remaining(task)
            exists = current['file'] is not None if kind == 'file' else name in current[kind+'s']
            if not exists:
                persist()
                self.command(command)
        restored = rgos_backup.snapshot(self.current())
        if rgos_backup.signature(restored) != rgos_backup.signature(previous):
            raise RuntimeError('旧配置恢复校验未通过，请恢复连接重试')
        if d['takeover'].get('previous_md5'):
            response = self.command('verify '+previous['file']['path'])
            if d['takeover']['previous_md5'] not in response.lower():
                raise RuntimeError('旧抓包文件校验发生变化，请检查设备')
        d['takeover']['phase'] = 'restored'
        d['cleanup'] = 'done';persist()

    def reconnect(self):
        if self.channel:
            self.channel.close()
        self.client.close()
        self.prompt = ""
        # Some RGOS releases throttle immediate successive password sessions.
        for attempt in range(3):
            try:
                self.connect()
                return
            except paramiko.AuthenticationException:
                if attempt == 2:
                    raise
                time.sleep(1)

    def ensure_connected(self):
        transport = self.client.get_transport()
        if self.cli_uncertain or not transport or not transport.is_active() or not self.channel or self.channel.closed:
            self.reconnect()

    def close(self):
        if self.receiver:
            tftp.release(self.receiver)
            self.receiver = None
        self.client.close()
