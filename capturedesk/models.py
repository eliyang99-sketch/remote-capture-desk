from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def identifier() -> str:
    return uuid.uuid4().hex


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Server:
    name: str = "新服务器"
    host: str = ""
    port: int = 22
    username: str = "root"
    auth: str = "password"
    key_path: str = ""
    privilege: str = "direct"
    interface: str = "any"
    remote_base: str = "/tmp"
    id: str = field(default_factory=identifier)

    def validate(self):
        if not self.name.strip() or not self.host.strip() or not self.username.strip():
            raise ValueError("名称、服务器地址和用户名不能为空")
        if any(c.isspace() for c in self.host) or self.host.startswith("-"):
            raise ValueError("服务器地址格式错误")
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH 端口必须为 1–65535")
        if self.auth not in {"password", "key"} or self.privilege not in {"direct", "sudo", "sudo_password"}:
            raise ValueError("认证或权限方式无效")
        if self.auth == "key" and not self.key_path:
            raise ValueError("请选择私钥文件")
        if not self.interface or self.interface.startswith("-"):
            raise ValueError("请选择有效网卡")
        if not self.remote_base.startswith("/"):
            raise ValueError("远端临时目录必须是绝对路径")
        for value in asdict(self).values():
            if isinstance(value, str) and any(ord(c) < 32 for c in value):
                raise ValueError("配置不能包含控制字符")


@dataclass
class Secrets:
    password: str = ""
    passphrase: str = ""
    sudo_password: str = ""

    def redact(self, text: str) -> str:
        for secret in (self.password, self.passphrase, self.sudo_password):
            if secret:
                text = text.replace(secret, "[已隐藏]")
        return text


@dataclass
class CaptureOptions:
    duration: int = 600
    size_mib: int = 500
    packet_count: int = 0
    mode: str = "form"
    host: str = ""
    port: str = ""
    protocol: str = "any"
    expression: str = ""
    exclude_ssh: bool = True

    def validate(self):
        if not 1 <= self.duration <= 86400:
            raise ValueError("最长时长应为 1–86400 秒")
        if not 1 <= self.size_mib <= 102400:
            raise ValueError("大小阈值应为 1–102400 MiB")
        if not 0 <= self.packet_count <= 2147483647:
            raise ValueError("包数上限无效")
        if self.mode not in {"form", "bpf"}:
            raise ValueError("过滤模式无效")
        self.base_filter()

    def base_filter(self) -> str:
        if self.mode == "bpf":
            if len(self.expression) > 4096 or any(ord(c) < 32 for c in self.expression):
                raise ValueError("BPF 表达式过长或包含控制字符")
            return self.expression.strip()
        parts = []
        if self.host.strip():
            try:
                address = ipaddress.ip_address(self.host.strip())
            except ValueError as exc:
                raise ValueError("IP 字段必须是有效 IPv4 或 IPv6 地址") from exc
            parts.append(f"host {address}")
        if self.port.strip():
            if not self.port.strip().isdigit() or not 1 <= int(self.port) <= 65535:
                raise ValueError("过滤端口应为 1–65535")
            parts.append(f"port {int(self.port)}")
        if self.protocol not in {"any", "tcp", "udp", "icmp", "icmp6"}:
            raise ValueError("协议无效")
        if self.protocol != "any":
            parts.append(self.protocol)
        return " and ".join(parts)

    def effective_filter(self, ssh_connection: str) -> str:
        base = self.base_filter()
        if not self.exclude_ssh:
            return base
        fields = ssh_connection.split()
        if len(fields) != 4:
            raise ValueError("无法识别 SSH 连接端点；请检查服务器环境或关闭排除 SSH")
        client, _, server, port = fields
        ipaddress.ip_address(client)
        ipaddress.ip_address(server)
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("SSH_CONNECTION 端口无效")
        # Exclude all SSH control connections from this client, including reconnects.
        excluded = f"not (tcp and host {client} and host {server} and port {int(port)})"
        return f"({base}) and {excluded}" if base else excluded


@dataclass
class Task:
    id: str
    batch: str
    server: dict
    options: dict
    local_dir: str
    created_at: str = field(default_factory=now)
    state: str = "等待连接"
    remote_dir: str = ""
    effective_filter: str = ""
    size: int = 0
    elapsed: int = 0
    progress: int = 0
    reason: str = ""
    error: str = ""
    local_file: str = ""
    sha256: str = ""

    @classmethod
    def create(cls, server: Server, options: CaptureOptions, batch: str, local_dir: str):
        return cls(identifier(), batch, asdict(server), asdict(options), local_dir)


def safe_name(value: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", value)[:60].strip(" .")
    if not value or value.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        return "server_" + value
    return value
