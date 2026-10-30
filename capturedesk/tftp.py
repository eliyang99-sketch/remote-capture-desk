"""Task-scoped, write-only TFTP receiver. No filesystem path comes from a client."""
from dataclasses import dataclass, field
from pathlib import Path
import socket
import struct
import threading
import time


@dataclass
class Upload:
    source: str | frozenset
    name: str
    path: Path
    limit: int = 64 * 1024 * 1024
    done: threading.Event = field(default_factory=threading.Event)
    cancelled: threading.Event = field(default_factory=threading.Event)
    size: int = 0
    error: str = ""
    active: bool = False
    peer: tuple | None = None
    channel: object = None
    reply: bytes = b""


class Receiver:
    def __init__(self, address, port=69):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((address, port))
        except Exception:
            self.socket.close()
            raise
        self.address = self.socket.getsockname()
        self.socket.settimeout(.2)
        self.lock = threading.RLock()
        self.uploads = {}
        self.closed = threading.Event()
        self.workers = []
        self.rejections = []
        self.thread = threading.Thread(target=self.listen, name="tftp-listener", daemon=True)
        self.thread.start()

    def register(self, upload):
        if "/" in upload.name or "\\" in upload.name or upload.name in {".", ".."}:
            raise ValueError("非法传输名称")
        with self.lock:
            if upload.name in self.uploads:
                raise ValueError("传输已登记")
            self.uploads[upload.name] = upload

    def unregister(self, upload):
        upload.cancelled.set()
        with self.lock:
            self.uploads.pop(upload.name, None)

    @staticmethod
    def error(sock, peer, message):
        sock.sendto(b"\x00\x05\x00\x02" + message.encode("ascii") + b"\0", peer)

    def listen(self):
        while not self.closed.is_set():
            try:
                packet, peer = self.socket.recvfrom(2048)
                fields = packet[2:].split(b"\0")
                if packet[:2] != b"\0\2" or len(fields) < 3 or fields[1].lower() != b"octet":
                    self.error(self.socket, peer, "Write-only octet service")
                    continue
                name = fields[0].decode("ascii")
                if name.startswith("/") and name.count("/") == 1:
                    name = name[1:]  # RGOS URL syntax can send a single leading slash.
                with self.lock:
                    upload = self.uploads.get(name)
                    if not upload or peer[0] not in ({upload.source} if isinstance(upload.source, str) else upload.source) or upload.done.is_set() or upload.cancelled.is_set():
                        self.rejections = (self.rejections + [(peer[0], name)])[-10:]
                        self.error(self.socket, peer, "Not authorized")
                        continue
                    if upload.active:
                        if upload.peer == peer and upload.channel and upload.reply:
                            upload.channel.sendto(upload.reply, peer)
                        continue
                    opts = fields[2:-1]
                    if len(opts) % 2:
                        self.error(self.socket, peer, "Bad options")
                        continue
                    options = {opts[i].decode("ascii").lower(): opts[i+1].decode("ascii") for i in range(0, len(opts), 2)}
                    upload.active, upload.peer = True, peer
                    worker = threading.Thread(target=self.receive, args=(upload, options), daemon=True)
                    self.workers.append(worker)
                    worker.start()
            except socket.timeout:
                pass
            except (OSError, UnicodeError, ValueError):
                if self.closed.is_set():
                    break

    def receive(self, upload, options):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.address[0], 0))
        sock.settimeout(.5)
        upload.channel = sock
        try:
            block_size = min(8192, max(8, int(options.get("blksize", 512))))
            accepted = {}
            if "blksize" in options:
                accepted["blksize"] = str(block_size)
            if "tsize" in options:
                size = int(options["tsize"])
                if not 0 <= size <= upload.limit:
                    raise ValueError("文件超过接收上限")
                accepted["tsize"] = str(size)
            upload.reply = (b"\0\6" + b"".join(k.encode()+b"\0"+v.encode()+b"\0" for k,v in accepted.items())
                            if accepted else b"\0\4\0\0")
            sock.sendto(upload.reply, upload.peer)
            block, retries = 1, 0
            upload.path.parent.mkdir(parents=True, exist_ok=True)
            with upload.path.open("xb") as output:
                while not (self.closed.is_set() or upload.cancelled.is_set()):
                    try:
                        data, peer = sock.recvfrom(block_size + 5)
                    except socket.timeout:
                        retries += 1
                        if retries > 12:
                            raise TimeoutError("TFTP 数据超时")
                        sock.sendto(upload.reply, upload.peer)
                        continue
                    if peer != upload.peer:
                        self.error(sock, peer, "Unknown transfer")
                        continue
                    if data[:2] == b"\0\5":
                        raise RuntimeError("设备取消 TFTP 传输")
                    if len(data) < 4 or data[:2] != b"\0\3" or len(data) > block_size+4:
                        continue
                    number = struct.unpack("!H", data[2:4])[0]
                    if number == ((block-1) & 65535):
                        sock.sendto(upload.reply, peer)
                        continue
                    if number != (block & 65535):
                        continue
                    payload = data[4:]
                    if upload.size + len(payload) > upload.limit:
                        raise ValueError("文件超过接收上限")
                    output.write(payload)
                    upload.size += len(payload)
                    upload.reply = b"\0\4" + data[2:4]
                    sock.sendto(upload.reply, peer)
                    retries = 0
                    block += 1
                    if len(payload) < block_size:
                        output.flush()
                        if "tsize" in accepted and upload.size != int(accepted["tsize"]):
                            raise ValueError("TFTP 长度不符")
                        output.close()  # Windows cannot rename an open destination file.
                        upload.done.set()
                        # Repeat final ACK if it was lost; never append duplicate data.
                        until = time.monotonic() + 2
                        while time.monotonic() < until and not self.closed.is_set():
                            try:
                                again, sender = sock.recvfrom(block_size+4)
                                if sender == peer and again == data:
                                    sock.sendto(upload.reply, peer)
                            except socket.timeout:
                                pass
                        return
                raise InterruptedError("TFTP 接收已取消")
        except Exception as exc:
            upload.error = str(exc)
            try:
                self.error(sock, upload.peer, "Transfer failed")
            except OSError:
                pass
        finally:
            upload.channel = None
            sock.close()
            upload.done.set()

    def close(self):
        self.closed.set()
        self.socket.close()
        self.thread.join(1)
        for worker in self.workers:
            worker.join(1)


_lock = threading.Lock()
_receivers = {}


def acquire(address):
    with _lock:
        if address not in _receivers:
            _receivers[address] = [Receiver(address), 0]
        value = _receivers[address]
        value[1] += 1
        return value[0]


def release(receiver):
    with _lock:
        value = _receivers.get(receiver.address[0])
        if value and value[0] is receiver:
            value[1] -= 1
            if value[1] == 0:
                del _receivers[receiver.address[0]]
                receiver.close()
