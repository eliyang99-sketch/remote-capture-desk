from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict
from pathlib import Path

from .models import Server, Task


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "RemoteCaptureDesk"
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.path = self.root / "state.json"
        self.data = {"version": 1, "servers": [], "tasks": [], "settings": {}}
        if self.path.exists():
            # Do not silently overwrite a corrupt history.
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if loaded.get("version") != 1:
                raise ValueError("不支持的数据版本，请备份本地数据后联系维护者")
            self.data.update(loaded)

    def flush(self):
        with self.lock:
            tmp = self.path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as stream:
                json.dump(self.data, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            # Windows scanners can briefly hold the destination without delete sharing.
            # Keep the old file intact and bound retries; permanent denial still propagates.
            for attempt in range(4):
                try:
                    tmp.replace(self.path)
                    break
                except PermissionError:
                    if attempt == 3:
                        raise
                    time.sleep(0.025 * (attempt + 1))

    def servers(self):
        with self.lock:
            return [Server(**s) for s in self.data["servers"]]

    def save_servers(self, servers):
        with self.lock:
            self.data["servers"] = [asdict(s) for s in servers]
            self.flush()

    def tasks(self):
        with self.lock:
            return [Task(**t) for t in self.data["tasks"]]

    def save_task(self, task: Task):
        with self.lock:
            rows = self.data["tasks"]
            for i, row in enumerate(rows):
                if row["id"] == task.id:
                    rows[i] = asdict(task)
                    break
            else:
                rows.append(asdict(task))
            self.flush()

    def setting(self, key, default=None):
        with self.lock:
            return self.data["settings"].get(key, default)

    def remove_records(self, kind, ids):
        """Only metadata is removed; never touch capture files or remote hosts."""
        if kind not in {"servers", "tasks"}:
            raise ValueError("不支持的记录类型")
        with self.lock:
            previous = self.data[kind]
            self.data[kind] = [row for row in previous if row["id"] not in ids]
            try:
                self.flush()
            except Exception:
                self.data[kind] = previous
                raise

    def set_setting(self, key, value):
        with self.lock:
            self.data["settings"][key] = value
            self.flush()
