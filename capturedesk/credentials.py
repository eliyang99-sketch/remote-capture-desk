from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .models import Secrets


class Credentials:
    """Explicit Windows Vault backend; never fall back to plaintext keyrings."""

    def __init__(self):
        self.session: dict[str, Secrets] = {}
        self.backend = None
        self.warning = ""
        if sys.platform == "win32":
            from keyring.backends.Windows import WinVaultKeyring
            self.backend = WinVaultKeyring()

    def get(self, server_id: str) -> Secrets:
        if server_id not in self.session:
            text = self._read(server_id)
            self.session[server_id] = Secrets(**json.loads(text)) if text else Secrets()
        return self.session[server_id]

    def _read(self, server_id: str):
        try:
            return self.backend.get_password("RemoteCaptureDesk", server_id) if self.backend else None
        except Exception:
            self.warning = "Windows 凭据管理器不可用。本次凭据只在内存中使用；无法确认或移除以前保存的凭据，请在系统凭据管理器中检查。"
            return None

    def remembered(self, server_id: str) -> bool:
        return bool(self._read(server_id))

    def set(self, server_id: str, secrets: Secrets, remember: bool):
        self.session[server_id] = secrets
        if remember:
            if self.backend is None:
                raise RuntimeError("仅 Windows 支持安全记住凭据")
            self.backend.set_password("RemoteCaptureDesk", server_id, json.dumps(asdict(secrets)))
        elif self.backend and self._read(server_id):
            self.backend.delete_password("RemoteCaptureDesk", server_id)
