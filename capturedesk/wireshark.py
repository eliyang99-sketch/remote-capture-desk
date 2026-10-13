"""Launch the system Wireshark without inheriting our bundled Qt runtime."""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

_launch_lock = threading.Lock()


def registry_paths():
    if sys.platform != "win32":
        return []
    import winreg
    found = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            for key, value in ((r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe", ""),
                               (r"SOFTWARE\Wireshark", "InstallDir")):
                try:
                    with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | view) as handle:
                        path = winreg.QueryValueEx(handle, value)[0]
                        if value:
                            path = str(Path(path) / "Wireshark.exe")
                        found.append(path)
                except OSError:
                    pass
    return found


def find_wireshark(saved=None):
    candidates = [saved, *registry_paths(), shutil.which("Wireshark.exe")]
    for name in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
        if os.environ.get(name):
            candidates.append(str(Path(os.environ[name]) / "Wireshark/Wireshark.exe"))
    for candidate in candidates:
        if candidate:
            path = Path(os.path.expandvars(str(candidate).strip().strip('"')))
            if path.is_absolute() and path.is_file():
                return str(path)
    return None


def external_environment():
    env = os.environ.copy()
    # Qt's plugin overrides belong to Capture Desk, not the external Qt app.
    for name in list(env):
        if name.upper().startswith(("QT_", "QML_", "QML2_")):
            env.pop(name)
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        root = os.path.normcase(os.path.abspath(bundle))
        def bundled(entry):
            entry = os.path.normcase(os.path.abspath(entry.strip('"')))
            try:
                return os.path.commonpath([root, entry]) == root
            except ValueError:
                return False
        env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep)
                                      if p and not bundled(p))
    return env


def spawn(executable, capture):
    executable, capture = Path(executable).resolve(), Path(capture).resolve()
    if not executable.is_file():
        raise FileNotFoundError("Wireshark 程序不存在，请重新设置程序路径")
    if not capture.is_file():
        raise FileNotFoundError("抓包文件不存在，可能已移动或删除")
    args = [str(executable), "-r", str(capture)]
    with _launch_lock:
        kernel = None
        previous = None
        if sys.platform == "win32" and getattr(sys, "frozen", False):
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetDllDirectoryW.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]
            kernel.GetDllDirectoryW.restype = ctypes.c_uint32
            kernel.SetDllDirectoryW.argtypes = [ctypes.c_wchar_p]
            kernel.SetDllDirectoryW.restype = ctypes.c_int
            size = kernel.GetDllDirectoryW(0, None)
            buffer = ctypes.create_unicode_buffer(size + 1)
            kernel.GetDllDirectoryW(len(buffer), buffer)
            previous = buffer.value or None
            if not kernel.SetDllDirectoryW(None):
                raise ctypes.WinError(ctypes.get_last_error())
        try:
            return subprocess.Popen(args, cwd=str(executable.parent), env=external_environment(),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        finally:
            if kernel is not None:
                kernel.SetDllDirectoryW(previous)


def open_capture(executable, capture):
    process = spawn(executable, capture)
    try:
        code = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return "已启动 Wireshark，并发送打开文件请求"
    if code:
        raise RuntimeError(f"Wireshark 启动后立即退出（退出码 0x{code & 0xffffffff:08X}）。"
                           "请通过“设置 Wireshark”确认路径，并检查该程序能否单独打开此文件。")
    return "已发送打开文件请求（Wireshark 进程已正常退出，请检查已有窗口）"
