from pathlib import Path
import subprocess
import sys
import pytest
from capturedesk import wireshark as ws


def test_stale_setting_falls_back_to_registry(tmp_path, monkeypatch):
    exe=tmp_path/'Wireshark.exe';exe.touch()
    monkeypatch.setattr(ws,'registry_paths',lambda:[str(exe)])
    assert ws.find_wireshark(str(tmp_path/'missing.exe'))==str(exe)


def test_external_environment_isolated(tmp_path, monkeypatch):
    root=tmp_path/'bundle';root.mkdir()
    monkeypatch.setattr(sys,'_MEIPASS',str(root),raising=False)
    monkeypatch.setenv('PATH',ws.os.pathsep.join([str(root),str(root/'PySide6'),str(tmp_path/'system')]))
    monkeypatch.setenv('QT_PLUGIN_PATH','private-qt')
    monkeypatch.setenv('QML2_IMPORT_PATH','private-qml')
    env=ws.external_environment()
    assert env['PATH']==str(tmp_path/'system')
    assert 'QT_PLUGIN_PATH' not in env and 'QML2_IMPORT_PATH' not in env
    assert ws.os.environ['QT_PLUGIN_PATH']=='private-qt'


def test_unicode_arguments_and_working_directory(tmp_path,monkeypatch):
    exe=tmp_path/'Wireshark.exe';exe.touch()
    capture=tmp_path/'中文 空格.pcap';capture.touch()
    calls=[]
    monkeypatch.setattr(ws.subprocess,'Popen',lambda *args,**kwargs:calls.append((args,kwargs)))
    ws.spawn(exe,capture)
    args,kw=calls[0]
    assert args[0]==[str(exe),'-r',str(capture)]
    assert kw['cwd']==str(tmp_path)
    assert 'shell' not in kw


def test_early_exit_error_and_running_result(monkeypatch):
    class Failed:
        def wait(self,timeout):return 0xc0000135
    monkeypatch.setattr(ws,'spawn',lambda *args:Failed())
    with pytest.raises(RuntimeError,match='C0000135'):ws.open_capture('exe','file')
    class Running:
        def wait(self,timeout):raise subprocess.TimeoutExpired('Wireshark',timeout)
    monkeypatch.setattr(ws,'spawn',lambda *args:Running())
    assert '已启动' in ws.open_capture('exe','file')


def test_missing_capture_rejected(tmp_path):
    exe=tmp_path/'Wireshark.exe';exe.touch()
    with pytest.raises(FileNotFoundError,match='抓包文件'):ws.spawn(exe,tmp_path/'missing.pcap')


def test_dll_directory_restored_on_spawn_failure(tmp_path,monkeypatch):
    if sys.platform!='win32':pytest.skip('Windows loader test')
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.SetDllDirectoryW.argtypes=[ctypes.c_wchar_p]
    kernel.GetDllDirectoryW.argtypes=[ctypes.c_uint32,ctypes.c_wchar_p]
    def current():
        buf=ctypes.create_unicode_buffer(32768)
        kernel.GetDllDirectoryW(len(buf),buf)
        return buf.value
    original=current()
    exe=tmp_path/'Wireshark.exe';exe.touch()
    capture=tmp_path/'capture.pcap';capture.touch()
    kernel.SetDllDirectoryW(str(tmp_path))
    monkeypatch.setattr(sys,'frozen',True,raising=False)
    def fail(*args,**kwargs):
        assert current()==''
        raise OSError('simulated startup failure')
    monkeypatch.setattr(ws.subprocess,'Popen',fail)
    try:
        with pytest.raises(OSError):ws.spawn(exe,capture)
        assert current()==str(tmp_path)
    finally:kernel.SetDllDirectoryW(original or None)
