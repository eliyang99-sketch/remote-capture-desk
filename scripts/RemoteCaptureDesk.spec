# Windows 10/11 x64 build; dependency versions are pinned in requirements-lock.txt.
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH).parent
data, binaries, hidden = collect_all('keyring')
a = Analysis(
    [str(root / 'launcher.py')], pathex=[str(root)],
    binaries=binaries, datas=data,
    hiddenimports=hidden + ['keyring.backends.Windows'],
    hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=['pytest'], noarchive=False,
)

# Do not ship unrelated ICU builds found on PATH (for example Poppler's ICU 78).
# They export versioned symbols and shadow the compatible Windows ICU library.
# API-set/UCRT shims from unrelated SDKs likewise belong to the target OS.
def use_binary(entry):
    name = Path(entry[0]).name.lower()
    return not (name in {'icuuc.dll', 'icuin.dll', 'ucrtbase.dll'}
                or (name.startswith('icudt') and name.endswith('.dll'))
                or name.startswith(('api-ms-win-', 'ext-ms-win-')))

a.binaries = [entry for entry in a.binaries if use_binary(entry)]
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='RemoteCaptureDesk',
          debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
          console=False, disable_windowed_traceback=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='RemoteCaptureDesk')
