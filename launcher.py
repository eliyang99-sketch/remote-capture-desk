"""Bootstrap that preserves diagnostics even in a windowed frozen executable."""
import os
import sys
import traceback
from pathlib import Path


def launch():
    try:
        from main import main
        return main()
    except Exception:
        if '--data-dir' in sys.argv:
            root = Path(sys.argv[sys.argv.index('--data-dir') + 1])
        else:
            root = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'RemoteCaptureDesk'
        root.mkdir(parents=True, exist_ok=True)
        report = root / 'startup-error.txt'
        report.write_text(traceback.format_exc(), encoding='utf-8')
        if sys.stderr:
            sys.stderr.write(traceback.format_exc())
        if '--smoke-test' not in sys.argv and sys.platform == 'win32':
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, f'程序启动失败。诊断已保存到：\n{report}', '远程抓包', 0x10)
        return 1


if __name__ == '__main__':
    raise SystemExit(launch())
