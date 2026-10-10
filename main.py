from __future__ import annotations

import argparse
import sys
from pathlib import Path

from PySide6.QtCore import QLockFile, QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from capturedesk.storage import Store
from capturedesk.ui import MainWindow, STYLE


def main():
    parser = argparse.ArgumentParser(description="远程抓包桌面工具")
    parser.add_argument("--data-dir", type=Path, help="指定本地配置目录")
    parser.add_argument("--smoke-test", action="store_true", help="启动界面后自动退出，不连接服务器")
    parser.add_argument("--screenshot", type=Path, help="保存应用窗口截图（无需服务器）")
    args = parser.parse_args()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("RemoteCaptureDesk")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    try:
        store = Store(args.data_dir)
        lock = QLockFile(str(store.root / "application.lock"))
        lock.setStaleLockTime(0)
        if not lock.tryLock(0):
            QMessageBox.information(None, "远程抓包", "此数据目录已有运行中的工具，请使用已有窗口。")
            return 1
        window = MainWindow(store)
    except Exception as exc:
        QMessageBox.critical(None, "启动失败", f"无法加载本地数据或依赖：{exc}\n原数据不会被覆盖。")
        return 1
    window.show()
    if args.screenshot:
        QTimer.singleShot(500, lambda: window.grab().save(str(args.screenshot)))
    if args.smoke_test:
        QTimer.singleShot(1200, window.close)
    result = app.exec()
    # Keep the single-instance lock until workers have released files/connections.
    window.controller.pool.shutdown(wait=True, cancel_futures=True)
    window.background_pool.shutdown(wait=True, cancel_futures=True)
    lock.unlock()
    return result


if __name__ == "__main__":
    sys.exit(main())
