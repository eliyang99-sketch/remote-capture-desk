"""Crash diagnostics without exception messages, source text or local variables."""
from __future__ import annotations

import faulthandler
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys
import threading
import traceback
import time

logger = logging.getLogger("capturedesk.diagnostics")
logger.addHandler(logging.NullHandler())
logger.propagate = False
_fatal_stream = None
_qt_handler = None
_secret_provider = lambda: ()


def set_secret_provider(provider):
    global _secret_provider
    _secret_provider = provider


def record_exception(stage, exception):
    frames = traceback.extract_tb(exception.__traceback__)
    stack = "\n".join(f"  {Path(f.filename).name}:{f.lineno} in {f.name}" for f in frames)
    # Exception text may contain SSH credentials or a command: deliberately omit it.
    logger.error("stage=%s type=%s thread=%s\n%s", stage,
                 type(exception).__name__, threading.current_thread().name, stack)


def install(root):
    global _fatal_stream, _qt_handler
    directory = Path(root) / "diagnostics"
    directory.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(directory / "runtime.log", maxBytes=1024 * 1024,
                                 backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    _fatal_stream = (directory / "native-crash.log").open("a", encoding="utf-8")
    faulthandler.enable(file=_fatal_stream, all_threads=True)
    sys.excepthook = lambda kind, value, tb: record_exception("unhandled_python", value)
    threading.excepthook = lambda args: record_exception("unhandled_thread", args.exc_value)
    from PySide6.QtCore import qInstallMessageHandler, qVersion
    import PySide6, shiboken6
    def qt_message(kind, context, message):
        # Only keep fixed runtime diagnostic categories, not arbitrary widget text.
        category = next((key for key in ("ASSERT", "QThread", "QObject", "QTimer", "GIL", "thread")
                         if key in message), "other")
        logger.error("qt_message type=%s category=%s source=%s line=%s", kind, category,
                     Path(context.file or "").name, context.line)
        if str(kind).endswith("QtFatalMsg") or getattr(kind, 'value', -1) == 3:
            try:
                for secret in _secret_provider():
                    message = secret.redact(message)
            except Exception:
                message = "[fatal diagnostic text omitted: redaction unavailable]"
            logger.critical("qt_fatal_reason=%s", message[:2000])
            faulthandler.dump_traceback(file=_fatal_stream, all_threads=True)
    _qt_handler = qt_message
    qInstallMessageHandler(_qt_handler)
    from . import __version__
    logger.info("application_started version=%s python=%s pid=%s", __version__,
                sys.version.split()[0], __import__('os').getpid())
    logger.info("runtime qt=%s pyside=%s shiboken=%s frozen=%s", qVersion(), PySide6.__version__,
                shiboken6.__version__, bool(getattr(sys, 'frozen', False)))
    return directory


def watch_gui(app, directory):
    """Record one all-thread stack per stall, without terminating the application."""
    from PySide6.QtCore import QTimer
    heartbeat = [time.monotonic()]
    stopped = threading.Event()
    timer = QTimer(app)
    timer.setInterval(1000)
    timer.timeout.connect(lambda: heartbeat.__setitem__(0, time.monotonic()))
    timer.start()
    app.aboutToQuit.connect(stopped.set)

    def watch():
        reported = False
        while not stopped.wait(2):
            stalled = time.monotonic() - heartbeat[0] > 15
            if stalled and not reported:
                try:
                    with (Path(directory) / "gui-hang.log").open("a", encoding="utf-8") as stream:
                        stream.write("\nGUI heartbeat missing >15s at " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
                        stream.flush()
                        faulthandler.dump_traceback(file=stream, all_threads=True)
                    logger.error("gui_heartbeat_timeout")
                except OSError:
                    pass
            reported = stalled

    threading.Thread(target=watch, name="gui-watchdog", daemon=True).start()
    return timer
