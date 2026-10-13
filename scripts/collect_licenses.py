"""Copy installed dependency notices alongside the dynamically linked distribution."""
import importlib.metadata
import shutil
import sys
from pathlib import Path

destination = Path(sys.argv[1]) / "第三方许可"
destination.mkdir(parents=True, exist_ok=True)
summary = ["Third-party software notices", "", "Qt for Python / PySide6: https://code.qt.io/pyside/pyside-setup.git/", "Qt source: https://code.qt.io/qt/", "Paramiko: https://github.com/paramiko/paramiko", "", "Installed build environment versions:"]
# Match import precedence when an isolated dependency directory overrides site-packages.
selected = {}
for distribution in importlib.metadata.distributions():
    selected.setdefault(distribution.metadata['Name'].lower().replace('_', '-'), distribution)
for distribution in sorted(selected.values(), key=lambda d: d.metadata['Name'].lower()):
    name = distribution.metadata['Name']
    summary.append(f"{name}=={distribution.version}")
    for relative in distribution.files or []:
        lower = str(relative).lower()
        if ('license' in lower or 'copying' in lower) and '.dist-info/' in lower:
            source = Path(distribution.locate_file(relative))
            if source.is_file():
                target = destination / name / Path(relative).name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
(destination / 'NOTICE.txt').write_text('\n'.join(summary), encoding='utf-8')
for name in ('LICENSE.txt', 'LICENSE'):
    source = Path(sys.base_prefix) / name
    if source.is_file():
        shutil.copyfile(source, destination / ('Python-' + name))
