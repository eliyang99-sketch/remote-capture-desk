"""Package the release and selected source files without deleting previous outputs."""
import hashlib
import shutil
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
release = root / 'dist/v1.0.0/RemoteCaptureDesk'
shutil.copyfile(root / 'TEST_REPORT.md', release / '测试报告.md')
shutil.copyfile(root / 'README.md', release / '使用说明.md')


def archive(path, entries):
    # Exclusive create: never replace a prior published archive.
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for source, name in entries:
            output.write(source, name)
    with zipfile.ZipFile(path) as output:
        assert output.testzip() is None
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return f'{digest.hexdigest()}  {path.name}'


binary_path = root / 'dist/RemoteCaptureDesk-1.0.0-windows-x64.zip'
checksums = [archive(binary_path, [(p, str(Path('RemoteCaptureDesk') / p.relative_to(release)))
                                  for p in release.rglob('*') if p.is_file()])]
files = [root / name for name in ['.gitignore', 'README.md', 'TEST_REPORT.md', 'main.py', 'launcher.py',
                                 'requirements.txt', 'requirements-dev.txt', 'requirements-lock.txt']]
for directory in ('capturedesk', 'scripts', 'tests'):
    files.extend(p for p in (root / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
source_path = root / 'dist/RemoteCaptureDesk-1.0.0-source.zip'
checksums.append(archive(source_path, [(p, str(Path('RemoteCaptureDesk-source') / p.relative_to(root))) for p in files]))
(root / 'dist/SHA256SUMS.txt').write_text('\n'.join(checksums) + '\n', encoding='utf-8')
for path in (binary_path, source_path):
    print(f'{path.name}: {path.stat().st_size / 1024 / 1024:.2f} MiB')
