from pathlib import Path
import pytest
from capturedesk.storage import Store

@pytest.mark.parametrize('permanent', [False, True])
def test_replace_permission_retry_preserves_previous_file(tmp_path, monkeypatch, permanent):
    store = Store(tmp_path)
    store.set_setting('value', 'old')
    original = Path.replace
    attempts = []
    def replace(path, target):
        attempts.append(1)
        if permanent or len(attempts) < 3:
            raise PermissionError('file held')
        return original(path, target)
    monkeypatch.setattr(Path, 'replace', replace)
    if permanent:
        with pytest.raises(PermissionError):
            store.set_setting('value', 'new')
        assert len(attempts) == 4
        assert Store(tmp_path).setting('value') == 'old'
    else:
        store.set_setting('value', 'new')
        assert len(attempts) == 3
        assert Store(tmp_path).setting('value') == 'new'
