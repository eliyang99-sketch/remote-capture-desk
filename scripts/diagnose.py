"""Read-only diagnostics for an explicitly supplied, already trusted SSH host."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capturedesk.models import Server, Secrets
from capturedesk.remote import Remote, HostKeys

server = Server(host=sys.argv[1])
keys = HostKeys(Path('.local-test/integration/known_hosts'), lambda *args: False)
remote = Remote(server, Secrets(password=os.environ.pop('CAPTURE_TEST_PASSWORD')), keys).connect()
try:
    commands = [
        "tcpdump --version; uname -a; id",
        "tcpdump -D; df -Pk /tmp",
    ]
    for command in commands:
        code, out, err = remote.run(command, check=False, timeout=12)
        print(command, '\nEXIT', code, '\n', out, '\n', err, flush=True)
finally:
    remote.close()
