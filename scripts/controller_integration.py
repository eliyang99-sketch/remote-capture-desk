"""Exercise the real concurrent scheduler against one authorized SSH server."""
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capturedesk.controller import Controller
from capturedesk.models import Server, Secrets, CaptureOptions, Task
from capturedesk.remote import HostKeys
from capturedesk.storage import Store
from scripts.integration import validate_pcap


def main():
    output = Path('.local-test/controller-integration').resolve()
    store = Store(output)
    secrets = Secrets(password=os.environ.pop('CAPTURE_TEST_PASSWORD'))
    host = sys.argv[1]
    keys = HostKeys(Path('.local-test/integration/known_hosts'), lambda *args: False)
    server_a = Server(name='并行任务 A', host=host, interface='lo')
    server_b = Server(name='并行任务 B', host=host, interface='lo')
    server_fail = Server(name='失败隔离测试', host=host, port=1, interface='lo')
    store.save_servers([server_a, server_b, server_fail])
    snapshots = []
    controller = Controller(store, keys, lambda event: snapshots.append(event))
    options = CaptureOptions(duration=8, size_mib=2, mode='bpf', expression='icmp and host 127.0.0.1')
    tasks = [Task.create(server, options, 'parallel', str(output / server.id)) for server in [server_a, server_b, server_fail]]
    try:
        for task in tasks:
            controller.submit(task, secrets)
        deadline = time.monotonic() + 45
        stopped = False
        while controller.active_ids() and time.monotonic() < deadline:
            running = {event['id'] for event in snapshots if event['state'] == '抓包中'}
            if tasks[0].id in running and tasks[1].id in running and not stopped:
                controller.stop(tasks[0].id)
                controller.stop(tasks[0].id)
                stopped = True
            time.sleep(0.1)
        assert not controller.active_ids(), 'tasks did not finish'
        assert tasks[0].state == tasks[1].state == '完成', [(t.state, t.error) for t in tasks]
        assert tasks[0].reason == 'manual' and tasks[1].reason == 'duration'
        assert tasks[2].state == '失败'
        for task in tasks[:2]:
            validate_pcap(task.local_file)
        # Recreate the controller and resume a persisted completed task. No relaunch.
        controller.close()
        controller = Controller(Store(output), keys, lambda event: snapshots.append(event))
        recovered = Task(**asdict(tasks[1]))
        controller.submit(recovered, secrets, resume=True)
        deadline = time.monotonic() + 20
        while controller.active_ids() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not controller.active_ids() and recovered.state == '完成'
        report = dict(parallel_two_tasks=True, stop_isolation=True, failure_isolation=True,
                      persistent_resume=True, auto_download=True, physical_servers=1,
                      tasks=[asdict(t) for t in tasks])
        (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({key: value for key, value in report.items() if key != 'tasks'}), flush=True)
    finally:
        controller.close()


if __name__ == '__main__':
    main()
