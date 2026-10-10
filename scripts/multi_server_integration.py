"""Bounded multi-host integration checks; credentials only from process environment."""
import argparse
import json
import os
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capturedesk.controller import Controller
from capturedesk.models import CaptureOptions, Secrets, Server, Task
from capturedesk.remote import HostKeys, Remote
from capturedesk.storage import Store
from scripts.integration import validate_pcap


def wait_for(predicate, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError('Timed out waiting for expected task state')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--hosts', nargs=2, required=True)
    parser.add_argument('--accept-test-host', action='store_true')
    args = parser.parse_args()
    assert args.hosts[0] != args.hosts[1], 'Two distinct hosts required'
    root = Path('.local-test/multi-server') / datetime.now().strftime('%Y%m%d_%H%M%S')
    root = root.resolve()
    store = Store(root)
    known = Path('.local-test/integration/known_hosts')
    if known.exists():
        shutil.copyfile(known, root / 'known_hosts')
    fingerprints = []

    def trust(host, algorithm, fingerprint):
        fingerprints.append(dict(host=host, algorithm=algorithm, fingerprint=fingerprint))
        return args.accept_test_host and host in args.hosts

    keys = HostKeys(root / 'known_hosts', trust)
    secrets = Secrets(password=os.environ.pop('CAPTURE_TEST_PASSWORD'))
    servers = [Server(name=f'多机测试 {host}', host=host, interface='lo') for host in args.hosts]
    store.save_servers(servers)
    report = dict(hosts=args.hosts, scenarios=[], fingerprints=fingerprints, remote_files_retained=True)
    controls = []
    controller = None

    def save():
        (root / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

    def connect(server):
        remote = Remote(server, secrets, keys).connect()
        try:
            info = remote.inspect()
            assert 'lo' in info['interfaces']
            _, version, _ = remote.run('tcpdump --version')
            remote.run('command -v ping')
            return remote, dict(host=server.host, interfaces=info['interfaces'], version=version)
        except Exception:
            remote.close()
            raise

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            connected = list(pool.map(connect, servers))
        controls = [entry[0] for entry in connected]
        report['environments'] = [entry[1] for entry in connected]
        save()
        print('Both SSH/tcpdump preflight checks passed', flush=True)
        for scenario in ('single_stop_isolation', 'batch_stop', 'disconnect_isolation_and_recovery'):
            controller = Controller(store, keys, lambda _: None)
            tasks = []
            for index, server in enumerate(servers):
                # Distinct request sizes ensure each pcap matches its own host's test stream.
                payload = 96 + index * 64
                expression = f'icmp and src host 127.0.0.1 and dst host 127.0.0.1 and icmp[0] = 8 and ip[2:2] = {payload + 28}'
                duration = 10 if scenario == 'disconnect_isolation_and_recovery' else (12 if index == 1 else 20)
                options = CaptureOptions(duration=duration, size_mib=2, mode='bpf', expression=expression)
                task = Task.create(server, options, scenario, str(root / scenario / server.host))
                tasks.append(task)
                controller.submit(task, secrets)
            wait_for(lambda: all(t.state == '抓包中' for t in tasks), 15)
            before = [remote.status(task) for remote, task in zip(controls, tasks)]
            assert all(s['phase'] == 'running' for s in before)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(remote.run, f'ping -c 3 -i 0.2 -s {96 + i * 64} 127.0.0.1 >/dev/null')
                           for i, remote in enumerate(controls)]
                for future in futures:
                    future.result()
            # Give the kernel capture ring time to deliver the final probe packet.
            time.sleep(1)
            if scenario == 'single_stop_isolation':
                controller.stop(tasks[0].id)
                controller.stop(tasks[0].id)
                wait_for(lambda: tasks[0].state == '完成', 10)
                assert controls[1].status(tasks[1])['phase'] == 'running'
            elif scenario == 'batch_stop':
                for task in tasks:
                    controller.stop(task.id)
            else:
                with controller.lock:
                    interrupted = controller.connections[tasks[0].id]
                interrupted.client.close()
                wait_for(lambda: tasks[0].id not in controller.active_ids(), 10)
                assert tasks[0].state == '状态未知', (tasks[0].state, tasks[0].error)
                assert controls[0].status(tasks[0])['phase'] == 'running'
                assert controls[1].status(tasks[1])['phase'] == 'running'
            wait_for(lambda: not controller.active_ids(), 35)
            if scenario == 'disconnect_isolation_and_recovery':
                assert tasks[1].state == '完成'
                controller.close()
                controller.pool.shutdown(wait=True)
                # Restore from disk in a new controller, as when reopening the app.
                recovered_store = Store(root)
                restored = next(t for t in recovered_store.tasks() if t.id == tasks[0].id)
                controller = Controller(recovered_store, keys, lambda _: None)
                controller.submit(restored, secrets, resume=True)
                wait_for(lambda: not controller.active_ids(), 20)
                tasks[0] = restored
            expected = ['manual', 'duration'] if scenario == 'single_stop_isolation' else (
                ['manual', 'manual'] if scenario == 'batch_stop' else ['duration', 'duration'])
            results = []
            for index, (remote, task) in enumerate(zip(controls, tasks)):
                assert task.state == '完成', (task.state, task.error)
                assert task.reason == expected[index], task.reason
                packets = validate_pcap(task.local_file)
                assert packets == 3, (task.server['host'], packets)
                final = remote.status(task)
                assert final['started'] == before[index]['started'] and final['pid'] == before[index]['pid']
                assert final['phase'] == 'finished' and final['code'] == '0'
                assert task.sha256 and task.progress == 100
                results.append(dict(host=task.server['host'], id=task.id, reason=task.reason, packets=packets,
                                    size=task.size, sha256=task.sha256, local_file=task.local_file,
                                    remote_dir=task.remote_dir, status=final))
            report['scenarios'].append(dict(name=scenario, passed=True, tasks=results))
            save()
            print(json.dumps(dict(scenario=scenario, passed=True, packets=[r['packets'] for r in results],
                                  sizes=[r['size'] for r in results])), flush=True)
            controller.close()
            controller.pool.shutdown(wait=True)
        report['passed'] = True
        save()
        print('Report: ' + str(root / 'report.json'), flush=True)
    except Exception as exc:
        report['passed'] = False
        report['error'] = secrets.redact(str(exc))
        save()
        raise
    finally:
        if controller:
            controller.close()
            controller.pool.shutdown(wait=True)
        for remote in controls:
            remote.close()


if __name__ == '__main__':
    main()
