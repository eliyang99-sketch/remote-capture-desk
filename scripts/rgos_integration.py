"""Explicit, bounded RGOS test. Credentials only from process environment."""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capturedesk.models import Server, Secrets, Task, CaptureOptions
from capturedesk.remote import HostKeys
from capturedesk.rgos import RgosRemote
from capturedesk.storage import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--takeover', action='store_true')
    args = parser.parse_args()
    root = Path('.local-test/rgos110')/datetime.now().strftime('%Y%m%d_%H%M%S')
    root = root.resolve()
    store = Store(root)
    secrets = Secrets(password=os.environ.pop('CAPTURE_TEST_PASSWORD'))
    keys = HostKeys(root/'known_hosts', lambda host, *a: host == args.host)
    server = Server(name='RGOS bounded test', host=args.host, username='admin', device_type='rgos',
                    interface='control-plane', remote_base='tmp:')
    remote = RgosRemote(server, secrets, keys)
    options = CaptureOptions(device=dict(minutes=1, packets=64, buffer_mb=2, filters={'v4_protocol':'icmp'},takeover=args.takeover))
    task = Task.create(server, options, root.name, str(root/'报文'))
    report = {'capture': args.capture}
    def persist(): store.save_task(task)
    try:
        remote.connect()
        info = remote.inspect()
        report['conflict'] = info['conflict']
        print('preflight conflict:', info['conflict'], flush=True)
        if not args.capture:
            if info['conflict']:
                try:
                    remote.plan(options,info)
                except ValueError:
                    report['blocked_existing_config'] = True
                    print('Existing capture configuration correctly blocks launch', flush=True)
                else:
                    raise AssertionError('Expected conflict to block capture')
            return
        remote.prepare_intent(task, info)
        persist()
        remote.configure(task, persist)
        remote.launch(task)
        time.sleep(1)
        print(remote.command('ping '+remote.receiver.address[0], timeout=15, check=False), flush=True)
        time.sleep(1)
        remote.stop(task)
        persist()
        report['directory'] = remote.command('dir '+task.device['file'], check=False)
        report['verify'] = remote.command('verify '+task.device['file'], check=False)
        print(report['directory'], flush=True)
        print(report['verify'], flush=True)
        task.local_file, task.sha256 = remote.download(task, lambda n: None, lambda: False)
        report['download_verified'] = True
        print('Downloaded and verified:', task.local_file, flush=True)
    except Exception as exc:
        report['error'] = secrets.redact(str(exc))
        print('Error:', report['error'], flush=True)
        raise
    finally:
        if task.pending_cleanup():
            try:
                remote.ensure_connected()
                remote.cleanup(task, persist)
                report['cleanup'] = task.device['cleanup']
            except Exception as exc:
                report['cleanup_error'] = secrets.redact(str(exc))
                print('Cleanup pending:', report['cleanup_error'], flush=True)
        remote.close()
        report['task'] = task.__dict__
        (root/'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print('Report:', root/'report.json', flush=True)


if __name__ == '__main__': main()
