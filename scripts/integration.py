"""Authorized Linux integration tests. Password comes from the process environment only.

No remote cleanup, system configuration changes, or unrelated process signals.
Traffic is restricted to loopback ICMP and each capture has bounded duration/size.
"""
import argparse
import json
import os
import struct
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capturedesk.models import CaptureOptions, Secrets, Server, Task
from capturedesk.remote import HostKeys, Remote


def validate_pcap(path):
    with open(path, "rb") as stream:
        header = stream.read(24)
        assert len(header) == 24, "pcap header missing"
        endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}[header[:4]]
        assert struct.unpack(endian + "HH", header[4:8]) == (2, 4)
        packets = 0
        while record := stream.read(16):
            assert len(record) == 16, "truncated packet header"
            _, _, captured, original = struct.unpack(endian + "IIII", record)
            assert captured <= original and len(stream.read(captured)) == captured, "truncated packet"
            packets += 1
        return packets


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", default="root")
    parser.add_argument("--output", type=Path, default=Path(".local-test/integration"))
    parser.add_argument("--accept-test-host", action="store_true", help="TOFU for this explicitly authorized test host only")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    password = os.environ.pop("CAPTURE_TEST_PASSWORD")
    secrets = Secrets(password=password)
    server = Server(name="授权测试服务器", host=args.host, username=args.username, interface="lo")
    keys = HostKeys(args.output / "known_hosts", lambda host, algorithm, fingerprint: args.accept_test_host)
    report = {"host": args.host, "cases": [], "remote_files_retained": True}
    remote = Remote(server, secrets, keys).connect()
    try:
        info = remote.inspect()
        report["interfaces"] = info["interfaces"]
        remote.run("command -v ping")
        for case in ("duration_no_traffic", "manual", "packet_count", "size", "disconnect"):
            options = CaptureOptions(duration=5 if case in {"duration_no_traffic", "disconnect"} else 15,
                                     size_mib=1 if case == "size" else 4,
                                     packet_count=4 if case == "packet_count" else 0,
                                     mode="bpf", expression="icmp and host 127.0.0.1")
            task = Task.create(server, options, "integration", str(args.output / case))
            remote.prepare(task, info)
            remote.launch(task)
            time.sleep(1)
            if case in {"manual", "packet_count", "size"}:
                remote.run("ping -c 12 -i 0.03 -s 60000 127.0.0.1 >/dev/null" if case == "size" else "ping -c 3 -i 0.2 127.0.0.1 >/dev/null")
            if case == "manual":
                remote.stop(task)
                remote.stop(task)
            if case == "disconnect":
                remote.close()
                time.sleep(6)
                remote = Remote(server, secrets, keys).connect()
            deadline = time.monotonic() + 30
            status = None
            while time.monotonic() < deadline:
                status = remote.status(task)
                if status and status.get("phase") == "finished":
                    break
                time.sleep(0.5)
            assert status and status.get("phase") == "finished", f"{case}: no final status"
            expected = {"duration_no_traffic": "duration", "manual": "manual", "packet_count": "packet_count", "size": "size", "disconnect": "duration"}[case]
            assert status["reason"] == expected, f"{case}: {status}; {remote.log(task)}"
            assert status["code"] == "0", remote.log(task)
            path, sha = remote.download(task, lambda _: None, lambda: False)
            packets = validate_pcap(path)
            if case == "packet_count":
                assert packets == 4
            if case in {"manual", "size"}:
                assert packets > 0
            entry = {"case": case, "status": status, "packets": packets, "sha256": sha,
                     "local_file": str(Path(path).resolve()), "remote_dir": task.remote_dir, "passed": True}
            report["cases"].append(entry)
            (args.output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(json.dumps({"case": case, "passed": True, "packets": packets, "bytes": status["size"]}), flush=True)
    finally:
        remote.close()


if __name__ == "__main__":
    main()
