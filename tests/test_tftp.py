import socket
import struct
import time
import pytest
from capturedesk.tftp import Receiver, Upload


def sock():
    result = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    result.bind(('127.0.0.1',0));result.settimeout(2)
    return result


def test_upload_options_duplicates_and_final_ack(tmp_path):
    receiver = Receiver('127.0.0.1',0)
    upload = Upload('127.0.0.1','random.pcap',tmp_path/'中文.pcap')
    receiver.register(upload)
    client = sock()
    try:
        request=b'\0\2/random.pcap\0octet\0blksize\08\0tsize\011\0'
        # Avoid octal escapes in option values.
        request=b'\0\2/random.pcap\0octet\0'+b'blksize\0'+b'8\0tsize\0'+b'11\0'
        client.sendto(request,receiver.address)
        reply,peer=client.recvfrom(1024)
        assert reply[:2] == b'\0\6'
        first=b'\0\3\0\1abcdefgh'
        client.sendto(first,peer);assert client.recvfrom(1024)[0] == b'\0\4\0\1'
        client.sendto(first,peer);assert client.recvfrom(1024)[0] == b'\0\4\0\1'
        last=b'\0\3\0\2ijk'
        client.sendto(last,peer);assert client.recvfrom(1024)[0] == b'\0\4\0\2'
        assert upload.done.wait(2) and not upload.error
        assert upload.path.read_bytes()==b'abcdefghijk'
        # File has been closed and is safe to rename on Windows.
        upload.path.rename(tmp_path/'完成.pcap')
        client.sendto(last,peer);assert client.recvfrom(1024)[0] == b'\0\4\0\2'
    finally:client.close();receiver.close()


@pytest.mark.parametrize('packet',[b'\0\1safe\0octet\0',b'\0\2../safe\0octet\0',
                                    b'\0\2safe\0netascii\0',b'\0\2other\0octet\0'])
def test_reject_reads_paths_modes_and_unregistered(packet,tmp_path):
    receiver=Receiver('127.0.0.1',0);receiver.register(Upload('127.0.0.1','safe',tmp_path/'safe'))
    client=sock()
    try:
        client.sendto(packet,receiver.address);assert client.recvfrom(1024)[0][:2] == b'\0\5'
        assert not (tmp_path/'safe').exists()
    finally:client.close();receiver.close()


def test_source_and_size_limit(tmp_path):
    receiver=Receiver('127.0.0.1',0)
    denied=Upload('192.0.2.1','denied',tmp_path/'denied');receiver.register(denied)
    upload=Upload('127.0.0.1','allowed',tmp_path/'allowed',limit=2);receiver.register(upload)
    client=sock()
    try:
        client.sendto(b'\0\2denied\0octet\0',receiver.address);assert client.recvfrom(1024)[0][:2]==b'\0\5'
        client.sendto(b'\0\2allowed\0octet\0',receiver.address);_,peer=client.recvfrom(1024)
        client.sendto(b'\0\3\0\1abc',peer);assert client.recvfrom(1024)[0][:2]==b'\0\5'
        assert upload.done.wait(2) and upload.error
    finally:client.close();receiver.close()


def test_existing_file_is_not_overwritten(tmp_path):
    path=tmp_path/'original';path.write_bytes(b'user data')
    receiver=Receiver('127.0.0.1',0);upload=Upload('127.0.0.1','safe',path);receiver.register(upload)
    client=sock()
    try:
        client.sendto(b'\0\2safe\0octet\0',receiver.address)
        assert upload.done.wait(2) and upload.error
        assert path.read_bytes()==b'user data'
    finally:client.close();receiver.close()


def test_cancelled_transfer_retains_only_partial_file(tmp_path):
    receiver=Receiver('127.0.0.1',0)
    upload=Upload('127.0.0.1','safe',tmp_path/'capture.part');receiver.register(upload)
    client=sock()
    try:
        client.sendto(b'\0\2safe\0octet\0',receiver.address);client.recvfrom(1024)
        receiver.unregister(upload)
        assert upload.done.wait(2) and upload.error
        assert not list(tmp_path.glob('*.pcap'))
    finally:client.close();receiver.close()
