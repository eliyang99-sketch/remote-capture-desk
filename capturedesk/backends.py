from .remote import Remote
from .rgos import RgosRemote


def create_remote(server, secrets, host_keys):
    return (RgosRemote if server.device_type == "rgos" else Remote)(server, secrets, host_keys)
