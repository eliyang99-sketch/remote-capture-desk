from capturedesk.credentials import Credentials
from capturedesk.models import Secrets


class MemoryVault:
    def __init__(self):
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, value):
        self.values[service, username] = value

    def delete_password(self, service, username):
        del self.values[service, username]


def test_remember_and_forget_keep_secrets_out_of_session_config():
    credentials = Credentials()
    credentials.backend = MemoryVault()
    credentials.set('test-server', Secrets(password='secret'), True)
    credentials.session.clear()
    assert credentials.get('test-server').password == 'secret'
    credentials.set('test-server', Secrets(password='session-only'), False)
    assert credentials.get('test-server').password == 'session-only'
    assert not credentials.remembered('test-server')


def test_inaccessible_vault_allows_memory_only_and_exposes_warning():
    class DeniedVault(MemoryVault):
        def get_password(self, *args):
            raise OSError('access denied')
    credentials = Credentials()
    credentials.backend = DeniedVault()
    assert credentials.get('server').password == ''
    credentials.set('server', Secrets(password='session-only'), False)
    assert credentials.get('server').password == 'session-only'
    assert credentials.warning
