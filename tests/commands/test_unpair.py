import os
import sys
import pytest

from ..mocks import MockTransport
from keycard.commands.unpair import unpair
from keycard.exceptions import APDUError

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')))


class DummySecureSession:
    def __init__(self, authenticated=True, wrap_result=None):
        self.authenticated = authenticated
        self._wrap_result = wrap_result or (0x80, 0x13, 0x01, 0x00, b"")

    def wrap_apdu(self, cla, ins, p1, p2, data):
        return self._wrap_result


def test_unpair_success():
    session = DummySecureSession(authenticated=True)
    transport = MockTransport(b'')

    unpair(transport, session, 1)
    assert True


@pytest.mark.parametrize("transport,secure_session,err_msg", [
    (None, object(), "Transport must be provided"),
    (object(), None, "Secure session must be provided"),
])
def test_unpair_missing_args(transport, secure_session, err_msg):
    with pytest.raises(ValueError, match=err_msg):
        unpair(transport, secure_session, 1)


def test_unpair_not_authenticated():
    session = DummySecureSession(authenticated=False)
    transport = MockTransport()
    with pytest.raises(
        ValueError,
        match="Secure session must be authenticated"
    ):
        unpair(transport, session, 1)


def test_unpair_apdu_error():
    session = DummySecureSession(authenticated=True)
    transport = MockTransport(status_word=0x6A80)
    with pytest.raises(APDUError) as excinfo:
        unpair(transport, session, 1)
    assert excinfo.value.sw == 0x6A80
