import os
import sys

import pytest

from ..mocks import MockTransport

from keycard.commands.verify_pin import verify_pin
from keycard.exceptions import APDUError


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..')))


class DummySession:
    def wrap_apdu(self, cla, ins, p1, p2, data):
        if isinstance(data, str):
            data = data.encode()
        return cla, ins, p1, p2, data


def test_verify_pin_success():
    session = DummySession()
    transport = MockTransport()
    assert verify_pin(transport, session, '1234') is True


def test_verify_pin_wrong_pin_with_attempts_left():
    session = DummySession()
    transport = MockTransport(status_word=0x63C2)
    assert verify_pin(transport, session, '0000') is False


def test_verify_pin_pin_blocked():
    session = DummySession()
    transport = MockTransport(status_word=0x63C0)
    with pytest.raises(RuntimeError, match="PIN is blocked"):
        verify_pin(transport, session, '0000')


def test_verify_pin_apdu_error():
    session = DummySession()
    transport = MockTransport(status_word=0x6A80)
    with pytest.raises(APDUError):
        verify_pin(transport, session, '0000')


def test_verify_pin_no_session():
    transport = MockTransport()
    with pytest.raises(
        ValueError,
        match="Secure session must be established before verifying PIN."
    ):
        verify_pin(transport, None, '1234')
