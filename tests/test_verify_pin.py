import pytest

from keycard.keycard import KeyCard

from tests.mocks import MockTransport


def test_verify_pin_success(monkeypatch):
    class DummySession:
        def wrap_apdu(self, cla, ins, p1, p2, data):
            return cla, ins, p1, p2, data

    transport = MockTransport(b'')
    card = KeyCard(transport)
    card.secure_session = DummySession()

    assert card.verify_pin('123456') is True


def test_verify_pin_wrong_pin(monkeypatch):
    class DummySession:
        def wrap_apdu(self, cla, ins, p1, p2, data):
            return cla, ins, p1, p2, data

    transport = MockTransport(b'', 0x63C3)
    card = KeyCard(transport)
    card.secure_session = DummySession()

    assert card.verify_pin('wrongpin') is False


def test_verify_pin_blocked(monkeypatch):
    class DummySession:
        def wrap_apdu(self, cla, ins, p1, p2, data):
            return cla, ins, p1, p2, data

    transport = MockTransport(b'', 0x63C0)
    card = KeyCard(transport)
    card.secure_session = DummySession()

    with pytest.raises(RuntimeError) as exc_info:
        card.verify_pin('blocked')
    assert "PIN is blocked" in str(exc_info.value)


def test_verify_pin_unexpected_status(monkeypatch):
    class DummySession:
        def wrap_apdu(self, cla, ins, p1, p2, data):
            return cla, ins, p1, p2, data

    transport = MockTransport(b'', 0x6A82)
    card = KeyCard(transport)
    card.secure_session = DummySession()

    with pytest.raises(RuntimeError) as exc_info:
        card.verify_pin('123456')
    assert "Unexpected status word" in str(exc_info.value)


def test_verify_pin_no_secure_session():
    transport = MockTransport(b'')
    card = KeyCard(transport)
    card.secure_session = None

    with pytest.raises(ValueError) as exc_info:
        card.verify_pin('123456')
    assert "Secure session must be established" in str(exc_info.value)
