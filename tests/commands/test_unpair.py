import pytest
from unittest.mock import MagicMock
from keycard.commands.unpair import unpair
from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError
from keycard import constants


def test_unpair_success():
    transport = MagicMock()
    secure_session = MagicMock()
    secure_session.authenticated = True
    secure_session.wrap_apdu.return_value = (0x80, 0x3E, 0x01, 0x00, b"\xDE\xAD")

    transport.send_apdu.return_value = APDUResponse(b"", 0x9000)

    unpair(transport, secure_session, 1)

    secure_session.wrap_apdu.assert_called_once_with(
        constants.CLA_PROPRIETARY,
        constants.INS_UNPAIR,
        1,
        0x00,
        b""
    )

    transport.send_apdu.assert_called_once_with(
        bytes([0x80, 0x3E, 0x01, 0x00]) + b"\xDE\xAD"
    )


def test_unpair_transport_missing():
    with pytest.raises(ValueError, match="Transport must be provided"):
        unpair(None, MagicMock(), 1)


def test_unpair_session_missing():
    with pytest.raises(ValueError, match="Secure session must be provided"):
        unpair(MagicMock(), None, 1)


def test_unpair_session_not_authenticated():
    session = MagicMock()
    session.authenticated = False

    with pytest.raises(ValueError, match="Secure session must be authenticated"):
        unpair(MagicMock(), session, 1)


def test_unpair_apdu_error():
    transport = MagicMock()
    secure_session = MagicMock()
    secure_session.authenticated = True
    secure_session.wrap_apdu.return_value = (0x80, 0x3E, 0x01, 0x00, b"")
    transport.send_apdu.return_value = APDUResponse(b"", 0x6A84)

    with pytest.raises(APDUError) as excinfo:
        unpair(transport, secure_session, 1)

    assert excinfo.value.sw == 0x6A84
