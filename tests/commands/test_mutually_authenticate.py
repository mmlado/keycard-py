import os
import pytest

from unittest.mock import MagicMock
from keycard.commands.mutually_authenticate import mutually_authenticate
from keycard.exceptions import APDUError
from keycard.apdu import APDUResponse


def test_mutually_authenticate_success():
    transport = MagicMock()
    session = MagicMock()

    client_challenge = os.urandom(32)
    response_data = os.urandom(32)
    response = APDUResponse(response_data, 0x9000)

    session.wrap_apdu.return_value = (0x80, 0x11, 0x00, 0x00, client_challenge)
    transport.send_apdu.return_value = response
    session.unwrap_response.return_value = (response_data, 0x9000)

    mutually_authenticate(transport, session, client_challenge)

    session.wrap_apdu.assert_called_once_with(
        cla=0x80,
        ins=0x11,
        p1=0x00,
        p2=0x00,
        data=client_challenge
    )
    transport.send_apdu.assert_called_once_with(
        bytes([
            0x80,
            0x11,
            0x00,
            0x00,
            len(client_challenge)
        ]) + client_challenge
    )
    session.unwrap_response.assert_called_once_with(response)


def test_mutually_authenticate_invalid_status_word():
    transport = MagicMock()
    session = MagicMock()

    client_challenge = os.urandom(32)
    response = APDUResponse(b'', 0x6F00)

    session.wrap_apdu.return_value = (0x80, 0x50, 0x00, 0x00, client_challenge)
    transport.send_apdu.return_value = response

    with pytest.raises(APDUError, match='APDU failed with SW=6F00'):
        mutually_authenticate(transport, session)


def test_mutually_authenticate_invalid_response_length():
    transport = MagicMock()
    session = MagicMock()

    client_challenge = os.urandom(32)
    response_data = os.urandom(16)  # Invalid length
    response = APDUResponse(response_data, 0x9000)

    session.wrap_apdu.return_value = (0x80, 0x50, 0x00, 0x00, client_challenge)
    transport.send_apdu.return_value = response
    session.unwrap_response.return_value = (response_data, 0x9000)

    with pytest.raises(
        ValueError,
        match='Response to MUTUALLY AUTHENTICATE is not 32 bytes'
    ):
        mutually_authenticate(transport, session)
