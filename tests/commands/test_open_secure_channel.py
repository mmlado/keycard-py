import pytest
from unittest.mock import MagicMock, patch
from ecdsa import SECP256k1

from keycard.apdu import APDUResponse
from keycard.commands.open_secure_channel import open_secure_channel
from keycard.exceptions import APDUError, NotSelectedError


@patch("keycard.commands.open_secure_channel.SecureSession")
@patch("keycard.commands.open_secure_channel.VerifyingKey")
@patch("keycard.commands.open_secure_channel.ECDH")
def test_open_secure_channel_success(
    mock_ecdh,
    mock_verifying_key,
    mock_secure_session
):
    transport = MagicMock()
    pairing_index = 1
    pairing_key = b"pairing_key"
    card_public_key = b"\x04" + b"\x01" * 64

    # Simulated card response: 32 bytes salt + 16 bytes IV
    salt = b"A" * 32
    seed_iv = b"B" * 16
    response_data = salt + seed_iv
    transport.send_apdu.return_value = APDUResponse(response_data, 0x9000)

    # Setup mocks
    mock_verifying_key.from_string.return_value = MagicMock()
    mock_ecdh_instance = MagicMock()
    mock_ecdh.return_value = mock_ecdh_instance
    mock_ecdh_instance.generate_sharedsecret_bytes.return_value = (
        b"shared_secret"
    )
    mock_secure_session.open.return_value = "secure_session"

    result = open_secure_channel(
        transport,
        card_public_key,
        pairing_index,
        pairing_key
    )

    transport.send_apdu.assert_called_once()
    mock_verifying_key.from_string.assert_called_once_with(
        card_public_key, curve=SECP256k1
    )
    mock_ecdh.assert_called_once()
    mock_ecdh_instance.generate_sharedsecret_bytes.assert_called_once()
    mock_secure_session.open.assert_called_once_with(
        b"shared_secret", pairing_key, salt, seed_iv
    )
    assert result == "secure_session"


def test_open_secure_channel_raises_not_selected_error():
    transport = MagicMock()
    pairing_index = 1
    pairing_key = b"pairing_key"
    card_public_key = None

    with pytest.raises(NotSelectedError):
        open_secure_channel(
            transport,
            card_public_key,
            pairing_index,
            pairing_key
        )


def test_open_secure_channel_raises_apdu_error():
    transport = MagicMock()
    pairing_index = 1
    pairing_key = b"pairing_key"
    card_public_key = b"\x04" + b"\x01" * 64

    transport.send_apdu.return_value = APDUResponse(b"", 0x6A80)

    with pytest.raises(APDUError):
        open_secure_channel(
            transport,
            card_public_key,
            pairing_index,
            pairing_key
        )
