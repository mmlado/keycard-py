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
    card = MagicMock()
    pairing_index = 1
    pairing_key = b"pairing_key"
    card.card_public_key = b"\x04" + b"\x01" * 64

    salt = b"A" * 32
    seed_iv = b"B" * 16
    response_data = salt + seed_iv
    card.send_apdu.return_value = response_data

    mock_verifying_key.from_string.return_value = MagicMock()
    mock_ecdh_instance = MagicMock()
    mock_ecdh.return_value = mock_ecdh_instance
    mock_ecdh_instance.generate_sharedsecret_bytes.return_value = (
        b"shared_secret"
    )
    mock_secure_session.open.return_value = "secure_session"

    result = open_secure_channel(
        card,
        pairing_index,
        pairing_key
    )

    card.send_apdu.assert_called_once()
    mock_verifying_key.from_string.assert_called_once_with(
        card.card_public_key, curve=SECP256k1
    )
    mock_ecdh.assert_called_once()
    mock_ecdh_instance.generate_sharedsecret_bytes.assert_called_once()
    mock_secure_session.open.assert_called_once_with(
        b"shared_secret", pairing_key, salt, seed_iv
    )
    assert result == "secure_session"


def test_open_secure_channel_raises_apdu_error():
    card = MagicMock()
    pairing_index = 1
    pairing_key = b"pairing_key"
    card.card_public_key = b"\x04" + b"\x01" * 64
    card.send_apdu.side_effect = APDUError(0x6A80)

    with pytest.raises(APDUError):
        open_secure_channel(
            card,
            pairing_index,
            pairing_key
        )
