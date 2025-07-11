import os
import sys

import pytest
from unittest.mock import MagicMock, patch

from keycard.commands.open_secure_channel import open_secure_channel
from keycard.exceptions import APDUError, NotSelectedError

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

# Dummy constants for mocking
DUMMY_PUBKEY = b"\x04" + b"\x01" * 64  # uncompressed pubkey (65 bytes)
DUMMY_PAIRING_KEY = b"pairingkey012345"
DUMMY_SALT = b"s" * 32
DUMMY_SEED_IV = b"i" * 16
DUMMY_SHARED_SECRET = b"sharedsecret"
DUMMY_PAIRING_INDEX = 1

class DummyAPDUResponse:
    def __init__(self, status_word=0x9000, data=None):
        self.status_word = status_word
        self.data = data or (DUMMY_SALT + DUMMY_SEED_IV)

@pytest.fixture
def mock_transport():
    transport = MagicMock()
    return transport

@patch("keycard.commands.open_secure_channel.constants")
@patch("keycard.commands.open_secure_channel.SigningKey")
@patch("keycard.commands.open_secure_channel.VerifyingKey")
@patch("keycard.commands.open_secure_channel.ECDH")
@patch("keycard.commands.open_secure_channel.SecureSession")
def test_open_secure_channel_success(
    mock_SecureSession, mock_ECDH, mock_VerifyingKey, mock_SigningKey, mock_constants, mock_transport
):
    # Setup constants
    mock_constants.CLA_PROPRIETARY = 0x80
    mock_constants.INS_OPEN_SECURE_CHANNEL = 0x10

    # Setup ephemeral key
    mock_ephemeral_key = MagicMock()
    mock_ephemeral_key.verifying_key.to_string.return_value = b"\x04" + b"\x02" * 64
    mock_SigningKey.generate.return_value = mock_ephemeral_key

    # Setup APDU response
    mock_transport.send_apdu.return_value = DummyAPDUResponse()

    # Setup VerifyingKey
    mock_verifying_key = MagicMock()
    mock_VerifyingKey.from_string.return_value = mock_verifying_key

    # Setup ECDH
    mock_ecdh = MagicMock()
    mock_ecdh.generate_sharedsecret_bytes.return_value = DUMMY_SHARED_SECRET
    mock_ECDH.return_value = mock_ecdh

    # Setup SecureSession.open
    mock_SecureSession.open.return_value = "session"

    result = open_secure_channel(
        mock_transport,
        DUMMY_PUBKEY,
        DUMMY_PAIRING_INDEX,
        DUMMY_PAIRING_KEY
    )

    assert result == "session"
    mock_transport.send_apdu.assert_called_once()
    mock_SecureSession.open.assert_called_once_with(
        DUMMY_SHARED_SECRET,
        DUMMY_PAIRING_KEY,
        DUMMY_SALT,
        DUMMY_SEED_IV,
    )

def test_open_secure_channel_no_card_public_key(mock_transport):
    with pytest.raises(NotSelectedError):
        open_secure_channel(
            mock_transport,
            None,
            DUMMY_PAIRING_INDEX,
            DUMMY_PAIRING_KEY
        )

@patch("keycard.commands.open_secure_channel.constants")
@patch("keycard.commands.open_secure_channel.SigningKey")
def test_open_secure_channel_apdu_error(mock_SigningKey, mock_constants, mock_transport):
    mock_constants.CLA_PROPRIETARY = 0x80
    mock_constants.INS_OPEN_SECURE_CHANNEL = 0x10

    # Setup ephemeral key
    mock_ephemeral_key = MagicMock()
    mock_ephemeral_key.verifying_key.to_string.return_value = b"\x04" + b"\x02" * 64
    mock_SigningKey.generate.return_value = mock_ephemeral_key

    # APDU returns error status word
    mock_transport.send_apdu.return_value = DummyAPDUResponse(status_word=0x6A80)

    with pytest.raises(APDUError):
        open_secure_channel(
            mock_transport,
            DUMMY_PUBKEY,
            DUMMY_PAIRING_INDEX,
            DUMMY_PAIRING_KEY
        )