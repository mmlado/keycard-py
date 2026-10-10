import sys
import pytest
from unittest.mock import MagicMock, patch

from keycard import constants
from keycard.card_interface import CardInterface
from keycard.commands.open_secure_channel import open_secure_channel
from keycard.exceptions import APDUError


@pytest.fixture
def mock_crypto():
    open_secure_channel_module = sys.modules[
        'keycard.commands.open_secure_channel'
    ]
    ephemeral_key = MagicMock()
    with (
        patch.object(
            open_secure_channel_module,
            'SecureChannel'
        ) as mock_secure_channel,
        patch.object(
            open_secure_channel_module,
            'generate_key_pair',
            return_value=(ephemeral_key, b'\x04' + b'\x02' * 64)
        ) as mock_generate_key_pair,
        patch.object(
            open_secure_channel_module,
            'ecdh_shared_secret',
            return_value=b'shared_secret'
        ) as mock_ecdh_shared_secret,
    ):
        yield {
            'secure_channel': mock_secure_channel,
            'generate_key_pair': mock_generate_key_pair,
            'ecdh_shared_secret': mock_ecdh_shared_secret,
            'ephemeral_key': ephemeral_key,
        }


def test_open_secure_channel_success(mock_crypto):
    mock_secure_channel = mock_crypto['secure_channel']

    pairing_index = 1
    pairing_key = b'pairing_key'
    card = MagicMock(spec=CardInterface)
    card.card_public_key = b'\x04' + b'\x01' * 64

    salt = b'A' * 32
    seed_iv = b'B' * 16
    card.send_apdu.return_value = salt + seed_iv
    mock_secure_channel.open.return_value = 'secure_session'

    result = open_secure_channel(
        card,
        pairing_index,
        pairing_key
    )

    card.send_apdu.assert_called_once_with(
        ins=constants.INS_OPEN_SECURE_CHANNEL,
        p1=pairing_index,
        data=b'\x04' + b'\x02' * 64
    )
    mock_crypto['ecdh_shared_secret'].assert_called_once_with(
        mock_crypto['ephemeral_key'], card.card_public_key
    )
    mock_secure_channel.open.assert_called_once_with(
        b'shared_secret', pairing_key, salt, seed_iv
    )
    assert result == 'secure_session'


def test_open_secure_channel_raises_apdu_error(card, mock_crypto):
    pairing_index = 1
    pairing_key = b'pairing_key'
    card.card_public_key = b'\x04' + b'\x01' * 64
    card.send_apdu.side_effect = APDUError(0x6A80)

    with pytest.raises(APDUError):
        open_secure_channel(
            card,
            pairing_index,
            pairing_key
        )

    mock_crypto['ecdh_shared_secret'].assert_not_called()
