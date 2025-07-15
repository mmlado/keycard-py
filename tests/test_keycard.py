import pytest
from unittest.mock import MagicMock, patch

from keycard.keycard import KeyCard
from keycard.transport import Transport


def test_keycard_init_with_transport():
    transport = MagicMock(spec=Transport)
    kc = KeyCard(transport)
    assert kc.transport == transport
    assert kc._card_public_key is None
    assert kc.secure_session is None


def test_keycard_init_without_transport_raises():
    with pytest.raises(ValueError, match='Transport not initialized'):
        KeyCard(None)


def test_select_sets_card_pubkey():
    mock_info = MagicMock()
    mock_info.ecc_public_key = b'pubkey'
    with patch('keycard.keycard.commands.select', return_value=mock_info):
        kc = KeyCard(MagicMock())
        result = kc.select()
        assert kc._card_public_key == b'pubkey'
        assert result == mock_info


def test_init_calls_command():
    transport = MagicMock()
    with patch('keycard.keycard.commands.init') as mock_init:
        kc = KeyCard(transport)
        kc._card_public_key = b'pub'
        kc.init(b'pin', b'puk', b'secret')
        mock_init.assert_called_once_with(
            transport, b'pub', b'pin', b'puk', b'secret'
        )


def test_ident_calls_command():
    with patch('keycard.keycard.commands.ident', return_value='identity') as m:
        kc = KeyCard(MagicMock())
        result = kc.ident(b'challenge')
        m.assert_called_once()
        assert result == 'identity'


def test_open_secure_channel_sets_session():
    with patch('keycard.keycard.commands.open_secure_channel') as mock_cmd:
        mock_cmd.return_value = 'session'
        kc = KeyCard(MagicMock())
        kc._card_public_key = b'pub'
        kc.open_secure_channel(1, b'pairing_key')
        assert kc.secure_session == 'session'


def test_mutually_authenticate_calls_command():
    with patch('keycard.keycard.commands.mutually_authenticate') as mock_auth:
        kc = KeyCard(MagicMock())
        kc.secure_session = 'sess'
        kc.mutually_authenticate()
        mock_auth.assert_called_once()


def test_pair_returns_expected_tuple():
    with patch('keycard.keycard.commands.pair', return_value=(1, b'crypt')):
        kc = KeyCard(MagicMock())
        result = kc.pair(b'shared')
        assert result == (1, b'crypt')


def test_verify_pin_delegates_call_and_returns_result():
    with patch(
        'keycard.keycard.commands.verify_pin',
        return_value=True
    ) as mock_cmd:
        kc = KeyCard(MagicMock())
        kc.secure_session = 'sess'
        result = kc.verify_pin('1234')
        mock_cmd.assert_called_once_with(kc.transport, 'sess', '1234')
        assert result is True


def test_unpair_delegates_call():
    transport = MagicMock()
    with patch('keycard.keycard.commands.unpair') as mock_unpair:
        kc = KeyCard(transport)
        kc.secure_session = 'sess'
        kc.unpair(2)
        mock_unpair.assert_called_once_with(kc.transport, 'sess', 2)
