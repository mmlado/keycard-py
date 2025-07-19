import pytest
from unittest.mock import MagicMock, patch

from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError
from keycard.keycard import KeyCard
from keycard.transport import Transport


def test_keycard_init_with_transport():
    transport = MagicMock(spec=Transport)
    kc = KeyCard(transport)
    assert kc.transport == transport
    assert kc.card_public_key is None
    assert kc.session is None


def test_keycard_init_without_transport_raises():
    with pytest.raises(ValueError, match='Transport not initialized'):
        KeyCard(None)


def test_select_sets_card_pubkey():
    mock_info = MagicMock()
    mock_info.ecc_public_key = b'pubkey'
    with patch('keycard.keycard.commands.select', return_value=mock_info):
        kc = KeyCard(MagicMock())
        result = kc.select()
        assert kc.card_public_key == b'pubkey'
        assert result == mock_info


def test_init_calls_command():
    transport = MagicMock()
    with patch('keycard.keycard.commands.init') as mock_init:
        kc = KeyCard(transport)
        kc.card_public_key = b'pub'
        kc.init(b'pin', b'puk', b'secret')
        mock_init.assert_called_once_with(kc, b'pin', b'puk', b'secret')


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
        assert kc.session == 'session'


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
        mock_cmd.assert_called_once_with(kc, '1234')
        assert result is True


def test_unpair_delegates_call():
    transport = MagicMock()
    with patch('keycard.keycard.commands.unpair') as mock_unpair:
        kc = KeyCard(transport)
        kc.secure_session = 'sess'
        kc.unpair(2)
        mock_unpair.assert_called_once_with(kc,  2)


def test_send_secure_apdu_success():
    mock_session = MagicMock()
    mock_session.wrap_apdu.return_value = b'encrypted'
    mock_session.unwrap_response.return_value = (b'plaintext', 0x9000)
    mock_transport = MagicMock()
    mock_response = MagicMock()
    mock_response.status_word = 0x9000
    mock_response.data = b'ciphertext'
    mock_transport.send_apdu.return_value = mock_response

    kc = KeyCard(mock_transport)
    kc.session = mock_session

    result = kc.send_secure_apdu(0xA4, 0x01, 0x02, b'data')

    mock_session.wrap_apdu.assert_called_once_with(
        cla=kc.transport.send_apdu.call_args[0][0][0],
        ins=0xA4,
        p1=0x01,
        p2=0x02,
        data=b'data'
    )
    mock_transport.send_apdu.assert_called_once()
    mock_session.unwrap_response.assert_called_once_with(mock_response)
    assert result == b'plaintext'


def test_send_secure_apdu_raises_on_transport_status_word():
    mock_session = MagicMock()
    mock_session.wrap_apdu.return_value = b'encrypted'
    mock_transport = MagicMock()
    mock_transport.send_apdu.return_value = APDUResponse(
        b'', status_word=0x6A82)

    kc = KeyCard(mock_transport)
    kc.session = mock_session

    with pytest.raises(APDUError) as exc:
        kc.send_secure_apdu(0xA4, 0x00, 0x00, b'data')
    assert exc.value.args[0] == 'APDU failed with SW=6A82'


def test_send_secure_apdu_raises_on_unwrap_status_word():
    mock_session = MagicMock()
    mock_session.wrap_apdu.return_value = b'encrypted'
    mock_session.unwrap_response.return_value = (b'plaintext', 0x6A84)
    mock_transport = MagicMock()
    mock_transport.send_apdu.return_value = APDUResponse(
        b'', status_word=0x9000)

    kc = KeyCard(mock_transport)
    kc.session = mock_session

    with pytest.raises(APDUError) as exc:
        kc.send_secure_apdu(0xA4, 0x00, 0x00, b'data')
    assert exc.value.args[0] == 'APDU failed with SW=6A84'


def test_send_apdu_success(monkeypatch):
    mock_transport = MagicMock()
    mock_response = MagicMock()
    mock_response.status_word = 0x9000
    mock_response.data = b'response'
    mock_transport.send_apdu.return_value = mock_response

    kc = KeyCard(mock_transport)

    result = kc.send_apdu(ins=0xA4, p1=0x01, p2=0x02, data=b'data')
    expected_apdu = bytes([0x80, 0xA4, 0x01, 0x02, 4]) + b'data'
    mock_transport.send_apdu.assert_called_once_with(expected_apdu)
    assert result == b'response'


def test_send_apdu_raises_on_non_success_status(monkeypatch):
    mock_transport = MagicMock()
    mock_transport.send_apdu.return_value = APDUResponse(b'', 0x6A82)

    kc = KeyCard(mock_transport)

    with pytest.raises(APDUError) as exc:
        kc.send_apdu(ins=0xA4, p1=0x00, p2=0x00, data=b'')
    assert exc.value.args[0] == 'APDU failed with SW=6A82'


def test_send_apdu_with_custom_cla(monkeypatch):
    mock_transport = MagicMock()
    mock_response = MagicMock()
    mock_response.status_word = 0x9000
    mock_response.data = b'abc'
    mock_transport.send_apdu.return_value = mock_response

    kc = KeyCard(mock_transport)

    result = kc.send_apdu(ins=0xA4, p1=0x01, p2=0x02, data=b'data', cla=0x90)
    expected_apdu = bytes([0x90, 0xA4, 0x01, 0x02, 4]) + b'data'
    mock_transport.send_apdu.assert_called_once_with(expected_apdu)
    assert result == b'abc'


def test_unblock_pin_calls_command_with_bytes():
    with patch('keycard.keycard.commands.unblock_pin') as mock_unblock:
        kc = KeyCard(MagicMock())
        puk = b'123456789012'
        new_pin = b'654321'
        kc.unblock_pin(puk, new_pin)
        mock_unblock.assert_called_once_with(kc, puk + new_pin)


def test_unblock_pin_calls_command_with_str():
    with patch('keycard.keycard.commands.unblock_pin') as mock_unblock:
        kc = KeyCard(MagicMock())
        puk = '123456789012'
        new_pin = '654321'
        kc.unblock_pin(puk, new_pin)
        mock_unblock.assert_called_once_with(
            kc,
            (puk + new_pin).encode('utf-8')
        )


def test_unblock_pin_calls_command_with_mixed_types():
    with patch('keycard.keycard.commands.unblock_pin') as mock_unblock:
        kc = KeyCard(MagicMock())
        puk = '123456789012'
        new_pin = b'654321'
        kc.unblock_pin(puk, new_pin)
        mock_unblock.assert_called_once_with(kc, puk.encode('utf-8') + new_pin)


def test_remove_key_calls_command():
    with patch('keycard.keycard.commands.remove_key') as mock_remove_key:
        kc = KeyCard(MagicMock())
        kc.remove_key()
        mock_remove_key.assert_called_once_with(kc)

