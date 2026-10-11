import pytest
from unittest.mock import MagicMock, patch

from keycard import constants
from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError, InvalidStateError
from keycard.parsing.exported_key import ExportedKey
from keycard.keycard import KeyCard
from keycard.pairing import Pairing
from keycard.secure_channel import SecureChannelVersion
from keycard.transport import Transport


def test_keycard_init_with_transport():
    transport = MagicMock(spec=Transport)
    kc = KeyCard(transport)
    assert kc.transport == transport
    assert kc.card_public_key is None
    assert kc.session is None


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
        mock_init.assert_called_once_with(
            kc, b'pin', b'puk', b'secret',
            pin_retries=None, puk_retries=None, alt_pin=None)


def test_ident_calls_command():
    with patch('keycard.keycard.commands.ident', return_value='identity') as m:
        kc = KeyCard(MagicMock())
        result = kc.ident(b'challenge')
        m.assert_called_once()
        assert result == 'identity'


def test_open_secure_channel_stores_session():
    with patch(
        'keycard.keycard.commands.open_secure_channel',
        return_value='session'
    ) as mock_osc:
        kc = KeyCard(MagicMock())
        kc.open_secure_channel()

    mock_osc.assert_called_once_with(kc)
    assert kc.session == 'session'


def test_mutually_authenticate_calls_command():
    with patch('keycard.keycard.commands.mutually_authenticate') as mock_auth:
        kc = KeyCard(MagicMock())
        kc.secure_session = 'sess'
        kc.mutually_authenticate()
        mock_auth.assert_called_once()


def test_pair_stores_and_returns_pairing():
    with patch('keycard.keycard.commands.pair', return_value=(1, b'key')):
        kc = KeyCard(MagicMock())
        result = kc.pair(b'shared')

    assert result == Pairing(1, b'key')
    assert kc.pairing == result
    slot, key = result
    assert (slot, key) == (1, b'key')


def test_unpair_clears_own_pairing():
    kc = KeyCard(MagicMock())
    kc.pairing = Pairing(2, b'key')

    with patch('keycard.keycard.commands.unpair'):
        kc.unpair(1)
        assert kc.pairing == Pairing(2, b'key')
        kc.unpair(2)

    assert kc.pairing is None


def test_verify_pin_delegates_call_and_returns_result():
    with patch(
        'keycard.keycard.commands.verify_pin',
        return_value=True
    ) as mock_cmd:
        kc = KeyCard(MagicMock())
        kc.secure_session = 'sess'
        result = kc.verify_pin('1234')
        mock_cmd.assert_called_once_with(kc, b'1234')
        assert result is True
        assert kc.is_pin_verified


def test_verify_pin_rejected_leaves_pin_unverified():
    kc = KeyCard(MagicMock())

    with patch('keycard.keycard.commands.verify_pin', return_value=False):
        assert kc.verify_pin('000000') is False

    assert not kc.is_pin_verified


def test_verify_pin_rejected_clears_previous_verification():
    kc = KeyCard(MagicMock())

    with patch('keycard.keycard.commands.verify_pin', return_value=True):
        kc.verify_pin('123456')
    with patch('keycard.keycard.commands.verify_pin', return_value=False):
        kc.verify_pin('000000')

    assert not kc.is_pin_verified


@pytest.mark.parametrize('error', [
    RuntimeError('PIN is blocked'),
    APDUError(0x6A80),
])
def test_verify_pin_error_leaves_pin_unverified(error):
    kc = KeyCard(MagicMock())

    with patch('keycard.keycard.commands.verify_pin', return_value=True):
        kc.verify_pin('123456')
    with patch('keycard.keycard.commands.verify_pin', side_effect=error):
        with pytest.raises(type(error)):
            kc.verify_pin('123456')

    assert not kc.is_pin_verified


def test_unpair_delegates_call():
    transport = MagicMock()
    with patch('keycard.keycard.commands.unpair') as mock_unpair:
        kc = KeyCard(transport)
        kc.secure_session = 'sess'
        kc.unpair(2)
        mock_unpair.assert_called_once_with(kc,  2)


def _open_channel():
    channel = MagicMock()
    channel.is_open = True
    channel.wrap.return_value = b'wrapped apdu'
    channel.unwrap.return_value = b'plaintext'
    return channel


def test_send_secure_apdu_success():
    channel = _open_channel()
    mock_transport = MagicMock()
    response = APDUResponse(b'ciphertext', status_word=0x9000)
    mock_transport.send_apdu.return_value = response

    kc = KeyCard(mock_transport)
    kc.session = channel

    result = kc.send_secure_apdu(0xA4, 0x01, 0x02, b'data')

    channel.wrap.assert_called_once_with(0xA4, 0x01, 0x02, b'data')
    mock_transport.send_apdu.assert_called_once_with(b'wrapped apdu')
    channel.unwrap.assert_called_once_with(response)
    assert result == b'plaintext'


def test_send_secure_apdu_propagates_channel_error():
    channel = _open_channel()
    channel.unwrap.side_effect = APDUError(0x6A84)

    kc = KeyCard(MagicMock())
    kc.session = channel

    with pytest.raises(APDUError) as exc:
        kc.send_secure_apdu(0xA4, 0x00, 0x00, b'data')
    assert exc.value.sw == 0x6A84


def test_send_secure_apdu_requires_open_channel():
    kc = KeyCard(MagicMock())

    with pytest.raises(RuntimeError, match='not established'):
        kc.send_secure_apdu(0xA4, 0x00, 0x00, b'data')


def _card_with_version(major, minor):
    kc = KeyCard(MagicMock())
    kc._application_info = MagicMock(
        version_major=major, version_minor=minor)
    return kc


def test_secure_channel_version_before_select():
    assert KeyCard(MagicMock()).secure_channel_version is None


@pytest.mark.parametrize('version,expected', [
    ((3, 2), SecureChannelVersion.V1),
    ((4, 0), SecureChannelVersion.V2),
])
def test_secure_channel_version(version, expected):
    assert _card_with_version(*version).secure_channel_version == expected


@pytest.mark.parametrize('method,args,command', [
    ('pair', (b'secret',), 'pair'),
    ('unpair', (0,), 'unpair'),
    ('mutually_authenticate', (), 'mutually_authenticate'),
])
def test_v1_operations_raise_on_v2(method, args, command):
    kc = _card_with_version(4, 0)

    with patch(f'keycard.keycard.commands.{command}') as mock_command:
        with pytest.raises(InvalidStateError, match='Secure Channel V1'):
            getattr(kc, method)(*args)

    mock_command.assert_not_called()


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


def test_store_data_calls_command_with_default_slot():
    with patch('keycard.keycard.commands.store_data') as mock_store_data:
        kc = KeyCard(MagicMock())
        data = b'testdata'
        kc.store_data(data)
        mock_store_data.assert_called_once_with(
            kc, data, constants.StorageSlot.PUBLIC
        )


def test_store_data_calls_command_with_custom_slot():
    with patch('keycard.keycard.commands.store_data') as mock_store_data:
        kc = KeyCard(MagicMock())
        data = b'testdata'
        slot = MagicMock()
        kc.store_data(data, slot)
        mock_store_data.assert_called_once_with(kc, data, slot)


def test_store_data_raises_value_error_on_invalid_slot():
    with patch(
        'keycard.keycard.commands.store_data',
        side_effect=ValueError("Invalid slot")
    ):
        kc = KeyCard(MagicMock())
        with pytest.raises(ValueError, match="Invalid slot"):
            kc.store_data(b'testdata', slot="INVALID")


def test_store_data_raises_value_error_on_data_too_long():
    with patch(
        'keycard.keycard.commands.store_data',
        side_effect=ValueError("data is too long")
    ):
        kc = KeyCard(MagicMock())
        long_data = b'a' * 128
        with pytest.raises(ValueError, match="data is too long"):
            kc.store_data(long_data)


def test_get_data_calls_command_with_default_slot():
    with patch(
        'keycard.keycard.commands.get_data',
        return_value=b'data'
    ) as mock_get_data:
        kc = KeyCard(MagicMock())
        result = kc.get_data()
        mock_get_data.assert_called_once_with(kc, constants.StorageSlot.PUBLIC)
        assert result == b'data'


def test_get_data_calls_command_with_custom_slot():
    with patch(
        'keycard.keycard.commands.get_data',
        return_value=b'data'
    ) as mock_get_data:
        kc = KeyCard(MagicMock())
        slot = MagicMock()
        result = kc.get_data(slot)
        mock_get_data.assert_called_once_with(kc, slot)
        assert result == b'data'


def test_export_key_delegates_and_returns_result():
    mock_exported = MagicMock(spec=ExportedKey)
    with patch(
        'keycard.keycard.commands.export_key',
        return_value=mock_exported
    ) as mock_cmd:
        kc = KeyCard(MagicMock())
        result = kc.export_key(
            derivation_option=constants.DerivationOption.DERIVE,
            public_only=True,
            keypath="m/44'/60'/0'/0/0",
            make_current=True,
            source=constants.DerivationSource.PARENT
        )

        mock_cmd.assert_called_once_with(
            kc,
            derivation_option=constants.DerivationOption.DERIVE,
            public_only=True,
            keypath="m/44'/60'/0'/0/0",
            make_current=True,
            source=constants.DerivationSource.PARENT
        )
        assert result is mock_exported


def test_export_current_key_delegates_and_returns_result():
    mock_exported = MagicMock(spec=ExportedKey)
    with patch(
        'keycard.keycard.commands.export_key',
        return_value=mock_exported
    ) as mock_cmd:
        kc = KeyCard(MagicMock())
        result = kc.export_current_key(public_only=False)

        mock_cmd.assert_called_once_with(
            kc,
            derivation_option=constants.DerivationOption.CURRENT,
            public_only=False,
            keypath=None,
            make_current=False,
            source=constants.DerivationSource.MASTER
        )
        assert result is mock_exported


def test_sign_current_key():
    with patch("keycard.keycard.commands.sign") as mock_sign:
        card = KeyCard(MagicMock())
        digest = b"\xAA" * 32
        mock_sign.return_value = "signed"

        result = card.sign(digest)

        mock_sign.assert_called_once_with(
            card,
            digest,
            constants.DerivationOption.CURRENT,
            constants.SigningAlgorithm.ECDSA_SECP256K1,
            tweak=None
        )
        assert result == "signed"


def test_sign_schnorr_with_tweak():
    with patch("keycard.keycard.commands.sign") as mock_sign:
        card = KeyCard(MagicMock())
        digest = b"\xAA" * 32
        tweak = b"\x01" * 32

        card.sign(digest, constants.SigningAlgorithm.SCHNORR_BIP340, tweak)

        mock_sign.assert_called_once_with(
            card,
            digest,
            constants.DerivationOption.CURRENT,
            constants.SigningAlgorithm.SCHNORR_BIP340,
            tweak=tweak
        )


def test_sign_with_path():
    with patch("keycard.keycard.commands.sign") as mock_sign:
        card = KeyCard(MagicMock())
        digest = b"\xBB" * 32
        path = [0x8000002C, 0x8000003C, 0, 0, 0]  # m/44'/60'/0'/0/0
        mock_sign.return_value = "sig"

        result = card.sign_with_path(digest, path)

        mock_sign.assert_called_once_with(
            card,
            digest,
            constants.DerivationOption.DERIVE,
            constants.SigningAlgorithm.ECDSA_SECP256K1,
            derivation_path=path,
            tweak=None
        )
        assert result == "sig"


def test_sign_with_path_make_current():
    with patch("keycard.keycard.commands.sign") as mock_sign:
        card = KeyCard(MagicMock())
        digest = b"\xCC" * 32
        path = [0x8000002C, 0x8000003C, 0, 0, 0]
        mock_sign.return_value = "sig"

        result = card.sign_with_path(digest, path, make_current=True)

        mock_sign.assert_called_once_with(
            card,
            digest,
            constants.DerivationOption.DERIVE_AND_MAKE_CURRENT,
            constants.SigningAlgorithm.ECDSA_SECP256K1,
            derivation_path=path,
            tweak=None
        )
        assert result == "sig"


def test_sign_pinless():
    with patch("keycard.keycard.commands.sign") as mock_sign:
        card = KeyCard(MagicMock())
        digest = b"\xDD" * 32
        mock_sign.return_value = "sig"

        result = card.sign_pinless(digest)

        mock_sign.assert_called_once_with(
            card,
            digest,
            constants.DerivationOption.PINLESS
        )
        assert result == "sig"


def test_export_lee():
    with patch("keycard.keycard.commands.export_lee") as mock_export_lee:
        card = KeyCard(MagicMock())
        mock_export_lee.return_value = "keys"

        result = card.export_lee("m/44'/60'")

        mock_export_lee.assert_called_once_with(card, "m/44'/60'")
        assert result == "keys"


def test_load_key_bip39_seed():
    with patch("keycard.keycard.commands.load_key") as mock_load_key:
        card = KeyCard(MagicMock())
        seed = b"\xAB" * 64
        mock_load_key.return_value = b"uid"

        result = card.load_key(
            key_type=constants.LoadKeyType.BIP39_SEED,
            bip39_seed=seed
        )

        mock_load_key.assert_called_once_with(
            card,
            key_type=constants.LoadKeyType.BIP39_SEED,
            public_key=None,
            private_key=None,
            chain_code=None,
            bip39_seed=seed
        )
        assert result == b"uid"


def test_load_key_ecc_pair():
    with patch("keycard.keycard.commands.load_key") as mock_load_key:
        card = KeyCard(MagicMock())
        pub = b"\x04" + b"\x01" * 64
        priv = b"\x02" * 32
        mock_load_key.return_value = b"uid"

        result = card.load_key(
            key_type=constants.LoadKeyType.ECC,
            public_key=pub,
            private_key=priv
        )

        mock_load_key.assert_called_once_with(
            card,
            key_type=constants.LoadKeyType.ECC,
            public_key=pub,
            private_key=priv,
            chain_code=None,
            bip39_seed=None
        )
        assert result == b"uid"


def test_load_key_extended():
    with patch("keycard.keycard.commands.load_key") as mock_load_key:
        card = KeyCard(MagicMock())
        pub = b"\x04" + b"\x01" * 64
        priv = b"\x02" * 32
        chain = b"\x00" * 32
        mock_load_key.return_value = b"uid"

        result = card.load_key(
            key_type=constants.LoadKeyType.EXTENDED_ECC,
            public_key=pub,
            private_key=priv,
            chain_code=chain
        )

        mock_load_key.assert_called_once_with(
            card,
            key_type=constants.LoadKeyType.EXTENDED_ECC,
            public_key=pub,
            private_key=priv,
            chain_code=chain,
            bip39_seed=None
        )
        assert result == b"uid"


def test_keycard_set_pinless_path():
    with patch("keycard.keycard.commands.set_pinless_path") as mock_cmd:
        card = KeyCard(MagicMock())
        card.set_pinless_path("m/44'/60'/0'/0/0")

        mock_cmd.assert_called_once_with(card, "m/44'/60'/0'/0/0")


def test_keycard_generate_mnemonic():
    with patch("keycard.keycard.commands.generate_mnemonic") as mock_cmd:
        card = KeyCard(None)
        mock_cmd.return_value = [0, 2047, 1337, 42]

        result = card.generate_mnemonic(checksum_size=6)

        mock_cmd.assert_called_once_with(card, 6)
        assert result == [0, 2047, 1337, 42]


def test_keycard_derive_key():
    with patch("keycard.keycard.commands.derive_key") as mock_cmd:
        card = KeyCard(MagicMock())
        card.derive_key("m/44'/60'/0'/0/0")

        mock_cmd.assert_called_once_with(card, "m/44'/60'/0'/0/0")
