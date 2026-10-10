from unittest.mock import MagicMock, patch

import pytest

from keycard import constants
from keycard.commands.init import init
from keycard.exceptions import APDUError

PIN = b'123456'
PUK = b'123456789012'
PAIRING_SECRET = b'abcdefgh'
CARD_PUBLIC_KEY = b'\x04' + b'\x00' * 64


@pytest.mark.parametrize('version,helper', [
    ((3, 2), '_init_v1'),
    ((4, 0), '_init_v2'),
])
def test_init_uses_helper_for_version(card, version, helper):
    card.version = version
    pairing_secret = PAIRING_SECRET if version < (4, 0) else None
    with patch(f'keycard.commands.init.{helper}') as init_version:
        init(card, PIN, PUK, pairing_secret, pin_retries=4)

    expected = PIN + PUK + (pairing_secret or b'') + b'\x04\x05'
    init_version.assert_called_once_with(card, expected)


@pytest.fixture
def v1_crypto():
    with (
        patch('keycard.commands.init.urandom', return_value=bytes(16)),
        patch(
            'keycard.commands.init.aes_cbc_encrypt',
            side_effect=lambda key, iv, pt: b'\xAA' * len(pt)
        ),
        patch(
            'keycard.commands.init.generate_key_pair',
            return_value=(MagicMock(), b'\x01' * 65)
        ),
        patch(
            'keycard.commands.init.ecdh_shared_secret',
            return_value=b'\xBB' * 32
        ),
    ):
        yield


def v1_initialize(card, pairing_secret=PAIRING_SECRET, **limits):
    card.version = (3, 2)
    init(card, b'1234', b'5678', pairing_secret, **limits)


def test_v1_initialize_sends_encrypted_credentials(card, v1_crypto):
    card.card_public_key = CARD_PUBLIC_KEY

    v1_initialize(card)

    card.send_apdu.assert_called_once_with(
        ins=constants.INS_INIT,
        data=bytes.fromhex(
            '4101010101010101010101010101010101010101010101010101010'
            '1010101010101010101010101010101010101010101010101010101'
            '010101010101010101010100000000000000000000000000000000'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    )


def test_v1_initialize_appends_limits_and_alt_pin(card, v1_crypto):
    card.card_public_key = CARD_PUBLIC_KEY

    with patch('keycard.commands.init.aes_cbc_encrypt') as encrypt:
        encrypt.return_value = b''
        v1_initialize(card, pin_retries=5, puk_retries=10, alt_pin='654321')

    plaintext = encrypt.call_args.args[2]
    assert plaintext == b'1234' + b'5678' + PAIRING_SECRET + b'\x05\x0a654321'


@pytest.mark.parametrize('secret_length', [10, 240])
def test_v1_initialize_data_length(card, v1_crypto, secret_length):
    card.card_public_key = CARD_PUBLIC_KEY
    pairing_secret = b'x' * secret_length

    if 1 + 65 + 16 + 8 + secret_length > 255:
        with pytest.raises(ValueError, match='Data too long'):
            v1_initialize(card, pairing_secret)
    else:
        v1_initialize(card, pairing_secret)
        assert card.send_apdu.call_count == 1


def test_v1_initialize_requires_pairing_secret(card):
    with pytest.raises(ValueError, match='pairing secret'):
        v1_initialize(card, None)


def test_v1_initialize_apdu_error(card, v1_crypto):
    card.card_public_key = CARD_PUBLIC_KEY
    card.send_apdu.side_effect = APDUError(0x6A84)

    with pytest.raises(APDUError) as excinfo:
        v1_initialize(card)

    assert excinfo.value.sw == 0x6A84


def v2_initialize(card, pairing_secret=None, **limits):
    card.version = (4, 0)
    init(card, PIN, PUK, pairing_secret, **limits)


def test_v2_initialize_opens_channel_and_sends_init(card):
    card.is_secure_channel_open = False

    v2_initialize(card, pin_retries=5, puk_retries=10, alt_pin='654321')

    card.open_secure_channel.assert_called_once_with()
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_INIT,
        data=PIN + PUK + b'\x05\x0a654321')


def test_v2_initialize_uses_open_channel(card):
    card.is_secure_channel_open = True

    v2_initialize(card)

    card.open_secure_channel.assert_not_called()
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_INIT, data=PIN + PUK)


def test_v2_initialize_rejects_pairing_secret(card):
    with pytest.raises(ValueError, match='pairing secret'):
        v2_initialize(card, PAIRING_SECRET)

    card.open_secure_channel.assert_not_called()


@pytest.mark.parametrize('limits,message', [
    ({'pin_retries': 11}, 'pin_retries'),
    ({'pin_retries': 1}, 'pin_retries'),
    ({'puk_retries': 2}, 'puk_retries'),
    ({'puk_retries': 13}, 'puk_retries'),
    ({'alt_pin': '12345'}, 'alt_pin'),
])
def test_initialize_validates_parameters_before_sending(card, limits, message):
    card.is_secure_channel_open = False

    with pytest.raises(ValueError, match=message):
        v2_initialize(card, **limits)

    card.open_secure_channel.assert_not_called()
    card.send_secure_apdu.assert_not_called()
