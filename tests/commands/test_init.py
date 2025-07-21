import pytest
from unittest.mock import MagicMock, patch
from keycard.commands.init import init
from keycard.exceptions import APDUError
from keycard import constants


PIN = b'1234'
PUK = b'5678'
PAIRING_SECRET = b'abcdefgh'
CARD_PUBLIC_KEY = b'\x04' + b'\x00' * 64  # Valid uncompressed pubkey format


@pytest.fixture
def ecc_patches():
    with (
        patch('keycard.commands.init.urandom', return_value=b'\x00' * 16),
        patch(
            'keycard.commands.init.aes_cbc_encrypt',
            side_effect=lambda k, iv, pt: b'\xAA' * len(pt)
        ),
        patch('keycard.commands.init.SigningKey.generate') as mock_gen,
        patch('keycard.commands.init.VerifyingKey.from_string') as mock_parse,
        patch('keycard.commands.init.ECDH') as mock_ecdh,
    ):
        fake_privkey = MagicMock()
        fake_privkey.verifying_key.to_string.return_value = b'\x01' * 65
        mock_gen.return_value = fake_privkey

        mock_parse.return_value = 'parsed-pubkey'

        ecdh_instance = MagicMock()
        ecdh_instance.generate_sharedsecret_bytes.return_value = b'\xBB' * 32
        mock_ecdh.return_value = ecdh_instance

        yield


def test_init_success(card, ecc_patches):
    card.send_apdu.return_value = b''

    init(card, PIN, PUK, PAIRING_SECRET)

    card.send_apdu.assert_called_once_with(
        ins=constants.INS_INIT,
        data=bytes.fromhex(
            '4101010101010101010101010101010101010101010101010101010'
            '1010101010101010101010101010101010101010101010101010101'
            '010101010101010101010100000000000000000000000000000000'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    )


@pytest.mark.parametrize('secret_length', [10, 240])
def test_init_data_length(card, ecc_patches, secret_length):
    card.send_apdu.return_value = b''

    pairing_secret = b'x' * secret_length
    plaintext = PIN + PUK + pairing_secret
    total_data_len = 1 + 65 + 16 + len(plaintext)

    if total_data_len > 255:
        with pytest.raises(ValueError, match='Data too long'):
            init(card, PIN, PUK, pairing_secret)
    else:
        init(card, PIN, PUK, pairing_secret)
        assert card.send_apdu.call_count == 1


def test_init_apdu_error(card, ecc_patches):
    card.send_apdu.side_effect = APDUError(0x6A84)

    with pytest.raises(APDUError) as excinfo:
        init(card, PIN, PUK, PAIRING_SECRET)

    assert excinfo.value.sw == 0x6A84
