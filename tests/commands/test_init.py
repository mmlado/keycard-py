import pytest
from unittest.mock import MagicMock, patch
from keycard.commands.init import init
from keycard.exceptions import NotSelectedError
from keycard.apdu import APDUResponse
from keycard import constants

PIN = b"1234"
PUK = b"5678"
PAIRING_SECRET = b"abcdefgh"
CARD_PUBLIC_KEY = b"\\x04" + b"\\x00" * 64


@pytest.fixture
def crypto_patches():
    def mock_encrypt(key, iv, pt):
        return b"\\xAA" * len(pt)

    with patch("keycard.commands.init.urandom", return_value=b"00" * 16), \
         patch("keycard.commands.init.aes_cbc_encrypt", side_effect=mock_encrypt), \
         patch("keycard.commands.init.derive_shared_secret", return_value=b"BB" * 32), \
         patch("keycard.commands.init.parse_uncompressed_public_key", return_value="parsed_pubkey"), \
         patch("keycard.commands.init.export_uncompressed_public_key", return_value=b"01" * 65), \
         patch("keycard.commands.init.generate_ephemeral_keypair", return_value="ephemeral_key"):
        yield


def test_init_success(crypto_patches):
    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(b"", 0x9000)

    init(transport, CARD_PUBLIC_KEY, PIN, PUK, PAIRING_SECRET)

    assert transport.send_apdu.call_count == 1
    apdu = transport.send_apdu.call_args[0][0]
    assert apdu[0] == constants.CLA_PROPRIETARY
    assert apdu[1] == constants.INS_INIT
    assert apdu[2:4] == b"\x00\x00"
    assert apdu[4] == len(apdu[5:])


def test_init_without_card_key(crypto_patches):
    transport = MagicMock()
    with pytest.raises(NotSelectedError, match="Card not selected"):
        init(transport, None, PIN, PUK, PAIRING_SECRET)


@pytest.mark.parametrize("secret_length", [10, 240])
def test_init_varied_secret_lengths(crypto_patches, secret_length):
    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(b"", 0x9000)
    secret = b"x" * secret_length
    plaintext = PIN + PUK + secret
    total_data_len = 1 + 65 + 16 + len(plaintext)  # len prefix + pubkey + iv + ciphertext

    if total_data_len > 255:
        with pytest.raises(ValueError, match="Data too long for single APDU"):
            init(transport, CARD_PUBLIC_KEY, PIN, PUK, secret)
    else:
        init(transport, CARD_PUBLIC_KEY, PIN, PUK, secret)
        assert transport.send_apdu.call_count == 1
