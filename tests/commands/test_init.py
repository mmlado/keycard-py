from ecdsa import SigningKey, VerifyingKey, ECDH, SECP256k1
import pytest
from unittest.mock import MagicMock, patch
from keycard.commands.init import init
from keycard.exceptions import NotSelectedError, APDUError
from keycard.apdu import APDUResponse
from keycard import constants


PIN = b"1234"
PUK = b"5678"
PAIRING_SECRET = b"abcdefgh"
CARD_PUBLIC_KEY = b"\x04" + b"\x00" * 64  # Valid uncompressed pubkey format


@pytest.fixture
def ecc_patches():
    with patch("keycard.commands.init.urandom", return_value=b"\x00" * 16), \
         patch("keycard.commands.init.aes_cbc_encrypt", side_effect=lambda k, iv, pt: b"\xAA" * len(pt)), \
         patch("keycard.commands.init.SigningKey.generate") as mock_gen, \
         patch("keycard.commands.init.VerifyingKey.from_string") as mock_parse, \
         patch("keycard.commands.init.ECDH") as mock_ecdh:

        fake_privkey = MagicMock()
        fake_privkey.verifying_key.to_string.return_value = b"\x01" * 65
        mock_gen.return_value = fake_privkey

        mock_parse.return_value = "parsed-pubkey"

        ecdh_instance = MagicMock()
        ecdh_instance.generate_sharedsecret_bytes.return_value = b"\xBB" * 32
        mock_ecdh.return_value = ecdh_instance

        yield


def test_init_success(ecc_patches):
    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(b"", constants.SW_SUCCESS)

    init(transport, CARD_PUBLIC_KEY, PIN, PUK, PAIRING_SECRET)

    assert transport.send_apdu.call_count == 1
    apdu = transport.send_apdu.call_args[0][0]
    assert apdu[0] == constants.CLA_PROPRIETARY
    assert apdu[1] == constants.INS_INIT
    assert apdu[2:4] == b"\x00\x00"
    assert apdu[4] == len(apdu[5:])


def test_init_no_card_key(ecc_patches):
    transport = MagicMock()
    with pytest.raises(NotSelectedError, match="Card not selected"):
        init(transport, None, PIN, PUK, PAIRING_SECRET)


@pytest.mark.parametrize("secret_length", [10, 240])
def test_init_data_length(ecc_patches, secret_length):
    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(b"", constants.SW_SUCCESS)

    pairing_secret = b"x" * secret_length
    plaintext = PIN + PUK + pairing_secret
    total_data_len = 1 + 65 + 16 + len(plaintext)  # len + pubkey + iv + ciphertext

    if total_data_len > 255:
        with pytest.raises(ValueError, match="Data too long"):
            init(transport, CARD_PUBLIC_KEY, PIN, PUK, pairing_secret)
    else:
        init(transport, CARD_PUBLIC_KEY, PIN, PUK, pairing_secret)
        assert transport.send_apdu.call_count == 1


def test_init_apdu_error(ecc_patches):
    transport = MagicMock()
    transport.send_apdu.return_value = APDUResponse(b"", 0x6A84)

    with pytest.raises(APDUError) as excinfo:
        init(transport, CARD_PUBLIC_KEY, PIN, PUK, PAIRING_SECRET)

    assert excinfo.value.sw == 0x6A84
