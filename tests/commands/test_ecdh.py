import pytest

from keycard import constants
from keycard.commands import ecdh
from keycard.exceptions import InvalidResponseError, InvalidStateError
from keycard.parsing.keypath import KeyPath

PUBLIC_KEY = b'\x04' + b'\x11' * 64
PATH = "m/44'/1237'/0'/0/0"
SECRET = b'\x22' * 32


@pytest.fixture
def card(card):
    card.is_pin_verified = True
    return card


def test_ecdh(card):
    card.send_secure_apdu.return_value = SECRET

    assert ecdh(card, PUBLIC_KEY, PATH) == SECRET

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_ECDH,
        p1=0x01,
        data=PUBLIC_KEY + KeyPath(PATH).data
    )


@pytest.mark.parametrize('public_key', [
    PUBLIC_KEY[:-1],
    PUBLIC_KEY + b'\x00',
    b'\x02' + b'\x11' * 32,
    b'\x02' + b'\x11' * 64,
])
def test_ecdh_rejects_public_key_format(card, public_key):
    with pytest.raises(ValueError, match='65-byte uncompressed'):
        ecdh(card, public_key, PATH)
    card.send_secure_apdu.assert_not_called()


@pytest.mark.parametrize('path', ["../0/0", "./0", "44'/1237'/0'/0/0"])
def test_ecdh_rejects_relative_path(card, path):
    with pytest.raises(ValueError, match='start at m'):
        ecdh(card, PUBLIC_KEY, path)
    card.send_secure_apdu.assert_not_called()


def test_ecdh_rejects_short_response(card):
    card.send_secure_apdu.return_value = SECRET[:31]

    with pytest.raises(InvalidResponseError, match='32-byte'):
        ecdh(card, PUBLIC_KEY, PATH)


def test_ecdh_requires_pin(card):
    card.is_pin_verified = False

    with pytest.raises(InvalidStateError, match='PIN'):
        ecdh(card, PUBLIC_KEY, PATH)
