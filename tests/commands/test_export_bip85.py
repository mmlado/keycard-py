import pytest

from keycard import constants
from keycard.commands import export_bip85
from keycard.exceptions import InvalidResponseError, InvalidStateError
from keycard.parsing.keypath import KeyPath

PATH = "m/83696968'/0'/0'"
# BIP-85 test case 1.
ENTROPY = bytes.fromhex(
    'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0'
    '0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7')


@pytest.fixture
def card(card):
    card.is_pin_verified = True
    return card


@pytest.mark.parametrize('length', [1, 16, 64])
def test_export_bip85(card, length):
    card.send_secure_apdu.return_value = ENTROPY[:length]

    assert export_bip85(card, PATH, length) == ENTROPY[:length]

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_EXPORT_BIP85,
        p1=length,
        data=KeyPath(PATH).data
    )


@pytest.mark.parametrize('length', [0, 65, -1])
def test_export_bip85_rejects_length(card, length):
    with pytest.raises(ValueError, match='between 1 and 64'):
        export_bip85(card, PATH, length)
    card.send_secure_apdu.assert_not_called()


@pytest.mark.parametrize('path', ["../0'", "./0'", "83696968'/0'/0'"])
def test_export_bip85_rejects_relative_path(card, path):
    with pytest.raises(ValueError, match='start at m'):
        export_bip85(card, path, 32)
    card.send_secure_apdu.assert_not_called()


def test_export_bip85_rejects_short_response(card):
    card.send_secure_apdu.return_value = ENTROPY[:31]

    with pytest.raises(InvalidResponseError, match='Expected 32'):
        export_bip85(card, PATH, 32)


def test_export_bip85_requires_pin(card):
    card.is_pin_verified = False

    with pytest.raises(InvalidStateError, match='PIN'):
        export_bip85(card, PATH, 32)
