import pytest

from keycard import constants
from keycard.commands import export_lee
from keycard.exceptions import InvalidResponseError, InvalidStateError
from keycard.parsing.keypath import KeyPath
from keycard.parsing.lee_keys import LeeKeys

# LEZ key_protocol child_keys_generation vector (m/42).
ASK = bytes.fromhex(
    'b5b269be1c60ae3e419d8285394009f8d057d3b97cc2b594f3193f232641304a')
NSK = bytes.fromhex(
    '095f03b99a49b41ff1c18d0df748d2c61d272195ee9d328aa2e346a45da953e7')
VSK_D = bytes.fromhex(
    '7aa7eded56a201924f0aa0413d4d0841f1f790996d861407e534f91e206d1770')
VSK_Z = bytes.fromhex(
    '70a881757fa0496e15a452d5fd870b1ad53578c7fe8f1ca9aabb5c0c2bd9813a')


def key_template(*elements):
    inner = b''.join(
        bytes([tag, len(value)]) + value for tag, value in elements)
    return b'\xA1\x81' + bytes([len(inner)]) + inner


RESPONSE = key_template(
    (0x84, ASK), (0x83, NSK), (0x85, VSK_D), (0x86, VSK_Z))


@pytest.fixture
def card(card):
    card.is_pin_verified = True
    return card


def test_export_lee(card):
    card.send_secure_apdu.return_value = RESPONSE

    keys = export_lee(card, 'm/42')

    assert keys == LeeKeys(ask=ASK, nsk=NSK, vsk_d=VSK_D, vsk_z=VSK_Z)
    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_EXPORT_LEE,
        data=KeyPath('m/42').data
    )


def test_export_lee_master_by_default(card):
    card.send_secure_apdu.return_value = RESPONSE

    export_lee(card)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_EXPORT_LEE, data=b'')


@pytest.mark.parametrize('path', ['../0', './0', '0/1'])
def test_export_lee_rejects_relative_path(card, path):
    with pytest.raises(ValueError, match='start at m'):
        export_lee(card, path)
    card.send_secure_apdu.assert_not_called()


def test_export_lee_missing_template(card):
    card.send_secure_apdu.return_value = b'\x80\x01\x00'

    with pytest.raises(InvalidResponseError, match='0xA1'):
        export_lee(card)


@pytest.mark.parametrize('response', [
    key_template((0x84, ASK), (0x83, NSK), (0x85, VSK_D)),
    key_template((0x84, ASK), (0x83, NSK), (0x85, VSK_D), (0x86, VSK_Z[1:])),
])
def test_export_lee_missing_or_short_key(card, response):
    card.send_secure_apdu.return_value = response

    with pytest.raises(InvalidResponseError, match='0x86'):
        export_lee(card)


def test_export_lee_requires_pin(card):
    card.is_pin_verified = False

    with pytest.raises(InvalidStateError, match='PIN'):
        export_lee(card)
