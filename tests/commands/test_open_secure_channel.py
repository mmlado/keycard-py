import importlib
import os
from hashlib import sha512
from unittest.mock import MagicMock, patch

import pytest

from keycard import constants
from keycard.apdu import APDUResponse
from keycard.commands.open_secure_channel import open_secure_channel
from keycard.crypto.aes import aes_cbc_decrypt, aes_cbc_encrypt
from keycard.exceptions import InvalidResponseError, InvalidStateError
from keycard.pairing import Pairing

PAIRING = Pairing(1, bytes(range(32)))
SHARED_SECRET = b'\xBB' * 32
SALT = b'A' * 32
SEED_IV = b'B' * 16
EPHEMERAL_PUBLIC_KEY = b'\x04' + b'\x02' * 64
DIGEST = sha512(SHARED_SECRET + PAIRING.key + SALT).digest()
ENC_KEY, MAC_KEY = DIGEST[:32], DIGEST[32:]

osc_module = importlib.import_module('keycard.commands.open_secure_channel')


@pytest.mark.parametrize('version,helper', [
    ((3, 2), '_open_v1'),
    ((4, 0), '_open_v2'),
])
def test_open_secure_channel_uses_helper_for_version(card, version, helper):
    card.version = version
    with patch.object(
        osc_module, helper,
        return_value='channel'
    ) as open_version:
        assert open_secure_channel(card) == 'channel'

    open_version.assert_called_once_with(card)


def card_response(command, payload):
    """Encrypts a response the way a 3.x card does."""
    encrypted = aes_cbc_encrypt(ENC_KEY, command[5:21], payload + b'\x90\x00')
    lr = (16 + len(encrypted)) & 0xFF
    mac = aes_cbc_encrypt(
        MAC_KEY, bytes(16), bytes([lr]) + bytes(15) + encrypted,
        padding=False
    )[-16:]
    return APDUResponse(mac + encrypted, 0x9000)


@pytest.fixture
def v1_card(card):
    card.version = (3, 2)
    card.is_initialized = True
    card.pairing = PAIRING
    card.card_public_key = b'\x04' + b'\x01' * 64
    card.send_apdu.return_value = SALT + SEED_IV
    with (
        patch.object(
            osc_module, 'generate_key_pair',
            return_value=(MagicMock(), EPHEMERAL_PUBLIC_KEY)
        ),
        patch.object(
            osc_module, 'ecdh_shared_secret',
            return_value=SHARED_SECRET
        ),
    ):
        yield card


def test_v1_open_derives_keys_and_mutually_authenticates(v1_card):
    challenges = []

    def send_raw_apdu(apdu):
        assert apdu[:4] == bytes([0x80, 0x11, 0x00, 0x00])
        challenges.append(aes_cbc_decrypt(ENC_KEY, SEED_IV, apdu[21:]))
        return card_response(apdu, os.urandom(32))

    v1_card.send_raw_apdu.side_effect = send_raw_apdu

    channel = open_secure_channel(v1_card)

    v1_card.send_apdu.assert_called_once_with(
        ins=constants.INS_OPEN_SECURE_CHANNEL,
        p1=PAIRING.slot,
        data=EPHEMERAL_PUBLIC_KEY
    )
    assert (channel.enc_key, channel.mac_key) == (ENC_KEY, MAC_KEY)
    assert len(challenges) == 1 and len(challenges[0]) == 32
    assert channel.is_open


def test_v1_open_rejects_short_mutual_authentication(v1_card):
    v1_card.send_raw_apdu.side_effect = (
        lambda apdu: card_response(apdu, bytes(31)))

    with pytest.raises(InvalidResponseError, match='not 32 bytes'):
        open_secure_channel(v1_card)


def test_v1_open_requires_pairing(v1_card):
    v1_card.pairing = None

    with pytest.raises(InvalidStateError, match='needs a pairing'):
        open_secure_channel(v1_card)

    v1_card.send_apdu.assert_not_called()


def test_v1_open_requires_initialized_card(v1_card):
    v1_card.is_initialized = False

    with pytest.raises(InvalidStateError, match='Initialization'):
        open_secure_channel(v1_card)

    v1_card.send_apdu.assert_not_called()
