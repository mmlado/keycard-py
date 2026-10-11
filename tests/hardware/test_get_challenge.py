import pytest

from keycard.exceptions import APDUError
from keycard.secure_channel import SecureChannelVersion

pytestmark = pytest.mark.card

PIN = '123456'
PUK = '987654321098'
PAIRING_SECRET = 'KeycardTest'


def is_v2(keycard):
    return keycard.secure_channel_version == SecureChannelVersion.V2


def test_get_challenge(keycard):
    if not is_v2(keycard):
        pytest.skip('GET CHALLENGE needs applet 4.0')

    keycard.open_secure_channel()
    first = keycard.get_challenge(32)
    second = keycard.get_challenge(32)

    assert len(first) == len(second) == 32
    assert first != second
    assert len(keycard.get_challenge(245)) == 245


@pytest.mark.destructive
def test_get_challenge_after_reset(reset_keycard):
    keycard = reset_keycard

    if is_v2(keycard):
        assert not keycard.is_initialized
        keycard.open_secure_channel()
        assert len(keycard.get_challenge(16)) == 16
        return

    # Release 3.x applets lack the command; development builds answer with
    # or without a secure channel.
    try:
        plain = keycard.get_challenge(16)
    except APDUError:
        return
    assert len(plain) == 16

    keycard.init(PIN, PUK, PAIRING_SECRET)
    keycard.select()
    pairing = keycard.pair(PAIRING_SECRET)
    keycard.open_secure_channel()
    try:
        assert len(keycard.get_challenge(16)) == 16
    finally:
        keycard.verify_pin(PIN)
        keycard.unpair(pairing.slot)
