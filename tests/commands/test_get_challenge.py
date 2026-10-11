import pytest

from keycard import constants
from keycard.commands import get_challenge
from keycard.exceptions import InvalidResponseError, InvalidStateError


@pytest.mark.parametrize('version', [(3, 2), (4, 0)])
@pytest.mark.parametrize('length', [1, 32, 245])
def test_get_challenge_inside_secure_channel(card, version, length):
    card.version = version
    card.is_secure_channel_open = True
    card.send_secure_apdu.return_value = bytes(length)

    assert get_challenge(card, length) == bytes(length)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_GET_CHALLENGE, p1=length)
    card.send_apdu.assert_not_called()


@pytest.mark.parametrize('length', [1, 255])
def test_get_challenge_without_channel_on_v1(card, length):
    card.version = (3, 2)
    card.is_secure_channel_open = False
    card.send_apdu.return_value = bytes(length)

    assert get_challenge(card, length) == bytes(length)

    card.send_apdu.assert_called_once_with(
        ins=constants.INS_GET_CHALLENGE, p1=length)
    card.send_secure_apdu.assert_not_called()


def test_get_challenge_requires_secure_channel_on_v2(card):
    card.version = (4, 0)
    card.is_secure_channel_open = False

    with pytest.raises(InvalidStateError, match='Secure Channel'):
        get_challenge(card, 32)

    card.send_apdu.assert_not_called()
    card.send_secure_apdu.assert_not_called()


@pytest.mark.parametrize('length', [0, 256, -1])
def test_get_challenge_rejects_length(card, length):
    card.is_secure_channel_open = True

    with pytest.raises(ValueError, match='between 1 and 255'):
        get_challenge(card, length)

    card.send_secure_apdu.assert_not_called()


def test_get_challenge_rejects_short_response(card):
    card.version = (4, 0)
    card.is_secure_channel_open = True
    card.send_secure_apdu.return_value = bytes(31)

    with pytest.raises(InvalidResponseError, match='Expected 32'):
        get_challenge(card, 32)
