import pytest
import hashlib
from unittest.mock import MagicMock, patch
from keycard.commands.pair import pair
from keycard.apdu import APDUResponse
from keycard.exceptions import APDUError, InvalidResponseError


@pytest.fixture
def mock_urandom():
    with patch("keycard.commands.pair.urandom", return_value=b"\x01" * 32):
        yield


def test_pair_success(mock_urandom):
    shared_secret = b"\xAA" * 32
    client_challenge = b"\x01" * 32
    card_challenge = b"\x02" * 32
    expected_card_cryptogram = hashlib.sha256(
        shared_secret + client_challenge).digest()
    expected_client_cryptogram = hashlib.sha256(
        shared_secret + card_challenge).digest()

    first_response = expected_card_cryptogram + card_challenge
    second_response = b"\x05" + card_challenge

    card = MagicMock()
    card.send_apdu.side_effect = [first_response, second_response]

    result = pair(card, shared_secret)

    assert result == (5, expected_client_cryptogram)
    assert card.send_apdu.call_count == 2


def test_pair_invalid_shared_secret(mock_urandom):
    card = MagicMock()
    with pytest.raises(ValueError, match="Shared secret must be 32 bytes"):
        pair(card, b"short")


def test_pair_apdu_error_on_first(mock_urandom):
    card = MagicMock()
    card.send_apdu.side_effect = APDUError(0x6A82)

    with pytest.raises(APDUError):
        pair(card, b"\x00" * 32)


def test_pair_invalid_response_length_first(mock_urandom):
    card = MagicMock()
    card.send_apdu.return_value = bytes(10)

    with pytest.raises(
        InvalidResponseError,
        match="Unexpected response length"
    ):
        pair(card, b"\x00" * 32)


def test_pair_cryptogram_mismatch(mock_urandom):
    wrong_card_cryptogram = b"\xAB" * 32
    card_challenge = b"\x02" * 32
    response = wrong_card_cryptogram + card_challenge

    card = MagicMock()
    card.send_apdu.side_effect = [response]

    with pytest.raises(InvalidResponseError, match="Card cryptogram mismatch"):
        pair(card, b"\xAA" * 32)


def test_pair_invalid_response_second_apdu(mock_urandom):
    shared_secret = b"\xAA" * 32
    client_challenge = b"\x01" * 32
    card_challenge = b"\x02" * 32
    card_cryptogram = hashlib.sha256(shared_secret + client_challenge).digest()

    first_response = card_cryptogram + card_challenge
    second_response = b"\x00" * 10

    card = MagicMock()
    card.send_apdu.side_effect = [first_response, second_response]

    with pytest.raises(
        InvalidResponseError,
        match="Unexpected response length"
    ):
        pair(card, shared_secret)
