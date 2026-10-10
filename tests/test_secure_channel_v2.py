import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from keycard.apdu import APDUResponse
from keycard.exceptions import (
    APDUError,
    InvalidResponseError,
    InvalidStateError,
)
from keycard.secure_channel import SecureChannelV2, SecureChannelVersion
from keycard.secure_channel.v2 import transcript_digest

KEY_H2C = bytes(range(16))
KEY_C2H = bytes(range(16, 32))


def nonce(counter):
    return counter.to_bytes(13, 'big')


def card_response(payload, sw, counter=0):
    data = AESCCM(KEY_C2H, 8).encrypt(
        nonce(counter), payload + sw.to_bytes(2, 'big'), None)
    return APDUResponse(data, 0x9000)


def test_version_and_is_open():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    assert channel.version == SecureChannelVersion.V2
    assert channel.is_open


def test_from_handshake_matches_spec_derivation():
    salt = bytes(range(32))
    shared_x = bytes(range(32, 64))
    prk = hmac.new(salt, shared_x, hashlib.sha256).digest()
    okm = hmac.new(prk, b'sc_v2_ccm' + b'\x01', hashlib.sha256).digest()

    channel = SecureChannelV2.from_handshake(salt, shared_x)
    apdu = channel.wrap(0x20, 0, 0, b'123456')

    inner = AESCCM(okm[:16], 8).decrypt(nonce(0), apdu[5:], None)
    assert inner == bytes([0x80, 0x20, 0x00, 0x00, 6]) + b'123456'


def test_transcript_digest():
    digest = transcript_digest(b'salt', b'client', b'card')

    assert digest == hashlib.sha256(
        b'sc_v2_ccm' + b'salt' + b'client' + b'card').digest()


def test_wrap_encrypts_whole_inner_apdu():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    apdu = channel.wrap(0xC0, 0x01, 0x03, b'data')

    assert apdu[:4] == bytes([0x80, 0x18, 0x00, 0x00])
    assert apdu[4] == len(apdu) - 5
    inner = AESCCM(KEY_H2C, 8).decrypt(nonce(0), apdu[5:], None)
    assert inner == bytes([0x80, 0xC0, 0x01, 0x03, 4]) + b'data'


def test_unwrap_returns_data_and_advances_counter():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    assert channel.unwrap(card_response(b'first', 0x9000)) == b'first'
    apdu = channel.wrap(0xF2, 0, 0, b'')
    assert AESCCM(KEY_H2C, 8).decrypt(nonce(1), apdu[5:], None)
    assert channel.unwrap(card_response(b'second', 0x9000, 1)) == b'second'


def test_unwrap_inner_status_word_keeps_channel_open():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    with pytest.raises(APDUError) as excinfo:
        channel.unwrap(card_response(b'', 0x63C2))

    assert excinfo.value.sw == 0x63C2
    assert channel.is_open


def test_unwrap_6982_closes_channel():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    with pytest.raises(APDUError) as excinfo:
        channel.unwrap(APDUResponse(b'', 0x6982))

    assert excinfo.value.sw == 0x6982
    assert not channel.is_open


def test_unwrap_rejects_modified_response():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)
    response = card_response(b'data', 0x9000)
    tampered = bytes([response.data[0] ^ 1]) + bytes(response.data[1:])

    with pytest.raises(InvalidResponseError, match='authentication'):
        channel.unwrap(APDUResponse(tampered, 0x9000))

    assert not channel.is_open


def test_unwrap_rejects_response_for_other_counter():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    with pytest.raises(InvalidResponseError):
        channel.unwrap(card_response(b'data', 0x9000, counter=1))


def test_wrap_rejects_closed_channel():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)
    channel.close()

    with pytest.raises(InvalidStateError):
        channel.wrap(0x20, 0, 0, b'')


def test_wrap_rejects_too_long_command():
    channel = SecureChannelV2(KEY_H2C, KEY_C2H)

    channel.wrap(0xE2, 0, 0, bytes(242))
    with pytest.raises(ValueError, match='too long'):
        channel.wrap(0xE2, 0, 0, bytes(243))
