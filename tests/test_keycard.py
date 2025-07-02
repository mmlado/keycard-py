import binascii
import os
import sys

import pytest

from .mocks import MockTransport

from keycard.crypto.ecc import (
    export_uncompressed_public_key,
    generate_ephemeral_keypair
)
from keycard.exceptions import (
    APDUError,
    InvalidResponseError,
    NotSelectedError
)
from keycard.keycard import KeyCard
from keycard.parsing.application_info import ApplicationInfo
from keycard.parsing.capabilities import Capabilities
from keycard.parsing.identity import Identity


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

PIN = b'123456'
PUK = b'123456789012'
PAIRING_SECRET = b'A' * 32


def test_select_applet_success():
    inner_tlv = (
        bytes([0x8F, 16])
        + bytes(range(16))
        + bytes([0x02, 2])
        + bytes([1, 2])
        + bytes([0x8E, 32])
        + bytes([0xAA] * 32)
        + bytes([0x8D, 1])
        + bytes([0x07])
    )

    transport = MockTransport(
        bytes([0xA4, len(inner_tlv)]) + inner_tlv,
        status_word=0x9000
    )
    card = KeyCard(transport)
    info: ApplicationInfo = card.select()

    assert info.version_major == 1
    assert info.version_minor == 2
    assert info.instance_uid == bytes(range(16))
    assert info.key_uid == bytes([0xAA] * 32)
    assert info.capabilities & Capabilities.SECURE_CHANNEL
    assert info.capabilities & Capabilities.CREDENTIALS_MANAGEMENT


def test_select_failure():
    transport = MockTransport(b'', status_word=0x6A82)
    card = KeyCard(transport)
    with pytest.raises(APDUError) as exc_info:
        card.select()

    assert exc_info.value.sw == 0x6A82


def test_init_without_select_raises_not_selected_error():
    transport = MockTransport()
    card = KeyCard(transport)

    with pytest.raises(NotSelectedError):
        card.init(
            pin=b'123456',
            puk=b'123456789012',
            pairing_secret=b'secret-secret-secret-secret-secret-secret'
        )


def test_invalid_response_error():
    transport = MockTransport(b'\xA4\x05\x8F')
    card = KeyCard(transport)

    with pytest.raises(InvalidResponseError):
        card.select()


def test_init_success():

    def build_fake_application_info_response() -> bytes:
        # Construct fake TLV with ECC public key (65 bytes, all 0xAA)
        card_key = generate_ephemeral_keypair()
        ecc_pubkey = export_uncompressed_public_key(card_key)
        inner_tlv = (
            bytes([0x80, 65]) + ecc_pubkey +
            bytes([0x02, 2]) + bytes([1, 0]) +  # Version 1.0
            bytes([0x8F, 16]) + bytes([0xBB]*16) +
            bytes([0x8E, 32]) + bytes([0xCC]*32) +
            bytes([0x8D, 1]) + bytes([0x07])
        )

        return bytes([0xA4, len(inner_tlv)]) + inner_tlv

    transport = MockTransport()
    card = KeyCard(transport)
    transport._response_data = build_fake_application_info_response()

    # First call select() to set card_public_key
    card.select()

    transport._response_data = b''

    card.init(PIN, PUK, PAIRING_SECRET)


def test_init_without_select():
    transport = MockTransport()
    card = KeyCard(transport)

    with pytest.raises(NotSelectedError):
        card.init(PIN, PUK, PAIRING_SECRET)


def test_apdu_error_on_init():
    transport = MockTransport()
    card = KeyCard(transport)

    # Fake select to set card_public_key
    card._card_public_key = b'\x04' + bytes([0xAA]*64)

    with pytest.raises(ValueError):
        card.init(PIN, PUK, PAIRING_SECRET)


def test_ident_valid():
    challenge = bytes.fromhex('00' * 32)

    response_tlv_hex = (
        '8a62' +
        '02cf86373c304339c1bf8c4bc4d9fd4c7b8b9cb8f1efc90d9d1668aa0bccb9794e'
        '36a89f6edf7dd38a205d977f995fd6226e5dfc6c54b1b83b7a7a3c5229df4da6'
        'e9104eec7c470a4ac4a5e264414f2752c6ead32ab607a82823520fc5cd9ad04d'
        '00' +
        '3044' +
        '02' +
        '2036a89f6edf7dd38a205d977f995fd6226e5dfc6c54b1b83b7a7a3c5229df4da6' +
        '0220e9104eec7c470a4ac4a5e264414f2752c6ead32ab607a82823520fc5cd9ad04d'
    )
    response_data = binascii.unhexlify(response_tlv_hex)

    mock = MockTransport(response_data)

    card = KeyCard(mock)
    identity = card.ident(challenge)

    assert isinstance(identity, Identity)
    assert identity.certificate[:1] == b'\x02'


def test_ident_invalid_response():
    mock = MockTransport(b'\x30\x02\x01\x00')

    card = KeyCard(mock)
    with pytest.raises(InvalidResponseError):
        card.ident(b'\x00' * 32)


def test_open_secure_channel_success(monkeypatch):
    card_key = generate_ephemeral_keypair()

    salt = b'\x11' * 32
    seed_iv = b'\x22' * 16
    response = salt + seed_iv

    ephemeral_key = generate_ephemeral_keypair()
    monkeypatch.setattr(
        'Crypto.PublicKey.ECC.generate',
        lambda curve: ephemeral_key
    )

    class DummySession:
        def __init__(self, enc_key, mac_key, iv):
            self.enc_key = enc_key
            self.mac_key = mac_key
            self.iv = iv

    monkeypatch.setattr('keycard.keycard.SecureSession', DummySession)

    # Patch derive_shared_secret to return a fixed value
    monkeypatch.setattr(
        'keycard.keycard.derive_shared_secret',
        lambda a, b: b'sharedsecret'
    )

    class DummyDigest:
        def __init__(self):
            self._data = b''

        def update(self, data):
            self._data += data

        def digest(self):
            return b'A' * 64

    monkeypatch.setattr(
        'keycard.keycard.SHA512',
        type('SHA512', (), {"new": DummyDigest})
    )

    transport = MockTransport(response)
    card = KeyCard(transport)
    card.public_key = card_key.public_key()

    pairing_index = 1
    pairing_key = b'B' * 32

    card.open_secure_channel(pairing_index, pairing_key)

    assert isinstance(card.secure_session, DummySession)
    assert card.secure_session.enc_key == b'A' * 32
    assert card.secure_session.mac_key == b'A' * 32
    assert card.secure_session.iv == seed_iv


def test_open_secure_channel_not_selected():
    transport = MockTransport(b'')
    card = KeyCard(transport)
    card.public_key = None

    with pytest.raises(NotSelectedError):
        card.open_secure_channel(0, b'B' * 32)
