import binascii
import os
import pytest
import sys

from Crypto.PublicKey import ECC

from keycard.exceptions import InvalidResponseError
from keycard.parsing.identity import Identity


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_parse_card_identity_valid():
    cert = (
        '02cf86373c304339c1bf8c4bc4d9fd4c7b8b9cb8f1efc90d9d1668aa0bccb9794e'
        '36a89f6edf7dd38a205d977f995fd6226e5dfc6c54b1b83b7a7a3c5229df4da6'
        'e9104eec7c470a4ac4a5e264414f2752c6ead32ab607a82823520fc5cd9ad04d'
        '00'
    )

    sig = (
        '30'
        '44'
        '022036a89f6edf7dd38a205d977f995fd6226e5dfc6c54b1b83b7a7a3c5229df4da6'
        '0220e9104eec7c470a4ac4a5e264414f2752c6ead32ab607a82823520fc5cd9ad04d'
    )

    tlv = (
        '8a' + f'{len(cert)//2:02x}' + cert +
        '30' + sig[2:]  # skip the first byte (tag) as it’s already added
    )

    parsed = Identity.parse(binascii.unhexlify(tlv))

    assert isinstance(parsed, Identity)
    assert parsed.certificate[:1] == b'\x02'
    assert len(parsed.certificate) == 98
    assert parsed.signature[0] == 0x02


def test_parse_card_identity_missing_fields():
    bad_data = b'\x30\x02\x01\x02'  # No 0x8A tag

    with pytest.raises(InvalidResponseError):
        Identity.parse(bad_data)


def test_verify_with_short_certificate():
    identity = Identity(certificate=b'\x04', signature=b'\x00' * 64)

    with pytest.raises(InvalidResponseError, match='Certificate too short'):
        identity.verify(b'\x00' * 32)


def test_verify_with_invalid_ecc_key():
    identity = Identity(certificate=b'\x00' * 33, signature=b'\x00' * 64)

    with pytest.raises(InvalidResponseError, match='Invalid ECC public key'):
        identity.verify(b'\x00' * 32)


def test_verify_invalid_signature():
    key = ECC.generate(curve='P-256')
    point = key.pointQ

    x = int(point.x)
    y = int(point.y)

    x_bytes = x.to_bytes(32, 'big')
    prefix = b'\x03' if y % 2 else b'\x02'
    compressed_pubkey = prefix + x_bytes

    bad_signature = b'\x00' * 64
    challenge = b'\x01' * 32

    identity = Identity(certificate=compressed_pubkey, signature=bad_signature)
    assert identity.verify(challenge) is False
