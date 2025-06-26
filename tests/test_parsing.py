import os
import sys

import pytest

from keycard.crypto.ecc import parse_uncompressed_public_key


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_parse_valid_public_key():
    valid_pubkey = bytes.fromhex(
        (
            '04be30331dbfc96848a8534c838227ff86acf59286e9face7787e37dba4c80c92'
            '7e8eb20ce1deca44b55772af2606cacf40bdefc2a9d86d06a6d6fee19e32d8ee3'
        )
    )

    key = parse_uncompressed_public_key(valid_pubkey)

    assert key.pointQ.x == int.from_bytes(
        bytes.fromhex(
            'be30331dbfc96848a8534c838227ff86acf59286e9face7787e37dba4c80c927'
        ),
        'big'
    )
    assert key.pointQ.y == int.from_bytes(
        bytes.fromhex(
            'e8eb20ce1deca44b55772af2606cacf40bdefc2a9d86d06a6d6fee19e32d8ee3'
        ),
        'big'
    )


def test_parse_invalid_point_coordinates():
    invalid_pubkey = b'\x04' + bytes([0xAA] * 64)
    with pytest.raises(ValueError,
                       match='EC point does not belong to the curve'):
        parse_uncompressed_public_key(invalid_pubkey)


def test_parse_invalid_prefix():
    invalid_pubkey = b'\x05' + bytes(64)
    with pytest.raises(ValueError,
                       match='Invalid uncompressed public key format'):
        parse_uncompressed_public_key(invalid_pubkey)


def test_parse_wrong_length():
    invalid_pubkey = b'\x04' + bytes(32)  # too short
    with pytest.raises(ValueError,
                       match='Invalid uncompressed public key format'):
        parse_uncompressed_public_key(invalid_pubkey)
