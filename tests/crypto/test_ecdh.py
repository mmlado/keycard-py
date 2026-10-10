import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from keycard.crypto.ecdh import ecdh_shared_secret, generate_key_pair


def test_generate_key_pair_returns_uncompressed_public_key():
    _, public_key = generate_key_pair()

    assert len(public_key) == 65
    assert public_key[0] == 0x04


def test_shared_secret_is_symmetric():
    key_a, public_a = generate_key_pair()
    key_b, public_b = generate_key_pair()

    secret = ecdh_shared_secret(key_a, public_b)

    assert len(secret) == 32
    assert secret == ecdh_shared_secret(key_b, public_a)


def test_shared_secret_rejects_invalid_point():
    key = ec.generate_private_key(ec.SECP256K1())

    with pytest.raises(ValueError):
        ecdh_shared_secret(key, b'\x04' + bytes(64))
