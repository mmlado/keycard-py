import os
import sys

from Crypto.PublicKey import ECC

from keycard.crypto.aes import (
    derive_aes_key,
    aes_cbc_encrypt
)
from keycard.crypto.ecc import (
    parse_uncompressed_public_key,
    derive_shared_secret
)
from keycard.crypto.padding import iso9797_m2_pad


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_full_crypto_vector():
    card_pubkey_bytes = bytes.fromhex(
        '04be30331dbfc96848a8534c838227ff86acf59286e9face7787e37dba4c80c92'
        '7e8eb20ce1deca44b55772af2606cacf40bdefc2a9d86d06a6d6fee19e32d8ee3'
    )
    ephemeral_private_bytes = bytes.fromhex(
        'a306aacaf5806304ed8740e8e0702c4e9d47ec27041705ccffce6802360c76c0'
    )
    iv = bytes.fromhex('d2c5feedf4bdb935057f8c78cf92395e')
    expected_ciphertext = bytes.fromhex(
        'caaac7be9c73923e34e0ccf1f5dd2d6a68bf6fb53d75d1176446b99a401e13d3'
        '8e14b2169811be239d3dcbec4d3b0b76cb1980fc68c54f1e817c83d4d57da011'
    )

    ephemeral_key: ECC.EccKey = ECC.construct(
        curve='P-256',
        d=int.from_bytes(ephemeral_private_bytes, 'big')
    )
    card_pubkey = parse_uncompressed_public_key(card_pubkey_bytes)

    shared_secret = derive_shared_secret(ephemeral_key, card_pubkey)
    aes_key = derive_aes_key(shared_secret)

    pin = b'123456'
    puk = b'123456789012'
    pairing_secret = b'A' * 32
    plaintext = pin + puk + pairing_secret
    padded = iso9797_m2_pad(plaintext)
    ciphertext = aes_cbc_encrypt(aes_key, iv, padded)

    # Assert full correctness
    assert ciphertext == expected_ciphertext
