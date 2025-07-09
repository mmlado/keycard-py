import os
import sys

from keycard.crypto.aes import aes_cbc_encrypt
from pyaes import AESModeOfOperationCBC
from ecdsa import ECDH, SigningKey, SECP256k1, VerifyingKey


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def iso7816_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + b'\x80' + b'\x00' * (pad_len - 1)


def test_full_crypto_vector():
    card_pubkey_bytes = bytes.fromhex(
        '04525481c70263f79c29092e95cfc972e0eb427ea31fe6cc6c96787eb12205737'
        'd431929f0837c66a4ee514578a7d5eb78087927851b15b691a79cdea431bd63d9'
    )
    ephemeral_private_bytes = bytes.fromhex(
        'e3b9a83efa7b113bac4562a77c496de21a9f91a17fa8dcb2384ed7154bb43c5c'
    )
    iv = bytes.fromhex('d2c5feedf4bdb935057f8c78cf92395e')
    expected_ciphertext = bytes.fromhex(
        '4707ca7edf4218c416f252967da55f1b6e2e65f0ffa0305f71501f53aa283fd5'
        'aaa8b049e75288c01034f25893db43d4db4bd6dfc4a6546658dd22227082aa58'
    )

    ephemeral_key = SigningKey.from_string(
        ephemeral_private_bytes, 
        curve=SECP256k1
    )
    card_pubkey = VerifyingKey.from_string(card_pubkey_bytes, curve=SECP256k1)

    ecdh = ECDH(
        curve=SECP256k1, 
        private_key=ephemeral_key, 
        public_key=card_pubkey
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    pin = b'123456'
    puk = b'123456789012'
    pairing_secret = b'A' * 32
    plaintext = pin + puk + pairing_secret
    ciphertext: bytes = aes_cbc_encrypt(shared_secret, iv, plaintext)

    # Assert full correctness
    assert ciphertext == expected_ciphertext
