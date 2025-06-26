"""
This module provides cryptographic utilities for AES encryption in CBC mode and
key derivation.
"""
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def aes_cbc_encrypt(aes_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts the given plaintext using AES encryption in CBC mode.

    Args:
        aes_key (bytes): The 32-byte (256-bit) AES key.
        iv (bytes): The 16-byte initialization vector.
        plaintext (bytes): The data to encrypt. Must be a multiple of 16 bytes
            in length.

    Returns:
        bytes: The encrypted ciphertext.

    Raises:
        ValueError: If the AES key is not 32 bytes or the IV is not 16 bytes.
    """
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    cipher: bytes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext: bytes = cipher.encrypt(plaintext)

    return ciphertext


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives a 256-bit AES key from a 32-byte shared secret using SHA-256.

    Args:
        shared_secret (bytes): A 32-byte shared secret.

    Returns:
        bytes: A 32-byte (256-bit) AES key derived from the shared secret.

    Raises:
        ValueError: If the shared secret is not exactly 32 bytes long.
    """
    if len(shared_secret) != 32:
        raise ValueError("Shared secret must be 32 bytes")

    hash_obj: bytes = SHA256.new(shared_secret)

    return hash_obj.digest()
