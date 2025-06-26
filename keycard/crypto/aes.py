from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def aes_cbc_encrypt(aes_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError("AES key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    cipher: bytes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext: bytes = cipher.encrypt(plaintext)

    return ciphertext


def derive_aes_key(shared_secret: bytes) -> bytes:
    if len(shared_secret) != 32:
        raise ValueError("Shared secret must be 32 bytes")

    hash_obj: bytes = SHA256.new(shared_secret)

    return hash_obj.digest()
