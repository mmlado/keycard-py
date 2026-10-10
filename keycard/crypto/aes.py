from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .padding import iso7816_pad, iso7816_unpad


def aes_cbc_encrypt(
    key: bytes,
    iv: bytes,
    data: bytes,
    padding: bool = True
) -> bytes:
    if padding:
        data = iso7816_pad(data, 16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return iso7816_unpad(decryptor.update(ciphertext) + decryptor.finalize())
