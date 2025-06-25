import os
import sys

import pytest

from keycard.crypto.aes import aes_cbc_encrypt


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_aes_invalid_key_length():
    with pytest.raises(ValueError):
        aes_cbc_encrypt(aes_key=b'short-key', iv=b'\x00'*16, plaintext=b'data')



def test_aes_invalid_iv_length():
    with pytest.raises(ValueError):
        aes_cbc_encrypt(aes_key=b'\x00'*32, iv=b'short-iv', plaintext=b'data')
