import os
import sys

import pytest

from keycard.crypto.padding import iso9797_m2_pad, iso9797_m2_unpad


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_padding_exact_block_size():
    data = b'A' * 16
    padded = iso9797_m2_pad(data)
    assert len(padded) == 32  # always adds padding


def test_padding_unpad_roundtrip():
    data = b'ABC'
    padded = iso9797_m2_pad(data)
    unpadded = iso9797_m2_unpad(padded)
    assert unpadded == data


def test_unpad_invalid():
    with pytest.raises(ValueError):
        iso9797_m2_unpad(b'ABCDEF')  # no 0x80 found
