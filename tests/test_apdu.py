import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from keycard.apdu import encode_lv


def test_encode_lv_valid():
    value = bytes(10)
    result = encode_lv(value)
    assert result == b'\x0A' + value


def test_encode_lv_too_long():
    value = bytes(256)
    with pytest.raises(ValueError):
        encode_lv(value)