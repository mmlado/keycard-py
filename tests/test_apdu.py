import pytest

from keycard.apdu import encode_lv



def test_encode_lv_valid():
    value = bytes(10)
    result = encode_lv(value)
    assert result == b'\x0A' + value


def test_encode_lv_too_long():
    value = bytes(256)
    with pytest.raises(ValueError):
        encode_lv(value)

def test_encode_lv_empty():
    value = bytes()
    result = encode_lv(value)
    assert result == b'\x00'

def test_encode_lv_single_byte():
    value = bytes([0xFF])
    result = encode_lv(value)
    assert result == b'\x01\xFF'

def test_encode_lv_max_length():
    value = bytes(255)
    result = encode_lv(value)
    assert result == b'\xFF' + value
