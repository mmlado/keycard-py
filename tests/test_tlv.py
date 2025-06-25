import os
import sys

import pytest

from keycard.exceptions import InvalidResponseError
from keycard.parsing.tlv import parse_tlv


sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))


def test_parse_tlv_valid():
    data = b'\x8F\x02\xAA\xBB'
    result = parse_tlv(data)
    assert result == [(0x8F, b'\xAA\xBB')]


def test_parse_tlv_incomplete_length():
    data = b'\x8F'
    with pytest.raises(InvalidResponseError):
        parse_tlv(data)


def test_parse_tlv_length_overflow():
    data = b'\x8F\x05\xAA\xBB'
    with pytest.raises(InvalidResponseError):
        parse_tlv(data)
