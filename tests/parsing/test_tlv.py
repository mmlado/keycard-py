import pytest
from keycard.parsing import tlv
from keycard.exceptions import InvalidResponseError

def test_parse_ber_length_short_form():
    data = bytes([0x05])
    length, consumed = tlv.parse_ber_length(data, 0)
    assert length == 5
    assert consumed == 1

def test_parse_ber_length_long_form_1byte():
    data = bytes([0x81, 0x10])
    length, consumed = tlv.parse_ber_length(data, 0)
    assert length == 0x10
    assert consumed == 2

def test_parse_ber_length_long_form_2bytes():
    data = bytes([0x82, 0x01, 0xF4])
    length, consumed = tlv.parse_ber_length(data, 0)
    assert length == 500
    assert consumed == 3

def test_parse_ber_length_unsupported_length():
    data = bytes([0x85, 0, 0, 0, 0, 0])
    with pytest.raises(InvalidResponseError):
        tlv.parse_ber_length(data, 0)

def test_parse_ber_length_exceeds_buffer():
    data = bytes([0x82, 0x01])  # Needs 2 bytes, only 1 provided
    with pytest.raises(InvalidResponseError):
        tlv.parse_ber_length(data, 0)

def test_parse_tlv_single():
    # Tag: 0x01, Length: 3, Value: b'abc'
    data = bytes([0x01, 0x03, ord('a'), ord('b'), ord('c')])
    result = tlv.parse_tlv(data)
    assert 0x01 in result
    assert result[0x01][0] == b'abc'

def test_parse_tlv_multiple_tags():
    # Tag: 0x01, Length: 2, Value: b'hi'
    # Tag: 0x02, Length: 1, Value: b'x'
    data = bytes([0x01, 0x02, ord('h'), ord('i'), 0x02, 0x01, ord('x')])
    result = tlv.parse_tlv(data)
    assert result[0x01][0] == b'hi'
    assert result[0x02][0] == b'x'

def test_parse_tlv_repeated_tag():
    # Tag: 0x01, Length: 1, Value: b'a'
    # Tag: 0x01, Length: 2, Value: b'bc'
    data = bytes([0x01, 0x01, ord('a'), 0x01, 0x02, ord('b'), ord('c')])
    result = tlv.parse_tlv(data)
    assert result[0x01][0] == b'a'
    assert result[0x01][1] == b'bc'

def test_parse_tlv_long_length():
    # Tag: 0x10, Length: 257 (0x101), Value: b'a'*257
    data = bytes([0x10, 0x82, 0x01, 0x01]) + b'a' * 257
    result = tlv.parse_tlv(data)
    assert result[0x10][0] == b'a' * 257

def test_parse_tlv_incomplete_value():
    # Tag: 0x01, Length: 5, Value: only 3 bytes present
    data = bytes([0x01, 0x05, ord('a'), ord('b'), ord('c')])
    with pytest.raises(InvalidResponseError):
        tlv.parse_tlv(data)
