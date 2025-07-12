import pytest

from keycard.exceptions import InvalidResponseError
from keycard.parsing.application_info import ApplicationInfo


class DummyCapabilities:
    CREDENTIALS_MANAGEMENT = 1
    SECURE_CHANNEL = 2

    @staticmethod
    def parse(val):
        return val


def test_parse_simple_pubkey(monkeypatch):
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )
    data = bytes([0x80, 0x04, 0x01, 0x02, 0x03, 0x04])
    info = ApplicationInfo.parse(data)
    assert info.ecc_public_key == b'\x01\x02\x03\x04'
    assert info.capabilities == 3  # 1 + 2
    assert info.instance_uid is None
    assert info.key_uid is None
    assert info.version_major == 0
    assert info.version_minor == 0


def test_parse_tlv(monkeypatch):
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )

    def fake_parse_tlv(inner_data):
        return {
            0x8F: [b'abc'],
            0x80: [b'pub'],
            0x8E: [b'key'],
            0x8D: [b'\x05'],
            0x02: [b'\x01\x02'],
        }
    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        fake_parse_tlv
    )
    data = bytes([0xA4, 0x03, 0x00, 0x00, 0x00])
    info = ApplicationInfo.parse(data)
    assert info.instance_uid == b'abc'
    assert info.ecc_public_key == b'pub'
    assert info.key_uid == b'key'
    assert info.capabilities == 5
    assert info.version_major == 1
    assert info.version_minor == 2


def test_parse_response_too_short():
    with pytest.raises(InvalidResponseError):
        ApplicationInfo._parse_response(b'\xA4')


def test_parse_response_invalid_tag():
    with pytest.raises(InvalidResponseError):
        ApplicationInfo._parse_response(b'\x00\x03\x01\x02\x03')


def test_parse_response_invalid_length():
    with pytest.raises(InvalidResponseError):
        ApplicationInfo._parse_response(b'\xA4\x0A\x01\x02\x03')


def test_str_method():
    info = ApplicationInfo(
        capabilities=7,
        ecc_public_key=b'\x01\x02',
        instance_uid=b'\xAA\xBB',
        key_uid=b'\xCC\xDD',
        version_major=2,
        version_minor=5,
    )
    s = str(info)
    assert '2.5' in s
    assert 'aabb' in s
    assert 'ccdd' in s
    assert '0102' in s
    assert '7' in s
