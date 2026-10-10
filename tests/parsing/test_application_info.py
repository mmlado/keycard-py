import pytest
from keycard.exceptions import InvalidResponseError
from keycard.parsing.application_info import ApplicationInfo
from keycard.parsing.capabilities import Capabilities


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
    assert info.capabilities == 3
    assert info.instance_uid is None
    assert info.key_uid is None
    assert info.version_major == 0
    assert info.version_minor == 0


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


def test_parse_tlv_success(monkeypatch):
    def dummy_parse_tlv(data):
        if data == b'\xA4\x0C' + b'\x01'*12:
            return {
                0xA4: [
                    b'\x8F\x02\xAA\xBB'
                    b'\x80\x02\x01\x02'
                    b'\x8E\x02\xCC\xDD'
                    b'\x8D\x01\x07'
                    b'\x02\x02\x02\x05'
                ]
            }
        return {
            0x8F: [b'\xAA\xBB'],
            0x80: [b'\x01\x02'],
            0x8E: [b'\xCC\xDD'],
            0x8D: [b'\x07'],
            0x02: [b'\x02\x05']
        }

    class DummyCapabilities:
        @staticmethod
        def parse(val):
            return val

    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        dummy_parse_tlv
    )
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )

    # Simulate TLV-encoded data
    data = b'\xA4\x0C' + b'\x01'*12
    info = ApplicationInfo.parse(data)

    assert info.instance_uid == b'\xAA\xBB'
    assert info.ecc_public_key == b'\x01\x02'
    assert info.key_uid == b'\xCC\xDD'
    assert info.capabilities == 7
    assert info.version_major == 2
    assert info.version_minor == 5


def test_parse_tlv_missing_a4(monkeypatch):
    def dummy_parse_tlv(data):
        # No 0xA4 tag present
        return {}

    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        dummy_parse_tlv
    )
    with pytest.raises(InvalidResponseError):
        ApplicationInfo.parse(b'\x00\x01\x02')


def test_parse_tlv_missing_fields(monkeypatch):
    def dummy_parse_tlv(data):
        # Missing some tags
        return {
            0xA4: [b'']
        }

    class DummyCapabilities:
        @staticmethod
        def parse(val):
            return val

    monkeypatch.setattr(
        'keycard.parsing.application_info.parse_tlv',
        dummy_parse_tlv
    )
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )

    with pytest.raises(InvalidResponseError, match='version'):
        ApplicationInfo.parse(b'\xA4\x01\x00')


def test_parse_pubkey_empty(monkeypatch):
    monkeypatch.setattr(
        'keycard.parsing.application_info.Capabilities',
        DummyCapabilities
    )
    # No pubkey bytes
    data = bytes([0x80, 0x00])
    info = ApplicationInfo.parse(data)
    assert info.ecc_public_key == b''
    assert info.capabilities == 1  # Only CREDENTIALS_MANAGEMENT
    assert info.instance_uid is None
    assert info.key_uid is None
    assert info.version_major == 0
    assert info.version_minor == 0


def test_is_initialized_property():
    info = ApplicationInfo(
        capabilities=1,
        ecc_public_key=None,
        instance_uid=None,
        key_uid=None,
        version_major=0,
        version_minor=0,
    )
    assert not info.is_initialized

    info.key_uid = b'\x01'
    assert info.is_initialized


# 3.2, initialized
SELECT_3_2 = bytes.fromhex(
    'a4618f10f19d991c5540034e2d8a81f7ca96cadb804104b0a7f30c7daa9ef25cfd57b290'
    'd0746c7bfa6b8cfc7ca3e8b936f0b6582a62de669543254a66160d63a55389aa02b4b6db'
    '89284dfda5eda9abb999355e8aa1b0020203020201098e008d011f'
)
# 4.0, initialized, key loaded
SELECT_4_0 = bytes.fromhex(
    'a48190020204008c01138e2032247859e85d192f8d6e57dc3bc238ace85cb96791e8b9ab'
    'c29643df7090c03f8d011f8a620257dad49497614a19a1dc8c53f0c0425dd6710ad4369a'
    '0a684041daedde1ae621abf896e3cd17472c32130e35326d71a0f79cae919333ea976aaa'
    '5914ef61f89d72341acc765027986fd415e5989eed49ad793e1c9e35e831aa4c5605da88'
    '17b801'
)
# 4.0, not initialized
SELECT_4_0_NEW = bytes.fromhex(
    'a470020204008c01008e008d011f8a6203523625c538127544f03b29754a106a88e0b6ee'
    'bb3a5d5a368b552960077c0a2d03318828db8d004431d99ea7dd2efe9bfd421983415c8e'
    '9c6f3ecd388bf317bd00c6bf5aba9c7a2d4e38432d442a5080c96c1210293883aef28e50'
    '3e78202b7d01'
)


def test_parse_3_2_select():
    info = ApplicationInfo.parse(SELECT_3_2)

    assert (info.version_major, info.version_minor) == (3, 2)
    assert info.instance_uid == bytes.fromhex(
        'f19d991c5540034e2d8a81f7ca96cadb')
    assert len(info.ecc_public_key) == 65
    assert info.free_pairing_slots == 9
    assert info.key_uid == b''
    assert info.status is None
    assert info.identity_certificate is None
    assert info.pin_retries is None
    assert info.is_initialized


def test_parse_4_0_select():
    info = ApplicationInfo.parse(SELECT_4_0)

    assert (info.version_major, info.version_minor) == (4, 0)
    assert info.instance_uid is None
    assert info.ecc_public_key is None
    assert info.free_pairing_slots is None
    assert len(info.key_uid) == 32
    assert info.status == 0x13
    assert info.is_initialized
    assert info.pin_retries == 3
    assert not info.is_lee_mode
    assert len(info.identity_certificate) == 98
    assert info.capabilities & Capabilities.FACTORY_RESET


def test_parse_4_0_select_not_initialized():
    info = ApplicationInfo.parse(SELECT_4_0_NEW)

    assert info.status == 0x00
    assert not info.is_initialized
    assert info.key_uid == b''
    assert len(info.identity_certificate) == 98


def test_lee_mode_from_status():
    info = ApplicationInfo(
        capabilities=None, ecc_public_key=None, instance_uid=None,
        key_uid=None, version_major=4, version_minor=0, status=0x33)

    assert info.is_lee_mode
    assert info.pin_retries == 3
