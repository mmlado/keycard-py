import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from keycard.parsing.application_info import ApplicationInfo
from keycard.keycard import KeyCard
from .mocks import MockTransport
from keycard.apdu import APDUResponse
from keycard.exceptions import KeyCardError
from keycard.parsing.capabilities import Capabilities


def build_valid_select_response() -> bytes:
    inner_tlv = (
        bytes([0x8F, 16])
        + bytes(range(16))
        + bytes([0x02, 2])
        + bytes([1, 2])
        + bytes([0x8E, 32])
        + bytes([0xAA] * 32)
        + bytes([0x8D, 1])
        + bytes([0x07])
    )
    return bytes([0xA4, len(inner_tlv)]) + inner_tlv


def test_select_applet_success():
    transport = MockTransport(build_valid_select_response(), status_word=0x9000)
    card = KeyCard(transport)
    info: ApplicationInfo = card.select()

    assert info.version_major == 1
    assert info.version_minor == 2
    assert info.instance_uid == bytes(range(16))
    assert info.key_uid == bytes([0xAA] * 32)
    assert info.capabilities & Capabilities.SECURE_CHANNEL
    assert info.capabilities & Capabilities.CREDENTIALS_MANAGEMENT


def test_select_failure():
    transport = MockTransport(b"", status_word=0x6A82)
    card = KeyCard(transport)
    with pytest.raises(KeyCardError) as exc_info:
        card.select()
    assert "6A82" in str(exc_info.value)
