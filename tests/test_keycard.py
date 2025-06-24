import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from keycard.keycard import KeyCard
from keycard.transport import Transport
from keycard.apdu import APDUResponse
from keycard.exceptions import KeyCardError

class MockTransport(Transport):
    def send_apdu(self, apdu: bytes) -> APDUResponse:
        # For now, always return success with empty data
        return APDUResponse(data=b'', status_word=0x9000)

class FailingTransport(Transport):
    def send_apdu(self, apdu: bytes) -> APDUResponse:
        # Simulate failure response
        return APDUResponse(data=b'', status_word=0x6A82)

def test_select_applet_success():
    transport = MockTransport()
    card = KeyCard(transport)
    response = card.select()
    assert response == b""  # Because MockTransport returns empty data

def test_select_failure():
    transport = FailingTransport()
    card = KeyCard(transport)
    with pytest.raises(KeyCardError) as exc_info:
        card.select()
    assert "6A82" in str(exc_info.value)
