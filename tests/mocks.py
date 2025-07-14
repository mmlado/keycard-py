from typing import Optional
from keycard.transport import Transport, APDUResponse


class MockTransport(Transport):
    """General purpose mock where you control responses"""

    def __init__(self, response_data: bytes = b'', status_word: int = 0x9000):
        self._response_data: bytes = response_data
        self._status_word: int = status_word
        self.last_apdu: Optional[APDUResponse] = None

    def send_apdu(self, apdu: bytes) -> APDUResponse:
        self.last_apdu = apdu
        return APDUResponse(
            data=self._response_data,
            status_word=self._status_word
        )
