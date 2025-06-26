from keycard.transport import Transport, APDUResponse


class MockTransport(Transport):
    """General purpose mock where you control responses"""

    def __init__(self, response_data: bytes = b'', status_word: int = 0x9000):
        self._response_data = response_data
        self._status_word = status_word

    def send_apdu(self, apdu: bytes) -> APDUResponse:
        return APDUResponse(
            data=self._response_data,
            status_word=self._status_word
        )
