from .apdu import APDUResponse


class Transport:
    def send_apdu(self, apdu: bytes) -> APDUResponse:
        """Abstract transport interface"""
        raise NotImplementedError
