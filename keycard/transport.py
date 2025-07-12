from smartcard.System import readers

from .apdu import APDUResponse
from .exceptions import TransportError


class Transport:
    def __init__(self):
        self.connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.connection:
            self.connection.disconnect()
            self.connection = None

    def connect(self):
        r = readers()
        if not r:
            raise TransportError("No smart card readers found")
        self.connection = r[0].createConnection()
        self.connection.connect()

    def send_apdu(self, apdu: bytes) -> bytes:
        if not self.connection:
            self.connect()

        print(f"Sending APDU: {apdu.hex()}")
        apdu_list = list(apdu)

        response, sw1, sw2 = self.connection.transmit(apdu_list)

        sw = (sw1 << 8) | sw2
        return APDUResponse(response, sw)
