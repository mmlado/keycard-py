from . import constants
from .apdu import APDUResponse
from .exceptions import KeyCardError
from .transport import Transport, APDUResponse
from .parsing.application_info import ApplicationInfo

class KeyCard:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport

    def select(self) -> bytes:
        P1: int = 0x04
        P2: int = 0x00
        aid: bytes = constants.KEYCARD_AID
        apdu: bytes = bytes([constants.CLAISO7816, constants.INS_SELECT, P1, P2]) + aid
        response: APDUResponse = self.transport.send_apdu(apdu)
        if response.status_word != constants.SW_SUCCESS:
            raise KeyCardError(f"Select failed with SW={response.status_word:04X}")

        return ApplicationInfo.parse(response.data)
