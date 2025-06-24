from . import constants
from .apdu import APDUResponse
from .exceptions import KeyCardError
from .transport import Transport, APDUResponse


class KeyCard:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport

    def select(self) -> bytes:
        apdu: bytes = self.build_select_apdu(constants.KEYCARD_AID)
        response: APDUResponse = self.transport.send_apdu(apdu)
        if response.status_word != constants.SW_SUCCESS:
            raise KeyCardError(f"Select failed with SW={response.status_word:04X}")

        return response.data

    @staticmethod
    def build_select_apdu(aid: bytes) -> bytes:
        P1: int = 0x04
        P2: int = 0x00

        return (
            bytes([constants.CLAISO7816, constants.INS_SELECT, P1, P2, len(aid)]) + aid
        )
