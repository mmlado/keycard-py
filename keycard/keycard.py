from typing import Optional

from . import constants
from .apdu import (
    APDUResponse,
    encode_lv,
)
from .exceptions import (
    APDUError,
    KeyCardError,
    NotSelectedError,
)
from .parsing.application_info import ApplicationInfo
from .transport import Transport


class KeyCard:
    def __init__(self, transport: Transport) -> None:
        self.transport: Transport = transport
        self.card_public_key: Optional[bytes] = None

    def select(self) -> bytes:
        P1: int = 0x04
        P2: int = 0x00
        aid: bytes = constants.KEYCARD_AID
        apdu: bytes = bytes([constants.CLAISO7816, constants.INS_SELECT, P1, P2]) + aid
        response: APDUResponse = self.transport.send_apdu(apdu)
        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)

        info: ApplicationInfo = ApplicationInfo.parse(response.data)
        self.card_public_key = info.ecc_public_key

        return info

    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes) -> None:
        if self.card_public_key is None:
            raise NotSelectedError("Card public key not set. Run select() first.")

        iv = bytes(16)
        encrypted_payload = bytes(50)  # Placeholder for actual encryption logic

        data = encode_lv(self.card_public_key) + iv + encrypted_payload
        if len(data) > 255:
            raise ValueError("Data too long for single APDU")

        apdu = bytes([constants.CLA_PROPRIETARY, constants.INS_INIT, 0x00, 0x00, len(data)]) + data

        response = self.transport.send_apdu(apdu)
        if response.status_word != constants.SW_SUCCESS:
            raise KeyCardError(f"INIT failed with SW={response.status_word:04X}")