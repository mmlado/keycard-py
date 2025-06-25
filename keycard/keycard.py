from typing import Optional

from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

from . import constants
from .apdu import APDUResponse, encode_lv
from .crypto.aes import aes_cbc_encrypt, derive_aes_key
from .crypto.ecc import (
    derive_shared_secret,
    export_uncompressed_public_key,
    generate_ephemeral_keypair,
    parse_uncompressed_public_key,
)
from .crypto.padding import iso9797_m2_pad
from .exceptions import (
    APDUError, 
    NotSelectedError
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
        apdu: bytes = (
            bytes([constants.CLAISO7816, constants.INS_SELECT, P1, P2]) + aid
        )
        response: APDUResponse = self.transport.send_apdu(apdu)

        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)

        info: ApplicationInfo = ApplicationInfo.parse(response.data)
        self.card_public_key = info.ecc_public_key

        return info

    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes) -> None:
        if self.card_public_key is None:
            raise NotSelectedError("Card not selected. Call select() first.")

        ephemeral_key: ECC.EccKey = generate_ephemeral_keypair()
        our_pubkey_bytes: bytes = export_uncompressed_public_key(ephemeral_key)
        card_pubkey: ECC.EccKey = parse_uncompressed_public_key(self.card_public_key)
        shared_secret: bytes = derive_shared_secret(ephemeral_key, card_pubkey)
        aes_key: bytes = derive_aes_key(shared_secret)
        plaintext: bytes = pin + puk + pairing_secret
        plaintext_padded: bytes = iso9797_m2_pad(plaintext)
        iv: bytes = get_random_bytes(16)
        ciphertext: bytes = aes_cbc_encrypt(aes_key, iv, plaintext_padded)
        data: bytes = encode_lv(our_pubkey_bytes) + iv + ciphertext
        if len(data) > 255:
            raise ValueError("Data too long for single APDU")

        apdu: bytes = (
            bytes(
                [
                    constants.CLA_PROPRIETARY,
                    constants.INS_INIT,
                    0x00,
                    0x00,
                    len(data),
                ]
            )
            + data
        )

        response: APDUResponse = self.transport.send_apdu(apdu)

        if response.status_word != constants.SW_SUCCESS:
            raise APDUError(response.status_word)
