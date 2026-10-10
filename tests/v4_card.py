from hashlib import sha256
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from keycard.apdu import APDUResponse

from tests.identity_helpers import CardIdentity, make_card_identity

LABEL = b'sc_v2_ccm'


def tlv(tag: int, value: bytes) -> bytes:
    length = bytes([len(value)]) if len(value) < 0x80 else bytes(
        [0x81, len(value)])
    return bytes([tag]) + length + value


class V4Card:
    """A minimal applet 4.0 simulation for Secure Channel V2 tests."""

    def __init__(self, identity: Optional[CardIdentity] = None) -> None:
        self.identity = identity or make_card_identity()
        self.channel: Optional[tuple[AESCCM, AESCCM]] = None
        self.counter = 0
        self.pin: Optional[bytes] = None
        self.inner_apdus: list[bytes] = []
        self.sign_transcript = True

    def select_response(self) -> bytes:
        status = 0x13 if self.pin is not None else 0x00
        inner = (
            tlv(0x02, b'\x04\x00') + tlv(0x8C, bytes([status]))
            + tlv(0x8E, b'') + tlv(0x8D, b'\x1f')
            + tlv(0x8A, self.identity.certificate)
        )
        return tlv(0xA4, inner)

    def send_apdu(self, apdu: bytes) -> APDUResponse:
        ins, lc = apdu[1], apdu[4]
        data = apdu[5:5 + lc]
        if ins == 0xA4:
            self.channel = None
            return APDUResponse(self.select_response(), 0x9000)
        if ins == 0x10:
            return self._open(data)
        if ins == 0x18 and self.channel is not None:
            return self._secured(data)
        return APDUResponse(b'', 0x6985)

    def _open(self, data: bytes) -> APDUResponse:
        salt, client_public_key = data[:32], data[32:97]
        ephemeral = ec.generate_private_key(ec.SECP256K1())
        card_public_key = ephemeral.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint)
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), client_public_key)
        okm = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt, info=LABEL
        ).derive(ephemeral.exchange(ec.ECDH(), peer))
        self.channel = (AESCCM(okm[:16], 8), AESCCM(okm[16:], 8))
        self.counter = 0

        transcript = LABEL + salt + client_public_key + card_public_key
        if not self.sign_transcript:
            transcript += b'tampered'
        signature = self.identity.private_key.sign(
            sha256(transcript).digest(), ec.ECDSA(Prehashed(hashes.SHA256())))
        return APDUResponse(card_public_key + signature, 0x9000)

    def _secured(self, data: bytes) -> APDUResponse:
        h2c, c2h = self.channel
        nonce = self.counter.to_bytes(13, 'big')
        inner = h2c.decrypt(nonce, data, None)
        self.inner_apdus.append(inner)
        payload, sw = self._handle(inner)
        response = c2h.encrypt(nonce, payload + sw.to_bytes(2, 'big'), None)
        self.counter += 1
        return APDUResponse(response, 0x9000)

    def _handle(self, inner: bytes) -> tuple[bytes, int]:
        ins, lc = inner[1], inner[4]
        data = inner[5:5 + lc]
        if ins == 0xFE:
            self.pin = data[:6]
            return b'', 0x9000
        if ins == 0x20:
            return b'', 0x9000 if data == self.pin else 0x63C2
        if ins == 0xF2:
            status = tlv(0x02, b'\x03') + tlv(0x02, b'\x05') + tlv(
                0x01, b'\x00')
            return tlv(0xA3, status), 0x9000
        return b'', 0x6D00
