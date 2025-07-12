from dataclasses import dataclass

from ecdsa import VerifyingKey, SECP256k1, util, ellipticcurve
from hashlib import sha256

from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv


@dataclass
class Identity:
    certificate: bytes
    signature: bytes

    def verify(self, challenge: bytes) -> bool:
        if len(self.certificate) < 33:
            raise InvalidResponseError("Certificate too short")

        compressed = self.certificate[:33]
        x = int.from_bytes(compressed[1:], "big")

        p = SECP256k1.curve.p()
        a = SECP256k1.curve.a()
        b = SECP256k1.curve.b()
        alpha = (x**3 + a*x + b) % p
        beta = pow(alpha, (p + 1) // 4, p)  # since p % 4 == 3

        if (compressed[0] == 3) != (beta % 2 == 1):
            beta = p - beta

        point = ellipticcurve.Point(SECP256k1.curve, x, beta)
        vk = VerifyingKey.from_public_point(point, curve=SECP256k1)

        r = int.from_bytes(self.signature[2:34], 'big')
        s = int.from_bytes(self.signature[36:], 'big')

        der_signature = util.sigencode_der(r, s, SECP256k1.order)

        vk.verify(
            der_signature,
            challenge,
            hashfunc=sha256,
            sigdecode=util.sigdecode_der
        )

    @staticmethod
    def parse(data: bytes) -> "Identity":
        tlvs: list[tuple[int, bytes]] = parse_tlv(data)

        cert = sig = None
        for tag, value in tlvs:
            if tag == 0xA0:
                inner_tlvs = parse_tlv(value)

                for inner_tag, inner_value in inner_tlvs:
                    if inner_tag == 0x8A:
                        cert = inner_value
                    elif inner_tag == 0x30:
                        sig = inner_value

        if not cert or not sig:
            raise InvalidResponseError("Missing certificate or signature")

        return Identity(certificate=cert, signature=sig)

    def __str__(self) -> str:
        return (
            f"Identity(certificate="
            f"{self.certificate.hex() if self.certificate else None}, "
            f"signature="
            f"{self.signature.hex() if self.signature else None})"
        )
