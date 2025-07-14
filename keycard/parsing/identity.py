from dataclasses import dataclass

from ecdsa import (
    BadSignatureError,
    ellipticcurve,
    VerifyingKey,
    SECP256k1,
    util,
)
from hashlib import sha256

from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv


@dataclass
class Identity:
    certificate: bytes
    signature: bytes

    def verify(self, challenge: bytes) -> bool:
        if len(self.certificate) < 33:
            raise InvalidResponseError('Certificate too short')

        compressed = self.certificate[:33]
        x = int.from_bytes(compressed[1:], 'big')

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

        try:
            vk.verify(
                der_signature,
                challenge,
                hashfunc=sha256,
                sigdecode=util.sigdecode_der
            )
            return True
        except BadSignatureError:
            return False

    @staticmethod
    def parse(data: bytes) -> 'Identity':
        tlvs = parse_tlv(data)

        cert = sig = None
        inner_tlvs = parse_tlv(tlvs[0xA0][0])

        if 0x8A in inner_tlvs and len(inner_tlvs[0x8A]):
            cert = inner_tlvs[0x8a][0]
        if 0x30 in inner_tlvs and len(inner_tlvs[0x30]):
            sig = inner_tlvs[0x30][0]

        if not cert or not sig:
            raise InvalidResponseError('Missing certificate or signature')

        return Identity(certificate=cert, signature=sig)

    def __str__(self) -> str:
        return (
            f'Identity(certificate='
            f'{self.certificate.hex() if self.certificate else None}, '
            f'signature='
            f'{self.signature.hex() if self.signature else None})'
        )
