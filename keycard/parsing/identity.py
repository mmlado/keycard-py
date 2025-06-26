"""
This module provides functionality for parsing and verifying ECC-based card
identities using the NIST P-256 curve.
"""

from dataclasses import dataclass

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Math.Numbers import Integer

from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv


# Constants for the P-256 curve
# These values are taken from the NIST P-256 curve parameters.
# Source:
# https://www.nist.gov/itl/antd/groups/publications/documents/fips186-3.pdf
# Section 5.1.2, Table 1: P-256 Parameters
# Note: The values are in hexadecimal format and converted to integers.
# The curve equation is y^2 = x^3 + ax + b over the finite field defined by p.
_p = Integer(int(
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16))
_a = Integer(int(
    'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC', 16))
_b = Integer(int(
    '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16))


def _decompress_point(data: bytes) -> ECC.EccKey:
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("Invalid compressed ECC point")

    x = Integer.from_bytes(data[1:])
    alpha = (x**3 + _a * x + _b) % _p
    beta = alpha.sqrt(modulus=_p)

    # Choose the y with the correct parity
    if bool(beta.is_odd()) != (data[0] == 3):
        beta = _p - beta

    return ECC.construct(curve='P-256', point_x=int(x), point_y=int(beta))


@dataclass
class Identity:
    """
    CardIdentity represents a card's identity, including its certificate and
    signature.

    Attributes:
        certificate (bytes): The ECC public key certificate, expected to be
            at least 33 bytes.
        signature (bytes): The signature associated with the certificate.
    """
    certificate: bytes
    signature: bytes

    def verify(self, challenge: bytes) -> bool:
        """
        Verifies the authenticity of a challenge using the certificate's ECC
        public key and a signature.

        Args:
            challenge (bytes): The challenge data to verify.

        Returns:
            bool: True if the signature is valid for the given challenge,
                False otherwise.

        Raises:
            InvalidResponseError: If the certificate is too short or contains
            an invalid ECC public key.
        """
        if len(self.certificate) < 33:
            raise InvalidResponseError("Certificate too short")

        compressed_pubkey = self.certificate[:33]
        try:
            ecc_key = _decompress_point(compressed_pubkey)
        except ValueError:
            raise InvalidResponseError("Invalid ECC public key")

        verifier = DSS.new(ecc_key, 'fips-186-3')
        h = SHA256.new(challenge)

        try:
            verifier.verify(h, self.signature)
            return True
        except ValueError:
            return False

    @staticmethod
    def parse(data: bytes) -> "Identity":
        """
        Parses a byte sequence containing TLV-encoded card identity data and
        extracts the certificate and signature.

        Args:
            data (bytes): The TLV-encoded data to parse.

        Returns:
            CardIdentity: An object containing the extracted certificate and
            signature.

        Raises:
            InvalidResponseError: If either the certificate or signature is
            missing from the parsed data.
        """
        tlvs: list[tuple[int, bytes]] = parse_tlv(data)

        cert = sig = None
        for tag, value in tlvs:
            if tag == 0x8A:
                cert = value
            elif tag == 0x30:
                sig = value

        if not cert or not sig:
            raise InvalidResponseError("Missing certificate or signature")

        return Identity(certificate=cert, signature=sig)
