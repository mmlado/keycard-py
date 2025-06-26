from dataclasses import dataclass

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv


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
            ecc_key = ECC.import_key(compressed_pubkey)
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
