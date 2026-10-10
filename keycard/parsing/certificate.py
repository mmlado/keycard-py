from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from ecdsa import SECP256k1, VerifyingKey

from ..exceptions import InvalidResponseError, UntrustedCardError

CERTIFICATE_LENGTH = 98


def compress_public_key(public_key: bytes) -> bytes:
    """
    Normalizes an encoded secp256k1 public key to its compressed form.

    Args:
        public_key (bytes): A compressed or uncompressed public key.

    Returns:
        bytes: The 33-byte compressed public key.

    Raises:
        ValueError: If the key is not a valid secp256k1 point.
    """
    key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), bytes(public_key))
    return key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


@dataclass(frozen=True)
class IdentityCertificate:
    """
    A card's Identity Certificate: its Identity Key signed by a Keycard CA.

    Attributes:
        identity_public_key (bytes): The card's compressed Identity Key.
        signature (bytes): The CA signature as r || s.
        recovery_id (int): Recovery id of the CA signature.
    """
    identity_public_key: bytes
    signature: bytes
    recovery_id: int

    @classmethod
    def parse(cls, data: bytes) -> 'IdentityCertificate':
        """
        Parses a 98-byte Identity Certificate.

        Raises:
            InvalidResponseError: If the certificate has the wrong length.
        """
        if len(data) != CERTIFICATE_LENGTH:
            raise InvalidResponseError(
                f'Identity Certificate must be {CERTIFICATE_LENGTH} bytes')
        return cls(bytes(data[:33]), bytes(data[33:97]), data[97])

    @property
    def ca_public_key(self) -> bytes:
        """
        The compressed public key of the Keycard CA that signed this
        certificate, recovered from the signature.

        Raises:
            InvalidResponseError: If no key can be recovered.
        """
        digest = sha256(self.identity_public_key).digest()
        try:
            candidates = VerifyingKey.from_public_key_recovery_with_digest(
                self.signature, digest, SECP256k1)
            key = candidates[self.recovery_id]
        except Exception as e:
            raise InvalidResponseError(
                'Cannot recover the CA key from the Identity Certificate'
            ) from e
        compressed: bytes = key.to_string('compressed')
        return compressed

    def check_trust(
        self,
        ca_public_keys: Iterable[bytes],
        trusted_identity_keys: Iterable[bytes] = ()
    ) -> None:
        """
        Checks that the certificate was signed by a trusted Keycard CA, or
        that its Identity Key is trusted directly.

        Raises:
            UntrustedCardError: If neither is the case.
        """
        trusted_identities = {
            compress_public_key(key) for key in trusted_identity_keys}
        if self.identity_public_key in trusted_identities:
            return

        trusted_cas = {compress_public_key(key) for key in ca_public_keys}
        if self.ca_public_key not in trusted_cas:
            raise UntrustedCardError(
                'Identity Certificate is not signed by a trusted Keycard CA')

    def verify(self, digest: bytes, signature: bytes) -> None:
        """
        Verifies a DER-encoded ECDSA signature made with the Identity Key
        over a SHA-256 digest.

        Raises:
            InvalidResponseError: If the signature is invalid.
        """
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), self.identity_public_key)
            key.verify(
                signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        except (InvalidSignature, ValueError) as e:
            raise InvalidResponseError('Identity signature is invalid') from e
