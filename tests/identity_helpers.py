from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from ecdsa import SECP256k1, VerifyingKey

from keycard.constants import TEST_CA_PUBLIC_KEY

# Public test key used by upstream tools (keycard-cli load-ident --test).
TEST_CA_PRIVATE_KEY = int(
    'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2', 16)

__all__ = ['CardIdentity', 'TEST_CA_PUBLIC_KEY', 'make_card_identity']


def compressed(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


@dataclass
class CardIdentity:
    """A simulated card identity: Identity Key plus its certificate."""
    private_key: ec.EllipticCurvePrivateKey
    certificate: bytes

    def sign_digest(self, digest: bytes) -> bytes:
        return self.private_key.sign(
            digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def make_card_identity(
    ca_private_key: int = TEST_CA_PRIVATE_KEY
) -> CardIdentity:
    ca = ec.derive_private_key(ca_private_key, ec.SECP256K1())
    identity = ec.generate_private_key(ec.SECP256K1())
    identity_public_key = compressed(identity.public_key())
    digest = sha256(identity_public_key).digest()

    r, s = decode_dss_signature(
        ca.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
    signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    candidates = VerifyingKey.from_public_key_recovery_with_digest(
        signature, digest, SECP256k1)
    recovery_id = [
        key.to_string('compressed') for key in candidates
    ].index(compressed(ca.public_key()))

    return CardIdentity(
        identity, identity_public_key + signature + bytes([recovery_id]))
