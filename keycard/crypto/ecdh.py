from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def generate_key_pair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """
    Generates an ephemeral secp256k1 key pair.

    Returns:
        tuple[EllipticCurvePrivateKey, bytes]: The private key and its
            uncompressed public key (65 bytes).
    """
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    return private_key, public_key


def ecdh_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: bytes
) -> bytes:
    """
    Computes the secp256k1 ECDH shared secret.

    Args:
        private_key (EllipticCurvePrivateKey): Our private key.
        peer_public_key (bytes): The peer's encoded public key.

    Returns:
        bytes: The X coordinate of the shared point (32 bytes).

    Raises:
        ValueError: If the peer public key is not a valid point.
    """
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), bytes(peer_public_key))
    return private_key.exchange(ec.ECDH(), peer)
