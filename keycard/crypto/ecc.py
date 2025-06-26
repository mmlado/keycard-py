"""
This module provides utility functions for Elliptic Curve Cryptography (ECC)
operations using the PyCryptodome library.
"""

from Crypto.PublicKey import ECC


def derive_shared_secret(private_key: ECC.EccKey,
                         peer_public_key: ECC.EccKey) -> bytes:
    """
    Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH) key
    exchange.

    Args:
        private_key (ECC.EccKey): The local party's private ECC key.
        peer_public_key (ECC.EccKey): The peer's public ECC key.

    Returns:
        bytes: The derived shared secret as a 32-byte big-endian value.

    Note:
        This function performs the ECDH operation manually by multiplying the
        private scalar with the peer's public point and extracting the
        x-coordinate as the shared secret.
    """
    shared_point: ECC.EccPoint = private_key.d * peer_public_key.pointQ
    x_shared: bytes = int(shared_point.x).to_bytes(32, byteorder='big')

    return x_shared


def export_uncompressed_public_key(ecc_key: ECC.EccKey) -> bytes:
    """
    Exports an ECC public key in uncompressed format.

    Args:
        ecc_key (ECC.EccKey): The ECC key object containing the public key.

    Returns:
        bytes: The uncompressed public key as a byte string, consisting of a
            0x04 prefix followed by the 32-byte big-endian X and Y coordinates.
    """
    point: ECC.EccPoint = ecc_key.pointQ
    x_bytes: bytes = int(point.x).to_bytes(32, byteorder='big')
    y_bytes: bytes = int(point.y).to_bytes(32, byteorder='big')

    return b'\x04' + x_bytes + y_bytes


def generate_ephemeral_keypair() -> ECC.EccKey:
    """
    Generates an ephemeral ECC (Elliptic Curve Cryptography) key pair using the
    P-256 curve.

    Returns:
        ECC.EccKey: The generated ephemeral ECC key pair.
    """
    key: ECC.EccKey = ECC.generate(curve="P-256")

    return key


def parse_uncompressed_public_key(raw: bytes) -> ECC.EccKey:
    """
    Parses an uncompressed ECC public key and returns an ECC.EccKey object.

    Args:
        raw (bytes): The uncompressed public key as a 65-byte sequence. The
        first byte should be 0x04, followed by 32 bytes for the X coordinate
        and 32 bytes for the Y coordinate.

    Returns:
        ECC.EccKey: The constructed ECC public key object using the P-256
            curve.

    Raises:
        ValueError: If the input does not conform to the uncompressed public
            key format.
    """
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("Invalid uncompressed public key format")

    x: int = int.from_bytes(raw[1:33], byteorder='big')
    y: int = int.from_bytes(raw[33:], byteorder='big')

    return ECC.construct(curve='P-256', point_x=x, point_y=y)
