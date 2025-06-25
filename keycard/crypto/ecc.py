from Crypto.PublicKey import ECC


def derive_shared_secret(private_key: ECC.EccKey, peer_public_key: ECC.EccKey) -> bytes:
    # Perform ECDH manually
    shared_point: ECC.EccPoint = private_key.d * peer_public_key.pointQ
    x_shared: bytes = int(shared_point.x).to_bytes(32, byteorder='big')

    return x_shared


def export_uncompressed_public_key(ecc_key: ECC.EccKey) -> bytes:
    point: ECC.EccPoint = ecc_key.pointQ
    x_bytes: bytes = int(point.x).to_bytes(32, byteorder='big')
    y_bytes: bytes = int(point.y).to_bytes(32, byteorder='big')

    return b'\x04' + x_bytes + y_bytes


def generate_ephemeral_keypair() -> ECC.EccKey:
    key: ECC.EccKey = ECC.generate(curve="P-256")

    return key


def parse_uncompressed_public_key(raw: bytes) -> ECC.EccKey:
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("Invalid uncompressed public key format")

    x: int = int.from_bytes(raw[1:33], byteorder='big')
    y: int = int.from_bytes(raw[33:], byteorder='big')

    return ECC.construct(curve='P-256', point_x=x, point_y=y)
