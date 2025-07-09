from ecdsa import ECDH, SECP256k1, SigningKey, VerifyingKey


def derive_shared_secret(private_key, peer_public_key) -> bytes:
    ecdh = ECDH(
        curve=SECP256k1, 
        private_key=private_key, 
        public_key=peer_public_key
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    return shared_secret


def export_uncompressed_public_key(ecc_key) -> bytes:
    return ecc_key.verifying_key.to_string("uncompressed")


def generate_ephemeral_keypair() -> SigningKey:
    return SigningKey.generate(curve=SECP256k1)


def parse_uncompressed_public_key(raw: bytes) -> VerifyingKey:
    return VerifyingKey.from_string(raw, curve=SECP256k1)
