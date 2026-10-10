"""
Provision a development Keycard with an Identity Certificate signed by the
Test CA, equivalent to `keycard-cli load-ident --test`.

Usage: python tools/load_test_identity.py [--reader INDEX]
"""
import argparse
import hashlib
import sys

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
from smartcard.System import readers

TEST_CA_PRIVATE_KEY = bytes.fromhex(
    'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2')
IDENT_INSTANCE_AID = bytes.fromhex('A00000080400010401')
CLA_GP = 0x80
INS_STORE_DATA = 0xE2
CERT_LEN = 98


def compressed(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def recover_keys(signature: bytes, digest: bytes) -> list[bytes]:
    """Candidate signer keys, indexed by recovery id."""
    candidates = VerifyingKey.from_public_key_recovery_with_digest(
        signature, digest, SECP256k1)
    return [key.to_string('compressed') for key in candidates]


def parse_certificate(cert: bytes) -> tuple[bytes, bytes]:
    """Returns (identity public key, recovered CA public key)."""
    ident_pub = cert[:33]
    digest = hashlib.sha256(ident_pub).digest()
    return ident_pub, recover_keys(cert[33:97], digest)[cert[97]]


def create_certificate(
    ca: ec.EllipticCurvePrivateKey
) -> tuple[bytes, bytes]:
    """Returns (98-byte certificate, 32-byte identity private key)."""
    ident = ec.generate_private_key(ec.SECP256K1())
    ident_pub = compressed(ident.public_key())
    digest = hashlib.sha256(ident_pub).digest()

    r, s = decode_dss_signature(
        ca.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256()))))
    # Match keycard-go, which produces low-S signatures.
    if s > SECP256k1.order // 2:
        s = SECP256k1.order - s
    signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    rec_id = recover_keys(signature, digest).index(
        compressed(ca.public_key()))
    cert = ident_pub + signature + bytes([rec_id])
    ident_priv = ident.private_numbers().private_value.to_bytes(32, 'big')
    return cert, ident_priv


def transmit(connection, apdu: bytes) -> bytes:
    data, sw1, sw2 = connection.transmit(list(apdu))
    sw = (sw1 << 8) | sw2
    if sw != 0x9000:
        raise RuntimeError(f'APDU {apdu[:4].hex()} failed with SW {sw:04X}')
    return bytes(data)


def select_ident(connection) -> bytes:
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(IDENT_INSTANCE_AID)])
    return transmit(connection, apdu + IDENT_INSTANCE_AID)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.strip().split('\n')[0])
    parser.add_argument('--reader', type=int, default=0)
    args = parser.parse_args()

    connection = readers()[args.reader].createConnection()
    connection.connect()

    if select_ident(connection):
        print('Card already has an Identity Certificate; the applet '
              'refuses to replace it.')
        return 1

    ca = ec.derive_private_key(
        int.from_bytes(TEST_CA_PRIVATE_KEY, 'big'), ec.SECP256K1())
    cert, ident_priv = create_certificate(ca)
    data = cert + ident_priv
    transmit(
        connection,
        bytes([CLA_GP, INS_STORE_DATA, 0x00, 0x00, len(data)]) + data,
    )

    stored = select_ident(connection)
    ident_pub, ca_pub = parse_certificate(stored)
    if (
        len(stored) != CERT_LEN or stored != cert
        or ca_pub != compressed(ca.public_key())
    ):
        print(f'Verification failed, card returned: {stored.hex()}')
        return 1

    print(f'Identity Key:   {ident_pub.hex()}')
    print(f'Keycard CA:     {ca_pub.hex()}')
    print(f'Certificate:    {stored.hex()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
