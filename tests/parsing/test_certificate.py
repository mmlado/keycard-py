import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from keycard.constants import OFFICIAL_CA_PUBLIC_KEY, TEST_CA_PUBLIC_KEY
from keycard.exceptions import InvalidResponseError, UntrustedCardError
from keycard.parsing.certificate import (
    IdentityCertificate,
    compress_public_key,
)

from tests.identity_helpers import make_card_identity

# Certificate read from a development card provisioned with the Test CA.
CARD_CERTIFICATE = bytes.fromhex(
    '0257dad49497614a19a1dc8c53f0c0425dd6710ad4369a0a684041daedde1ae621'
    'abf896e3cd17472c32130e35326d71a0f79cae919333ea976aaa5914ef61f89d'
    '72341acc765027986fd415e5989eed49ad793e1c9e35e831aa4c5605da8817b8'
    '01'
)


def test_parse_fields():
    cert = IdentityCertificate.parse(CARD_CERTIFICATE)

    assert cert.identity_public_key == CARD_CERTIFICATE[:33]
    assert cert.signature == CARD_CERTIFICATE[33:97]
    assert cert.recovery_id == 1


def test_ca_public_key_from_card_certificate():
    cert = IdentityCertificate.parse(CARD_CERTIFICATE)

    assert cert.ca_public_key == TEST_CA_PUBLIC_KEY


@pytest.mark.parametrize('length', [0, 97, 99])
def test_parse_rejects_wrong_length(length):
    with pytest.raises(InvalidResponseError, match="98 bytes"):
        IdentityCertificate.parse(bytes(length))


def test_ca_public_key_rejects_bad_recovery_id():
    cert = IdentityCertificate.parse(CARD_CERTIFICATE[:97] + b'\x05')

    with pytest.raises(InvalidResponseError, match="recover"):
        cert.ca_public_key


def test_check_trust_accepts_trusted_ca():
    cert = IdentityCertificate.parse(make_card_identity().certificate)

    cert.check_trust([OFFICIAL_CA_PUBLIC_KEY, TEST_CA_PUBLIC_KEY])


def test_check_trust_rejects_unknown_ca():
    cert = IdentityCertificate.parse(make_card_identity().certificate)

    with pytest.raises(UntrustedCardError):
        cert.check_trust([OFFICIAL_CA_PUBLIC_KEY])


def test_check_trust_accepts_trusted_identity_key():
    identity = make_card_identity(ca_private_key=12345)
    cert = IdentityCertificate.parse(identity.certificate)

    cert.check_trust(
        [OFFICIAL_CA_PUBLIC_KEY],
        trusted_identity_keys=[cert.identity_public_key]
    )


def test_check_trust_accepts_uncompressed_ca_key():
    cert = IdentityCertificate.parse(make_card_identity().certificate)
    uncompressed = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), TEST_CA_PUBLIC_KEY
    ).public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    cert.check_trust([uncompressed])
    assert compress_public_key(uncompressed) == TEST_CA_PUBLIC_KEY


def test_verify_accepts_identity_signature():
    identity = make_card_identity()
    cert = IdentityCertificate.parse(identity.certificate)
    digest = bytes(range(32))

    cert.verify(digest, identity.sign_digest(digest))


def test_verify_rejects_other_digest():
    identity = make_card_identity()
    cert = IdentityCertificate.parse(identity.certificate)

    with pytest.raises(InvalidResponseError, match="signature is invalid"):
        cert.verify(bytes(range(32)), identity.sign_digest(bytes(32)))
