import sys
import pytest

from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from keycard.commands.sign import sign
from keycard import constants
from keycard.exceptions import InvalidStateError
from keycard.parsing.keypath import KeyPath

SCHNORR = constants.SigningAlgorithm.SCHNORR_BIP340
PUBLIC_KEY = b'\x04' + b'\x11' * 64


def signature_template(*elements):
    inner = b''.join(elements)
    return b'\xA0\x81' + bytes([len(inner)]) + inner


def test_sign_current_key(card):
    sign_module = sys.modules['keycard.commands.sign']
    digest = b'\xAA' * 32
    raw = b'\x01' * 64 + b'\x1f'
    encoded = b'\x80' + bytes([len(raw)]) + raw
    card.send_secure_apdu.return_value = encoded
    card.version = (3, 2)
    with mock.patch.object(sign_module, "SignatureResult"):
        sign(card, digest)

        card.send_secure_apdu.assert_called_once_with(
            ins=constants.INS_SIGN,
            p1=constants.DerivationOption.CURRENT,
            p2=constants.SigningAlgorithm.ECDSA_SECP256K1,
            data=digest,
        )


def test_sign_with_derivation_path(card):
    sign_module = sys.modules['keycard.commands.sign']
    digest = bytes(32)
    raw = bytes(65)
    encoded = b'\x80' + bytes([len(raw)]) + raw
    card.send_secure_apdu.return_value = encoded
    key_path = KeyPath("m/44'/60'/0'/0/0")
    expected_data = digest + key_path.data

    with mock.patch.object(sign_module, "SignatureResult"):
        sign(
            card,
            digest,
            p1=constants.DerivationOption.DERIVE,
            derivation_path=key_path.to_string()
        )

        card.send_secure_apdu.assert_called_once_with(
            ins=constants.INS_SIGN,
            p1=constants.DerivationOption.DERIVE,
            p2=constants.SigningAlgorithm.ECDSA_SECP256K1,
            data=expected_data,
        )


def test_sign_requires_pin(card):
    card.is_pin_verified = False
    digest = b'\xCC' * 32

    with pytest.raises(
        InvalidStateError,
        match="PIN must be verified to sign with this derivation option"
    ):
        sign(card, digest)


def test_sign_short_digest(card):
    short_digest = b'\xDD' * 10

    with pytest.raises(ValueError, match="Digest must be exactly 32 bytes"):
        sign(card, short_digest)


def test_sign_missing_path(card):
    digest = b'\xEE' * 32

    with pytest.raises(ValueError, match="Derivation path cannot be empty"):
        sign(
            card,
            digest,
            p1=constants.DerivationOption.DERIVE,
            derivation_path=None
        )


def test_sign_not_implemented_algo(card):
    digest = b'\xAB' * 32

    with pytest.raises(
        NotImplementedError,
        match="Signature algorithm 255 not supported"
    ):
        sign(card, digest, p2=0xFF)


def test_sign_raw_signature_wrong_length(card):
    digest = b'\xCC' * 32
    raw = b'\x01' * 64  # Should be 65 bytes
    encoded = b'\x80' + bytes([len(raw)]) + raw
    card.send_secure_apdu.return_value = encoded
    card.is_pin_verified = True
    card.version = (3, 2)
    with pytest.raises(ValueError, match="Expected 65-byte raw signature"):
        sign(card, digest)


def test_sign_current_key_on_v2_uses_master_key(card):
    sign_module = sys.modules['keycard.commands.sign']
    digest = b'\xAA' * 32
    card.version = (4, 0)
    card.send_secure_apdu.return_value = b'\x80\x41' + bytes(65)

    with mock.patch.object(sign_module, "SignatureResult"):
        sign(card, digest)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_SIGN,
        p1=constants.DerivationOption.DERIVE,
        p2=constants.SigningAlgorithm.ECDSA_SECP256K1,
        data=digest,
    )


def test_sign_master_path_sends_empty_path(card):
    sign_module = sys.modules['keycard.commands.sign']
    digest = b'\xAA' * 32
    card.send_secure_apdu.return_value = b'\x80\x41' + bytes(65)

    with mock.patch.object(sign_module, "SignatureResult"):
        sign(
            card,
            digest,
            p1=constants.DerivationOption.DERIVE,
            derivation_path='m'
        )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_SIGN,
        p1=constants.DerivationOption.DERIVE,
        p2=constants.SigningAlgorithm.ECDSA_SECP256K1,
        data=digest,
    )


def test_sign_ecdsa_v2_template(card):
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    digest = b'\x42' * 32
    der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    card.version = (4, 0)
    card.send_secure_apdu.return_value = signature_template(
        b'\x80\x41' + public_key, der)

    result = sign(card, digest)

    assert result.public_key == public_key
    assert result.signature_der == der
    assert len(result.signature) == 64
    assert result.recovery_id in (0, 1)


@pytest.mark.parametrize('tweak', [None, b'\x07' * 32])
def test_sign_schnorr_sends_tweak_before_path(card, tweak):
    digest = b'\xAA' * 32
    path = KeyPath("m/86'/0'/0'/0/0")
    signature = b'\x00' + b'\x22' * 31 + b'\x33' * 32
    card.send_secure_apdu.return_value = signature_template(
        b'\x80\x41' + PUBLIC_KEY, b'\x88\x40' + signature)

    result = sign(
        card,
        digest,
        p1=constants.DerivationOption.DERIVE,
        p2=SCHNORR,
        derivation_path=path.to_string(),
        tweak=tweak
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_SIGN,
        p1=constants.DerivationOption.DERIVE,
        p2=SCHNORR,
        data=digest + (tweak or bytes(32)) + path.data,
    )
    assert result.algo == SCHNORR
    assert result.signature == signature
    assert result.public_key == PUBLIC_KEY
    assert result.recovery_id is None


def test_sign_schnorr_short_signature(card):
    card.send_secure_apdu.return_value = signature_template(
        b'\x80\x41' + PUBLIC_KEY, b'\x88\x3F' + bytes(63))

    with pytest.raises(ValueError, match="64-byte Schnorr signature"):
        sign(card, bytes(32), p1=constants.DerivationOption.DERIVE,
             p2=SCHNORR, derivation_path='m')


def test_sign_schnorr_tweak_wrong_length(card):
    with pytest.raises(ValueError, match="Tweak must be exactly 32 bytes"):
        sign(card, bytes(32), p2=SCHNORR, tweak=bytes(31))
    card.send_secure_apdu.assert_not_called()


def test_sign_ecdsa_rejects_tweak(card):
    with pytest.raises(ValueError, match="only used with Schnorr"):
        sign(card, bytes(32), tweak=bytes(32))
    card.send_secure_apdu.assert_not_called()
