import pytest
from keycard.commands.sign import sign
from keycard import constants
from keycard.exceptions import InvalidStateError
from keycard.parsing.keypath import KeyPath


def test_sign_current_key(card):
    digest = b'\xAA' * 32
    raw = b'\x01' * 64 + b'\x1f'
    encoded = b'\x80' + bytes([len(raw)]) + raw
    card.send_secure_apdu.return_value = encoded

    result = sign(card, digest)

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_SIGN,
        p1=constants.DerivationOption.CURRENT,
        p2=constants.SigningAlgorithm.ECDSA_SECP256K1,
        data=digest,
    )
    assert result.signature == raw
    assert result.recovery_id == 0x1f


def test_sign_with_derivation_path(card):
    digest = bytes(32)
    raw = bytes(65)
    encoded = b'\x80' + bytes([len(raw)]) + raw
    card.send_secure_apdu.return_value = encoded

    key_path = KeyPath("m/44'/60'/0'/0/0")
    result = sign(
        card,
        digest,
        p1=constants.DerivationOption.DERIVE,
        derivation_path=key_path.to_string()
    )

    expected_data = digest + key_path.data

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_SIGN,
        p1=constants.DerivationOption.DERIVE,
        p2=constants.SigningAlgorithm.ECDSA_SECP256K1,
        data=expected_data,
    )
    assert result.recovery_id == 0x00


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
