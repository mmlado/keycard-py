import pytest
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)

from keycard.parsing.signature_result import SignatureResult
from keycard.constants import SigningAlgorithm
from unittest import mock


def test_signature_result_with_minimal_r_s():
    r = 1
    s = 1
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=0
    )
    assert sig.r == (1).to_bytes(32, 'big')
    assert sig.s == (1).to_bytes(32, 'big')
    assert len(sig.signature) == 64


def test_signature_result_with_large_r_s():
    r = 2**255
    s = 2**255 - 1
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=2
    )
    assert sig.r == r.to_bytes(32, 'big')
    assert sig.s == s.to_bytes(32, 'big')
    assert sig.recovery_id == 2


def test_signature_result_signature_der_property():
    r = 123
    s = 456
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32

    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=3
    )

    assert sig.signature_der == bytes.fromhex('300702017b020201c8')
    assert decode_dss_signature(sig.signature_der) == (r, s)


def test_signature_result_schnorr_has_no_recovery_id():
    public_key = b'\x04' + b'\x01' * 64
    sig = SignatureResult(
        digest=b'\x01' * 32,
        algo=SigningAlgorithm.SCHNORR_BIP340,
        r=1,
        s=2,
        public_key=public_key
    )
    assert sig.signature == (1).to_bytes(32, 'big') + (2).to_bytes(32, 'big')
    assert sig.public_key == public_key
    assert sig.recovery_id is None


def test_signature_result_schnorr_requires_public_key():
    with pytest.raises(ValueError, match="Public key not returned"):
        SignatureResult(
            digest=b'\x01' * 32,
            algo=SigningAlgorithm.SCHNORR_BIP340,
            r=1,
            s=2
        )


def test_signature_result_repr_exists():
    r = int.from_bytes(b'\x01' * 32, 'big')
    s = int.from_bytes(b'\x01' * 32, 'big')
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=0
    )
    assert isinstance(repr(sig), str)


def test_signature_result_public_key_and_recovery_id_priority():
    r = 5
    s = 6
    digest = b'\x01' * 32
    public_key = b'\x02' + b'\x01' * 32
    sig = SignatureResult(
        digest=digest,
        algo=SigningAlgorithm.ECDSA_SECP256K1,
        r=r,
        s=s,
        public_key=public_key,
        recovery_id=7
    )
    assert sig.public_key == public_key
    assert sig.recovery_id == 7


def test_signature_result_missing_public_key_calls_recover():
    r = 10
    s = 20
    digest = b'\x01' * 32
    with mock.patch.object(
        SignatureResult,
        "_recover_public_key",
        return_value=b'\x02' + b'\x02' * 32
    ) as mock_pubkey:
        sig = SignatureResult(
            digest=digest,
            algo=SigningAlgorithm.ECDSA_SECP256K1,
            r=r,
            s=s,
            public_key=None,
            recovery_id=9
        )
        assert sig.public_key == b'\x02' + b'\x02' * 32
        assert sig.recovery_id == 9
        mock_pubkey.assert_called_once_with(digest)
