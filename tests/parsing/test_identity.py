import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from keycard.parsing.identity import parse, InvalidResponseError
from keycard.parsing import identity


def make_tlv(tag, value):
    return bytes([tag, len(value)]) + value


def fake_parse_tlv(data):
    if data == b'outer':
        return {0xA0: [b'inner']}
    elif data == b'inner':
        return {0x8A: [b'cert'], 0x30: [b'sig']}
    return {}


def test_parse_success(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data:
            {0xA0: [b'inner']} if data == b'data'
            else {0x8A: [b'c'*95], 0x30: [b's'*64]})
    monkeypatch.setattr(
        identity,
        "_verify",
        lambda certificate, signature, challenge: None
    )
    monkeypatch.setattr(
        identity,
        "_recover_public_key",
        lambda certificate: b'pubkey'
    )

    challenge = b'challenge'
    data = b'data'
    result = parse(challenge, data)
    assert result == b'pubkey'


def test_parse_malformed_index(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data: {0xA0: [b'inner']} if data == b'data' else {}
    )
    challenge = b'challenge'
    data = b'data'
    with pytest.raises(
        InvalidResponseError,
        match="Malformed identity response"
    ):
        parse(challenge, data)


def test_parse_certificate_too_short(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data:
            {0xA0: [b'inner']} if data == b'data'
            else {0x8A: [b'c'*10], 0x30: [b's'*64]}
    )
    challenge = b'challenge'
    data = b'data'
    with pytest.raises(
        InvalidResponseError,
        match="Malformed identity response"
    ):
        parse(challenge, data)


def test_parse_signature_too_short(monkeypatch):
    monkeypatch.setattr(
        identity,
        "parse_tlv",
        lambda data:
            {0xA0: [b'inner']} if data == b'data'
            else {0x8A: [b'c'*95], 0x30: [b's'*10]})
    challenge = b'challenge'
    data = b'data'
    with pytest.raises(
        InvalidResponseError,
        match="Malformed identity response"
    ):
        parse(challenge, data)


def _identity_key_and_signature(challenge):
    key = ec.generate_private_key(ec.SECP256K1())
    public_key = key.public_key().public_bytes(
        Encoding.X962, PublicFormat.CompressedPoint)
    signature = key.sign(challenge, ec.ECDSA(Prehashed(hashes.SHA256())))
    return public_key, signature


def test_verify_accepts_valid_signature():
    challenge = bytes(range(32))
    public_key, signature = _identity_key_and_signature(challenge)

    identity._verify(public_key + bytes(65), signature, challenge)


def test_verify_rejects_invalid_signature():
    challenge = bytes(range(32))
    public_key, signature = _identity_key_and_signature(challenge)

    with pytest.raises(InvalidResponseError, match="signature is invalid"):
        identity._verify(public_key + bytes(65), signature, bytes(32))
