import pytest

from keycard.exceptions import InvalidResponseError
from keycard.parsing.identity import parse

from tests.identity_helpers import TEST_CA_PUBLIC_KEY, make_card_identity


def ber_length(length):
    return bytes([length]) if length < 0x80 else bytes([0x81, length])


def ident_response(certificate, signature_der):
    signature = signature_der[2:]
    inner = (
        b'\x8A' + ber_length(len(certificate)) + certificate
        + b'\x30' + ber_length(len(signature)) + signature
    )
    return b'\xA0' + ber_length(len(inner)) + inner


def test_parse_returns_ca_public_key():
    identity = make_card_identity()
    challenge = bytes(range(32))

    response = ident_response(
        identity.certificate, identity.sign_digest(challenge))

    assert parse(challenge, response) == TEST_CA_PUBLIC_KEY


def test_parse_rejects_signature_over_other_challenge():
    identity = make_card_identity()
    response = ident_response(
        identity.certificate, identity.sign_digest(bytes(32)))

    with pytest.raises(InvalidResponseError, match="signature is invalid"):
        parse(bytes(range(32)), response)


def test_parse_missing_template():
    with pytest.raises(InvalidResponseError, match="Malformed"):
        parse(bytes(32), b'\x80\x01\x00')


def test_parse_missing_signature():
    identity = make_card_identity()
    inner = b'\x8A' + bytes([98]) + identity.certificate
    response = b'\xA0' + ber_length(len(inner)) + inner

    with pytest.raises(InvalidResponseError, match="Malformed"):
        parse(bytes(32), response)


def test_parse_short_certificate():
    identity = make_card_identity()
    response = ident_response(
        identity.certificate[:95], identity.sign_digest(bytes(32)))

    with pytest.raises(InvalidResponseError, match="98 bytes"):
        parse(bytes(32), response)
