import pytest
from keycard.parsing.identity import Identity
from keycard.exceptions import InvalidResponseError
from ecdsa import BadSignatureError


def test_identity_str():
    cert = b'\x02' * 33
    sig = b'\x00' * 70
    identity = Identity(certificate=cert, signature=sig)
    s = str(identity)
    assert 'Identity(certificate=' in s
    assert cert.hex() in s
    assert sig.hex() in s


def test_verify_certificate_too_short():
    identity = Identity(certificate=b'\x01\x02', signature=b'\x00' * 70)
    with pytest.raises(
        InvalidResponseError,
        match='Certificate too short'
    ):
        identity.verify(b'challenge')


def test_parse_missing_certificate_or_signature():
    # TLV with missing certificate and signature
    data = b'\xa0\x06\x8b\x01\x00\x30\x01\x00'
    with pytest.raises(
        InvalidResponseError,
        match='Missing certificate or signature'
    ):
        Identity.parse(data)


def test_parse_valid(monkeypatch):
    # Patch parse_tlv to return expected structure
    cert = b'\x02' * 33
    sig = b'\x00' * 70

    def fake_parse_tlv(data):
        if data == b'data':
            return {0xA0: [b'inner']}
        elif data == b'inner':
            return {0x8a: [cert], 0x30: [sig]}
        return {}

    monkeypatch.setattr('keycard.parsing.identity.parse_tlv', fake_parse_tlv)
    identity = Identity.parse(b'data')
    assert identity.certificate == cert
    assert identity.signature == sig


def test_verify_invalid_signature(monkeypatch):
    cert = b'\x02' + b'\x01' * 32
    sig = b'\x00' * 70
    identity = Identity(certificate=cert, signature=sig)

    class FakeVerifyingKey:
        def verify(self, *args, **kwargs):
            raise BadSignatureError()

    monkeypatch.setattr(
        'keycard.parsing.identity.VerifyingKey', type('VK', (), {
            'from_public_point': staticmethod(
                lambda *a, **kw: FakeVerifyingKey()
            )
        })
    )
    assert not identity.verify(b'challenge')


def test_verify_valid_signature(monkeypatch):
    cert = b'\x02' + b'\x01' * 32
    sig = b'\x00' * 70
    identity = Identity(certificate=cert, signature=sig)

    class FakeVerifyingKey:
        def verify(self, *args, **kwargs):
            return True

    monkeypatch.setattr(
        'keycard.parsing.identity.VerifyingKey', type('VK', (), {
            'from_public_point': staticmethod(
                lambda *a, **kw: FakeVerifyingKey()
            )
        })
    )
    assert identity.verify(b'challenge')
