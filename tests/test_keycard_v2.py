import pytest

from keycard import constants
from keycard.exceptions import (
    APDUError,
    InvalidResponseError,
    InvalidStateError,
    UntrustedCardError,
)
from keycard.keycard import KeyCard
from keycard.secure_channel import SecureChannelV2, SecureChannelVersion

from tests.identity_helpers import make_card_identity
from tests.v4_card import V4Card

PIN = '123456'
PUK = '123456789012'


def keycard_for(card, **kwargs):
    kwargs.setdefault('ca_public_keys', [constants.TEST_CA_PUBLIC_KEY])
    keycard = KeyCard(card, **kwargs)
    keycard.select()
    return keycard


def test_select_reports_v2():
    keycard = keycard_for(V4Card())

    assert keycard.is_selected
    assert keycard.secure_channel_version == SecureChannelVersion.V2
    assert keycard.card_public_key is None
    assert not keycard.is_initialized


def test_open_secure_channel():
    keycard = keycard_for(V4Card())

    keycard.open_secure_channel()

    assert isinstance(keycard.session, SecureChannelV2)
    assert keycard.is_secure_channel_open


def test_init_opens_channel_and_initializes():
    card = V4Card()
    keycard = keycard_for(card)

    keycard.init(PIN, PUK)

    assert card.inner_apdus == [
        bytes([0x80, 0xFE, 0x00, 0x00, 18]) + PIN.encode() + PUK.encode()]
    assert keycard.is_secure_channel_open
    assert keycard.is_initialized


def test_init_with_retries_and_alt_pin():
    card = V4Card()
    keycard = keycard_for(card)

    keycard.init(PIN, PUK, pin_retries=5, puk_retries=10, alt_pin='654321')

    assert card.inner_apdus[0][5:] == (
        PIN.encode() + PUK.encode() + b'\x05\x0a' + b'654321')


def test_commands_after_init_use_the_channel():
    card = V4Card()
    keycard = keycard_for(card)
    keycard.init(PIN, PUK)

    assert keycard.verify_pin(PIN) is True
    assert keycard.verify_pin('000000') is False
    assert keycard.status['pin_retry_count'] == 3
    assert card.counter == 4


def test_card_error_comes_back_as_apdu_error():
    card = V4Card()
    keycard = keycard_for(card)
    keycard.open_secure_channel()

    with pytest.raises(APDUError) as excinfo:
        keycard.send_secure_apdu(ins=0x99)

    assert excinfo.value.sw == 0x6D00
    assert keycard.is_secure_channel_open


def test_select_closes_the_channel():
    keycard = keycard_for(V4Card())
    keycard.open_secure_channel()

    keycard.select()

    assert not keycard.is_secure_channel_open


def test_untrusted_ca_is_rejected_before_handshake():
    card = V4Card()
    keycard = keycard_for(
        card, ca_public_keys=[constants.OFFICIAL_CA_PUBLIC_KEY])

    with pytest.raises(UntrustedCardError):
        keycard.open_secure_channel()

    assert card.channel is None


def test_default_trust_is_official_ca_only():
    card = V4Card()
    keycard = KeyCard(card)
    keycard.select()

    assert keycard.ca_public_keys == [constants.OFFICIAL_CA_PUBLIC_KEY]
    with pytest.raises(UntrustedCardError):
        keycard.open_secure_channel()


def test_trusted_identity_key_without_trusted_ca():
    card = V4Card(identity=make_card_identity(ca_private_key=12345))
    identity_key = card.identity.certificate[:33]
    keycard = keycard_for(
        card,
        ca_public_keys=[constants.OFFICIAL_CA_PUBLIC_KEY],
        trusted_identity_keys=[identity_key],
    )

    keycard.open_secure_channel()

    assert keycard.is_secure_channel_open


def test_bad_handshake_signature_is_rejected():
    card = V4Card()
    card.sign_transcript = False
    keycard = keycard_for(card)

    with pytest.raises(InvalidResponseError, match='signature is invalid'):
        keycard.open_secure_channel()

    assert not keycard.is_secure_channel_open


def test_pairing_secret_rejected_on_v2():
    keycard = keycard_for(V4Card())

    with pytest.raises(ValueError, match='pairing secret'):
        keycard.init(PIN, PUK, 'KeycardTest')


@pytest.mark.parametrize('method,args', [
    ('pair', (b'secret',)),
    ('unpair', (0,)),
    ('mutually_authenticate', ()),
])
def test_pairing_operations_raise_on_v2(method, args):
    card = V4Card()
    keycard = keycard_for(card)

    with pytest.raises(InvalidStateError, match='Secure Channel V1'):
        getattr(keycard, method)(*args)

    assert card.channel is None


def test_v1_open_requires_pairing():
    keycard = KeyCard(V4Card())
    keycard._application_info = keycard_for(V4Card())._application_info
    keycard._application_info.version_major = 3
    keycard._is_initialized = True

    with pytest.raises(InvalidStateError, match='needs a pairing'):
        keycard.open_secure_channel()


def test_v1_init_requires_pairing_secret():
    keycard = KeyCard(V4Card())
    keycard._application_info = keycard_for(V4Card())._application_info
    keycard._application_info.version_major = 3

    with pytest.raises(ValueError, match='need a pairing secret'):
        keycard.init(PIN, PUK)


def test_get_challenge_before_init():
    card = V4Card()
    keycard = keycard_for(card)
    keycard.open_secure_channel()

    assert keycard.get_challenge(16) == bytes(16)
    assert card.inner_apdus[-1] == bytes([0x80, 0x84, 16, 0x00, 0])
    assert not keycard.is_initialized
