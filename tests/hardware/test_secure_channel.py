import pytest

from keycard import constants
from keycard.exceptions import APDUError, UntrustedCardError
from keycard.keycard import KeyCard
from keycard.secure_channel import SecureChannelVersion, channel_version

pytestmark = pytest.mark.card

PIN = '123456'
PUK = '987654321098'
PAIRING_SECRET = 'KeycardTest'


def test_secure_channel_version_matches_applet(keycard):
    assert keycard.secure_channel_version == channel_version(keycard.version)


def test_open_secure_channel_v2_and_read_status(keycard):
    if keycard.secure_channel_version != SecureChannelVersion.V2:
        pytest.skip('Secure Channel V2 only')

    keycard.open_secure_channel()

    assert keycard.is_secure_channel_open
    if keycard.is_initialized:
        status = keycard.status
        assert status['pin_retry_count'] == (
            keycard._application_info.pin_retries)


def test_untrusted_ca_rejected(keycard):
    if keycard.secure_channel_version != SecureChannelVersion.V2:
        pytest.skip('Secure Channel V2 only')

    untrusted = KeyCard(
        keycard.transport,
        ca_public_keys=[constants.OFFICIAL_CA_PUBLIC_KEY])
    untrusted.select()

    with pytest.raises(UntrustedCardError):
        untrusted.open_secure_channel()


@pytest.mark.destructive
def test_reset_init_and_verify_pin(reset_keycard):
    keycard = reset_keycard
    v2 = keycard.secure_channel_version == SecureChannelVersion.V2

    if v2:
        keycard.init(PIN, PUK, pin_retries=5, puk_retries=10)
    else:
        keycard.init(
            PIN, PUK, PAIRING_SECRET, pin_retries=5, puk_retries=10)
        keycard.select()
        pairing = keycard.pair(PAIRING_SECRET)
        keycard.open_secure_channel()

    assert keycard.is_secure_channel_open
    assert keycard.verify_pin(PIN)
    status = keycard.status
    assert status['pin_retry_count'] == 5
    assert status['puk_retry_count'] == 10

    assert keycard.verify_pin('000000') is False
    assert not keycard.is_pin_verified
    with pytest.raises(APDUError) as excinfo:
        keycard.send_secure_apdu(
            ins=constants.INS_STORE_DATA, data=b'\x01x')
    assert excinfo.value.sw == 0x6985
    assert keycard.verify_pin(PIN)
    assert keycard.is_pin_verified
    keycard.send_secure_apdu(ins=constants.INS_STORE_DATA, data=b'\x01x')

    if not v2:
        keycard.unpair(pairing.slot)

    keycard.select()
    assert keycard.is_initialized
    if v2:
        assert keycard._application_info.pin_retries == 5
        keycard.open_secure_channel()
        assert keycard.verify_pin(PIN)
