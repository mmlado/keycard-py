import pytest

from keycard.constants import LoadKeyType
from keycard.exceptions import APDUError
from keycard.secure_channel import SecureChannelVersion

pytestmark = [pytest.mark.card, pytest.mark.destructive]

# BIP-85 test case 1: the master key of its xprv and the entropy at PATH.
PRIVATE_KEY = bytes.fromhex(
    '3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed9')
CHAIN_CODE = bytes.fromhex(
    '1b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c')
PATH = "m/83696968'/0'/0'"
ENTROPY = bytes.fromhex(
    'efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0'
    '0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7')


@pytest.fixture
def bip85_keycard(verified_keycard):
    verified_keycard.load_key(
        LoadKeyType.EXTENDED_ECC,
        private_key=PRIVATE_KEY,
        chain_code=CHAIN_CODE)
    return verified_keycard


def test_export_bip85(bip85_keycard):
    keycard = bip85_keycard

    if keycard.secure_channel_version != SecureChannelVersion.V2:
        with pytest.raises(APDUError) as excinfo:
            keycard.export_bip85(PATH, 64)
        assert excinfo.value.sw == 0x6D00
        assert keycard.status['pin_retry_count'] > 0
        return

    assert keycard.export_bip85(PATH, 64) == ENTROPY
    assert keycard.export_bip85(PATH, 16) == ENTROPY[:16]


@pytest.mark.parametrize('path', ["m/44'/0'/0'", "m/83696968'/0'/0"])
def test_export_bip85_rejects_other_paths(bip85_keycard, path):
    with pytest.raises(APDUError):
        bip85_keycard.export_bip85(path, 32)
