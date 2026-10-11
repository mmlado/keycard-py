import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from keycard.constants import DerivationOption, LoadKeyType
from keycard.exceptions import APDUError
from keycard.secure_channel import SecureChannelVersion

pytestmark = [pytest.mark.card, pytest.mark.destructive]

SEED = bytes(range(64))
NIP44_PATH = "m/44'/1237'/0'/0/0"
EIP1581_PATH = "m/43'/60'/1581'/0'/0"


@pytest.fixture
def ecdh_keycard(verified_keycard):
    verified_keycard.load_key(LoadKeyType.BIP39_SEED, bip39_seed=SEED)
    return verified_keycard


@pytest.fixture
def peer():
    return ec.generate_private_key(ec.SECP256K1())


def public_bytes(key):
    return key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)


def require_v2(keycard):
    if keycard.secure_channel_version != SecureChannelVersion.V2:
        pytest.skip('applet 4.0 only')


@pytest.mark.parametrize('path', [NIP44_PATH, EIP1581_PATH])
def test_ecdh_matches_peer_side(ecdh_keycard, peer, path):
    keycard = ecdh_keycard

    if keycard.secure_channel_version != SecureChannelVersion.V2:
        with pytest.raises(APDUError) as excinfo:
            keycard.ecdh(public_bytes(peer), path)
        assert excinfo.value.sw == 0x6D00
        return

    card_public_key = keycard.export_key(
        DerivationOption.DERIVE, public_only=True, keypath=path).public_key
    expected = peer.exchange(
        ec.ECDH(),
        ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), card_public_key))

    assert keycard.ecdh(public_bytes(peer), path) == expected


@pytest.mark.parametrize('path', [
    "m/44'/60'/0'/0/0",
    "m/44'/1237'/0'/0",
])
def test_ecdh_rejects_other_paths(ecdh_keycard, peer, path):
    require_v2(ecdh_keycard)

    with pytest.raises(APDUError) as excinfo:
        ecdh_keycard.ecdh(public_bytes(peer), path)
    assert excinfo.value.sw == 0x6985


def test_ecdh_rejects_point_off_curve(ecdh_keycard):
    require_v2(ecdh_keycard)

    with pytest.raises(APDUError) as excinfo:
        ecdh_keycard.ecdh(b'\x04' + bytes(64), NIP44_PATH)
    assert excinfo.value.sw == 0x6A80
