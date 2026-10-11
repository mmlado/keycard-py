import hmac
from hashlib import sha256, sha512

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from ecdsa import SECP256k1, VerifyingKey
from ecdsa.ellipticcurve import INFINITY

from keycard.constants import LoadKeyType, SigningAlgorithm
from keycard.exceptions import APDUError
from keycard.parsing.lee_keys import LeeKeys
from keycard.secure_channel import SecureChannelVersion

from tests.hardware.conftest import PIN

pytestmark = [pytest.mark.card, pytest.mark.destructive]

SCHNORR = SigningAlgorithm.SCHNORR_BIP340
SEED = bytes(range(64))
DIGEST = sha256(b'keycard-py').digest()
G = SECP256k1.generator
N = SECP256k1.order

# LEZ key_protocol test vectors: master_key_generation, child_keys_generation.
LEE_SEED = bytes.fromhex(
    'fc38cc53e87bd1bcbba727d547273a417d86ff312b6c5c35ada45e8e964a15a3'
    '2b90e257c71281dfb0c605969d46d2fe0e6959bff61b34aa3872272676c5cde1')
LEE_MASTER = LeeKeys(
    ask=bytes.fromhex(
        '65b5bc84148d7ccd3f0c17ee024a57e0bc9b633f0e3c1b7e2f6a6172679e673c'),
    nsk=bytes.fromhex(
        '2ea033724d8129d28cf424435f1160937190435ec699dcce3b3d12343f003366'),
    vsk_d=bytes.fromhex(
        'ef69699b0d59cb64a26c5780415865d9d67ec8332392fbcf4c2cda023371aba7'),
    vsk_z=bytes.fromhex(
        '6b34179e66906b2f8934388f34e16be4981718aca4155c5957af33be22db342f'),
)
LEE_CHILD_42 = LeeKeys(
    ask=bytes.fromhex(
        'b5b269be1c60ae3e419d8285394009f8d057d3b97cc2b594f3193f232641304a'),
    nsk=bytes.fromhex(
        '095f03b99a49b41ff1c18d0df748d2c61d272195ee9d328aa2e346a45da953e7'),
    vsk_d=bytes.fromhex(
        '7aa7eded56a201924f0aa0413d4d0841f1f790996d861407e534f91e206d1770'),
    vsk_z=bytes.fromhex(
        '70a881757fa0496e15a452d5fd870b1ad53578c7fe8f1ca9aabb5c0c2bd9813a'),
)


def is_v2(keycard):
    return keycard.secure_channel_version == SecureChannelVersion.V2


def master_public_key(seed):
    secret = hmac.new(b'Bitcoin seed', seed, sha512).digest()[:32]
    private_key = ec.derive_private_key(
        int.from_bytes(secret, 'big'), ec.SECP256K1())
    return private_key.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)


def verify_ecdsa(result):
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), result.public_key)
    public_key.verify(
        result.signature_der, DIGEST, ec.ECDSA(Prehashed(hashes.SHA256())))


def tagged_hash(tag, data):
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + data).digest()


def lift_x(x):
    return VerifyingKey.from_string(b'\x02' + x, curve=SECP256k1).pubkey.point


def tweak_x(x, tweak):
    point = lift_x(x) + G * int.from_bytes(tweak, 'big')
    return point.x().to_bytes(32, 'big')


def bip340_verify(public_key_x, message, signature):
    r = int.from_bytes(signature[:32], 'big')
    s = int.from_bytes(signature[32:], 'big')
    challenge = tagged_hash(
        'BIP0340/challenge', signature[:32] + public_key_x + message)
    e = int.from_bytes(challenge, 'big') % N
    point = G * s + lift_x(public_key_x) * (N - e)
    return point != INFINITY and point.y() % 2 == 0 and point.x() == r


def test_sign_ecdsa_with_master_key(verified_keycard):
    keycard = verified_keycard
    keycard.load_key(LoadKeyType.BIP39_SEED, bip39_seed=SEED)

    current = keycard.sign(DIGEST)
    master = keycard.sign_with_path(DIGEST, 'm')

    for result in (current, master):
        assert result.public_key == master_public_key(SEED)
        verify_ecdsa(result)


def test_sign_ecdsa_with_path(verified_keycard):
    keycard = verified_keycard
    keycard.load_key(LoadKeyType.BIP39_SEED, bip39_seed=SEED)

    result = keycard.sign_with_path(DIGEST, "m/44'/60'/0'/0/0")

    assert result.public_key != master_public_key(SEED)
    verify_ecdsa(result)


def test_sign_schnorr(verified_keycard):
    keycard = verified_keycard
    keycard.load_key(LoadKeyType.BIP39_SEED, bip39_seed=SEED)
    path = "m/86'/0'/0'/0/0"

    if not is_v2(keycard):
        with pytest.raises(APDUError):
            keycard.sign_with_path(DIGEST, path, algorithm=SCHNORR)
        return

    master = keycard.sign(DIGEST, SCHNORR)
    assert master.public_key == master_public_key(SEED)
    assert bip340_verify(master.public_key[1:33], DIGEST, master.signature)

    plain = keycard.sign_with_path(DIGEST, path, algorithm=SCHNORR)
    x = plain.public_key[1:33]
    assert plain.recovery_id is None
    assert bip340_verify(x, DIGEST, plain.signature)

    tweak = tagged_hash('TapTweak', x)
    tweaked = keycard.sign_with_path(
        DIGEST, path, algorithm=SCHNORR, tweak=tweak)
    assert tweaked.public_key == plain.public_key
    assert bip340_verify(tweak_x(x, tweak), DIGEST, tweaked.signature)
    assert not bip340_verify(x, DIGEST, tweaked.signature)


def test_v2_rejects_removed_derivation_options(verified_keycard):
    keycard = verified_keycard
    if not is_v2(keycard):
        pytest.skip('applet 4.0 only')
    keycard.load_key(LoadKeyType.BIP39_SEED, bip39_seed=SEED)

    with pytest.raises(APDUError):
        keycard.sign_with_path(DIGEST, 'm/0', make_current=True)
    with pytest.raises(APDUError):
        keycard.sign_pinless(DIGEST)


def test_lee_keys(verified_keycard):
    keycard = verified_keycard

    if not is_v2(keycard):
        with pytest.raises(APDUError):
            keycard.load_key(LoadKeyType.LEE_SEED, bip39_seed=LEE_SEED)
        return

    keycard.load_key(LoadKeyType.LEE_SEED, bip39_seed=LEE_SEED)
    reselect(keycard)
    assert keycard._application_info.is_lee_mode

    assert keycard.export_lee() == LEE_MASTER
    assert keycard.export_lee('m/42') == LEE_CHILD_42

    keycard.load_key(LoadKeyType.BIP39_SEED, bip39_seed=LEE_SEED)
    reselect(keycard)
    assert not keycard._application_info.is_lee_mode
    with pytest.raises(APDUError):
        keycard.export_lee()


def reselect(keycard):
    keycard.select()
    keycard.open_secure_channel()
    keycard.verify_pin(PIN)
