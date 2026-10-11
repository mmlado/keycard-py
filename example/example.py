"""
Walks through the Keycard commands on applet 3.x or 4.x.

WARNING: this factory-resets the card. Use a test card.
"""
import hashlib
import hmac
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from mnemonic import Mnemonic

from keycard import KeyCard, constants
from keycard.constants import (
    DerivationOption,
    LoadKeyType,
    SigningAlgorithm,
    StorageSlot,
)
from keycard.exceptions import APDUError
from keycard.secure_channel import SecureChannelVersion

PIN = '123456'
# Without an Alternate PIN the card uses the PUK's first 6 digits as one.
PUK = '987654321098'
PAIRING_PASSWORD = 'KeycardTest'
MNEMONIC = (
    'gravity machine north sort system female '
    'filter attitude volume fold club stay'
)
NIP44_PATH = "m/44'/1237'/0'/0/0"


def bip32_master_key(seed: bytes) -> tuple[bytes, bytes]:
    digest = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def uncompressed(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)


def get_uncompressed_pubkey(priv_key_bytes: bytes) -> bytes:
    key = ec.derive_private_key(
        int.from_bytes(priv_key_bytes, 'big'), ec.SECP256K1())
    return uncompressed(key.public_key())


def verify(public_key: bytes, signature_der: bytes, digest: bytes) -> None:
    ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), public_key
    ).verify(signature_der, digest, ec.ECDSA(Prehashed(hashes.SHA256())))


def check(label: str, ok: bool) -> None:
    print(f'{label}: {"OK" if ok else "MISMATCH"}')


# Development cards carry a Test CA certificate; trust it only for testing.
card = KeyCard(ca_public_keys=[
    constants.OFFICIAL_CA_PUBLIC_KEY,
    constants.TEST_CA_PUBLIC_KEY,
])

with card:
    print(card.select())
    v4 = card.secure_channel_version == SecureChannelVersion.V2
    print(f'Applet {card.version}, Secure Channel {"V2" if v4 else "V1"}')

    if card.is_initialized:
        print('Factory resetting card...')
        card.factory_reset()
        print(card.select())

    print('Initializing...')
    pairing = None
    if v4:
        # Opens the secure channel, checking the Identity Certificate.
        card.init(PIN, PUK)
    else:
        card.init(PIN, PUK, PAIRING_PASSWORD)
        print(card.select())

        try:
            ca_public_key = card.ident()
            print(f'Keycard CA public key: {ca_public_key.hex()}')
        except APDUError as e:
            print(f'IDENT failed, no Identity Certificate: {e}')

        print('Pairing...')
        pairing = card.pair(PAIRING_PASSWORD)
        print(f'Paired. Slot: {pairing.slot}')
        card.open_secure_channel()
    print('Secure channel established.')

    print(card.status)

    print('Generating mnemonic...')
    indexes = card.generate_mnemonic()
    wordlist = Mnemonic('english').wordlist
    print('Mnemonic:', ' '.join(wordlist[i] for i in indexes))

    print('Blocking and unblocking the PIN...')
    for _ in range(2):
        print(f'Wrong PIN accepted: {card.verify_pin("654321")}')
    try:
        card.verify_pin('654321')
    except RuntimeError as e:
        print(f'PIN verification failed: {e}')
    card.unblock_pin(PUK, PIN)
    print('PIN unblocked.')

    card.verify_pin(PIN)
    print('PIN verified.')

    print('Storing a long NDEF record...')
    # 221 bytes: two STORE DATA chunks, still a single GET DATA on 3.x.
    message = b'\xAA' * 219
    ndef = len(message).to_bytes(2, 'big') + message
    card.store_data(ndef, StorageSlot.NDEF)
    check('NDEF read back', card.get_data(StorageSlot.NDEF) == ndef)

    print('Generating key...')
    key_uid = card.generate_key()
    print(f'Key UID: {key_uid.hex()}')

    exported_key = card.export_current_key(public_only=True)
    print(f'Master public key: {exported_key.public_key.hex()}')
    check('Key UID', sha256(exported_key.public_key).digest() == key_uid)

    digest = sha256(b'This is a test message.').digest()
    print('Signing with the master key...')
    signature = card.sign(digest)
    verify(exported_key.public_key, signature.signature_der, digest)
    print('Signature verified.')

    print('Signing with a derived key...')
    path = "m/44'/60'/0'/0/0"
    signature = card.sign_with_path(digest, path)
    derived_key = card.export_key(
        DerivationOption.DERIVE, public_only=True, keypath=path)
    verify(derived_key.public_key, signature.signature_der, digest)
    print('Signature verified.')

    if v4:
        print('Signing with Schnorr (BIP-340)...')
        tweak = sha256(b'example tweak').digest()
        signature = card.sign_with_path(
            digest,
            "m/86'/0'/0'/0/0",
            algorithm=SigningAlgorithm.SCHNORR_BIP340,
            tweak=tweak,
        )
        print(f'Schnorr signature: {signature.signature.hex()}')
    else:
        print('Signing with the PIN-less path...')
        card.set_pinless_path(path)
        signature = card.sign_pinless(digest)
        verify(derived_key.public_key, signature.signature_der, digest)
        print('Signature verified.')

    print('Loading a key pair...')
    sk = ec.generate_private_key(ec.SECP256K1())
    public_key = uncompressed(sk.public_key())
    key_uid = card.load_key(
        key_type=LoadKeyType.ECC,
        public_key=public_key,
        private_key=sk.private_numbers().private_value.to_bytes(32, 'big')
    )
    check('Key UID', key_uid == sha256(public_key).digest())

    print('Loading a key from the mnemonic...')
    seed = Mnemonic.to_seed(MNEMONIC, passphrase='')
    master_priv_key, _ = bip32_master_key(seed)
    key_uid = card.load_key(
        key_type=LoadKeyType.BIP39_SEED,
        bip39_seed=seed
    )
    check(
        'Key UID',
        key_uid == sha256(get_uncompressed_pubkey(master_priv_key)).digest())

    if v4:
        print(f'Card random bytes: {card.get_challenge(32).hex()}')

        entropy = card.export_bip85("m/83696968'/39'/0'/12'/0'", 16)
        print('BIP-85 mnemonic:', Mnemonic('english').to_mnemonic(entropy))

        print('ECDH...')
        peer = ec.generate_private_key(ec.SECP256K1())
        secret = card.ecdh(uncompressed(peer.public_key()), NIP44_PATH)
        card_key = card.export_key(
            DerivationOption.DERIVE, public_only=True, keypath=NIP44_PATH)
        check('Shared secret', secret == peer.exchange(
            ec.ECDH(),
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), card_key.public_key)))

        print('Loading the seed in LEE mode...')
        card.load_key(LoadKeyType.LEE_SEED, bip39_seed=seed)
        lee_keys = card.export_lee("m/0'")
        print(f'LEE ASK: {lee_keys.ask.hex()}')
    else:
        print('Deriving key...')
        card.derive_key(path)

    card.change_pin(PIN)
    print('PIN changed.')

    card.change_puk(PUK)
    print('PUK changed.')

    if not v4:
        card.change_pairing_secret(PAIRING_PASSWORD)
        print('Pairing secret changed.')

    print('Storing public data...')
    data = b'This is some test data.'
    card.store_data(data, slot=StorageSlot.PUBLIC)
    check('Public data', card.get_data(slot=StorageSlot.PUBLIC) == data)

    print('Removing key...')
    card.remove_key()
    print('Key removed.')

    if pairing is not None:
        card.unpair(pairing.slot)
        print(f'Unpaired slot {pairing.slot}.')
