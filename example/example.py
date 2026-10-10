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

from keycard import constants
from keycard.exceptions import APDUError
from keycard import KeyCard

PIN = '123456'
PUK = '123456123456'
PAIRING_PASSWORD = 'KeycardTest'


def bip32_master_key(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_priv_key = I[:32]
    master_chain_code = I[32:]
    return master_priv_key, master_chain_code


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


with KeyCard() as card:
    card.select()
    print('Retrieving data...')
    retrieved_data = card.get_data(slot=constants.StorageSlot.PUBLIC)
    print(f'Retrieved data: {retrieved_data.hex()}')
    try:
        print('Factory resetting card...')
        card.factory_reset()
    except APDUError as e:
        print(f'Factory reset failed: {e}')
    else:
        print(card.select())

    card.init(PIN, PUK, PAIRING_PASSWORD)
    print('Card initialized.')
    print(card.select())

    print('Identifying...')
    ident_public_key = card.ident()
    print(f'Identity public key: {ident_public_key.hex()}')

    print('Pairing...')
    pairing_index, pairing_key = card.pair(PAIRING_PASSWORD)
    print(f'Paired. Index: {pairing_index}')
    print(f'{pairing_key.hex()=}')

    card.open_secure_channel(pairing_index, pairing_key)
    print('Secure channel established.')

    print(card.status)

    print("Generating mnemonic")
    indexes = card.generate_mnemonic()
    print("Generated list: ", ", ".join(str(m) for m in indexes))
    mnemo = Mnemonic("english")
    words = [mnemo.wordlist[i] for i in indexes]
    print("Mnemonic: ", " ".join(words))

    print('Unblocking PIN...')
    card.verify_pin('654321')
    card.verify_pin('654321')
    try:
        card.verify_pin('654321')
    except RuntimeError as e:
        print(f'PIN verification failed: {e}')
    card.unblock_pin(PUK, PIN)
    print('PIN unblocked.')

    card.verify_pin(PIN)
    print('PIN verified.')

    print('Store long NDEF')
    # 221 bytes: two STORE DATA chunks, still a single GET DATA on 3.x.
    message = b'\xAA' * 219
    ndef = len(message).to_bytes(2, 'big') + message
    print(f'Writing NDEF: {ndef.hex()}')
    card.store_data(ndef, constants.StorageSlot.NDEF)
    print('Data written. Reading...')
    read_ndef = card.get_data(constants.StorageSlot.NDEF)
    print(f'Received NDEF: {read_ndef.hex()}')
    if ndef == read_ndef:
        print('Read NDEF the same as stored')
    else:
        print('NDEF data not the same')
    
    print('Generating key...')
    key = b'0x04' + card.generate_key()
    print(f'Generated key: {key.hex()}')

    print('Exporting key...')
    exported_key = card.export_current_key(True)
    print(f'Exported key: {exported_key.public_key.hex()}')
    if exported_key.private_key:
        print(f'Private key: {exported_key.private_key.hex()}')
    if exported_key.chain_code:
        print(f'Chain code: {exported_key.chain_code.hex()}')

    digest = sha256(b'This is a test message.').digest()
    print(f'Digest: {digest.hex()}')
    signature = card.sign(digest)
    print(f'Signature: {signature}')

    try:
        verify(exported_key.public_key, signature.signature_der, digest)
        print('Signature verified successfully.')
    except Exception as e:
        print(f"Signature verification failed: {e}")

    print("Set pinless path...")
    card.set_pinless_path("m/44'/60'/0'/0/0")
    
    print("Sign with pinless path...")
    print(f'Digest: {digest.hex()}')
    signature = card.sign_pinless(digest)
    print(f'Signature: {signature}')
    
    exported_key = card.export_key(
        derivation_option=constants.DerivationOption.DERIVE,
        public_only=True,
        keypath="m/44'/60'/0'/0/0"
    )

    try:
        verify(exported_key.public_key, signature.signature_der, digest)
        print('Signature verified successfully.')
    except Exception as e:
        print(f"Signature verification failed: {e}")

    print("Load key...")
    sk = ec.generate_private_key(ec.SECP256K1())
    public_key = uncompressed(sk.public_key())

    result = card.load_key(
        key_type=constants.LoadKeyType.ECC,
        public_key=public_key,
        private_key=sk.private_numbers().private_value.to_bytes(32, 'big')
    )

    uid = sha256(public_key).digest()
    if (result == uid):
        print("Received public key hash is the same")
    else:
        print("Received public key hash is not the same")
    
    print("Loading key from mnemonic...")
    mnemonic = ( 
        "gravity machine north sort system female "
        "filter attitude volume fold club stay"
    )
    passphrase = ""
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic, passphrase)

    master_priv_key, master_chain_code = bip32_master_key(seed)
    pubkey = get_uncompressed_pubkey(master_priv_key)
    uid = hashlib.sha256(pubkey).digest()

    result = card.load_key(
        key_type=constants.LoadKeyType.BIP39_SEED,
        bip39_seed=seed
    )
    
    if (result == uid):
        print("Received public key hash is the same")
    else:
        print("Received public key hash is not the same")

    print("Deriving key...")
    card.derive_key("m/44'/60'/0'/0/0")

    card.change_pin(PIN)
    print('PIN changed.')
    
    card.change_puk(PUK)
    print('PUK changed.')
    
    card.change_pairing_secret(PAIRING_PASSWORD)
    print('Pairing secret changed.')
    
    print('Storing data...')
    data = b'This is some test data.'
    card.store_data(data, slot=constants.StorageSlot.PUBLIC)
    print('Data stored.')
    
    print('Retrieving data...')
    retrieved_data = card.get_data(slot=constants.StorageSlot.PUBLIC)
    print(f'Retrieved data: {retrieved_data}')

    print('Removing key...')
    card.remove_key()
    print('Key removed.')

    print('Unpairing...')
    card.unpair(pairing_index)
    print(f'Unpaired index {pairing_index}.')
