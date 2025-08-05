import os

from ecdsa import VerifyingKey, SECP256k1, util
from hashlib import sha256

from keycard import constants
from keycard.exceptions import APDUError
from keycard.keycard import KeyCard
from keycard.transport import Transport

PIN = '123456'
PUK = '123456123456'
PAIRING_PASSWORD = 'KeycardTest'


def verify_ecdsa_secp256k1(
    digest: bytes, signature: bytes, public_key: bytes) -> bool:
    vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
    try:
        return vk.verify(signature[:64], digest, sigdecode=sigdecode_string)
    except Exception:
        return False


with Transport() as transport:
    card = KeyCard(transport)
    card.select()
    print('Retrieving data...')
    retrieved_data = card.get_data(slot=constants.StorageSlot.PUBLIC)
    print(f'Retrieved data: {retrieved_data}')
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

    challenge = os.urandom(32)
    identity = card.ident(challenge)
    print(identity)
    if identity.verify(challenge):
        print('Card verified')
    else:
        print('Card verification failed')


    print('Pairing....')
    pairing_index, pairing_key = card.pair(PAIRING_PASSWORD)
    print(f'Paired. Index: {pairing_index}')
    print(f'{pairing_key.hex()=}')

    card.open_secure_channel(pairing_index, pairing_key)
    print('Secure channel established.')

    card.mutually_authenticate()

    print(card.status)

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
    print(f'Signature: {signature.signature.hex()}')

    vk = VerifyingKey.from_string(exported_key.public_key, curve=SECP256k1)
    try:
        vk.verify_digest(signature.signature, digest, sigdecode=util.sigdecode_der)
        print('Signature verified successfully.')
    except Exception as e:
        print(f"Signature verification failed: {e}")

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
