import os

from keycard.exceptions import APDUError
from keycard.keycard import KeyCard
from keycard.transport import Transport

PIN = bytes('123456', 'ascii')
PUK = bytes('123456123456', 'ascii')
PAIRING_PASSWORD = 'KeycardTest'

with Transport() as transport:
    card = KeyCard(transport)
    card.select()
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
    card.verify_pin(b'654321')
    card.verify_pin(b'654321')
    try:
        card.verify_pin(b'654321')
    except RuntimeError as e:
        print(f'PIN verification failed: {e}')
    card.unblock_pin(PUK, PIN)
    print('PIN unblocked.')

    card.verify_pin(PIN)
    print('PIN verified.')

    print('Generating key...')
    key = card.generate_key()
    print(f'Generated key: {key.hex()}')

    card.change_pin(PIN)
    print('PIN changed.')
    
    card.change_puk(PUK)
    print('PUK changed.')
    
    card.change_pairing_secret(PAIRING_PASSWORD)
    print('Pairing secret changed.')

    print('Removing key...')
    card.remove_key()
    print('Key removed.')

    print('Unpairing...')
    card.unpair(pairing_index)
    print(f'Unpaired index {pairing_index}.')
