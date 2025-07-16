import os

from keycard.keycard import KeyCard
from keycard.transport import Transport

PIN = bytes("123456", 'ascii')
PUK = bytes("123456123456", 'ascii')
PAIRING_PASSWORD = "KeycardTest"

with Transport() as transport:
    card = KeyCard(transport)
    card.select()
    card.factory_reset()

    print(card.select())
    card.init(PIN, PUK, PAIRING_PASSWORD)
    print("Card initialized.")
    print(card.select())

    challenge = os.urandom(32)
    identity = card.ident(challenge)
    print(identity)
    if identity.verify(challenge):
        print('Card verified')
    else:
        print('Card verification failed')


    # # Step 4: PAIR (both steps handled internally)
    print('Pairing....')
    pairing_index, pairing_key = card.pair(PAIRING_PASSWORD)
    print(f"Paired. Index: {pairing_index}")
    print(f"{pairing_key.hex()=}")

    # # Step 5: OPEN SECURE CHANNEL
    card.open_secure_channel(pairing_index, pairing_key)
    print("Secure channel established.")

    card.mutually_authenticate()

    print(card.status)

    # # Step 6: VERIFY PIN
    card.verify_pin(PIN)
    print("PIN verified.")

    # # Step 7: UNPAIR
    card.unpair(pairing_index)
    print(f"Unpaired index {pairing_index}.")
