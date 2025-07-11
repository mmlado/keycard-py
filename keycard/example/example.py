import hashlib
import unicodedata
from keycard.keycard import KeyCard
from keycard.transport import Transport

PIN = bytes("123456", 'ascii')
PUK = bytes("123456123456", 'ascii')
PAIRING_PASSWORD = "KeycardTest"

with Transport() as transport:
    card = KeyCard(transport)
    print(card.select())
    transport.send_apdu(bytes([0x80, 0xFD, 0xAA, 0x55]))

    # Step 1: IDENT (optional but recommended)
    # challenge = os.urandom(32)
    # identity = card.ident(challenge)
    # assert identity.verify(challenge)
    # print("Card identity verified.")
    # transport.send_apdu(bytes([0x80, 0xFD, 0xAA, 0x55]))
    # Step 2: INIT
    # exit()
    print(card.select())
    def generate_pairing_token(passphrase: str) -> bytes:
        norm_pass = unicodedata.normalize("NFKD", passphrase).encode("utf-8")
        salt = unicodedata.normalize("NFKD", "Keycard Pairing Password Salt").encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", norm_pass, salt, 50000, dklen=32)
    shared_secret = generate_pairing_token(PAIRING_PASSWORD)
    # print(f"{shared_secret.hex()=}")
    card.init(PIN, PUK, shared_secret)
    print("Card initialized.")
    print(card.select())
    
    # challenge = os.urandom(32)
    # identity = card.ident(challenge)
    # identity.verify(challenge)

    # keypair = SigningKey.generate(curve=SECP256k1)

    # # Step 4: PAIR (both steps handled internally)
    print('Pairing....')
    pairing_index, pairing_key = card.pair(shared_secret)
    # pairing_index, pairing_key = 0, bytes.fromhex("e6984050429656efef8a72f94ef9d51c77c9077a40db16302c00294564d541d1")
    print(f"Paired. Index: {pairing_index}")
    print(f"{pairing_key.hex()=}")

    # # Step 5: OPEN SECURE CHANNEL
    card.open_secure_channel(pairing_index, pairing_key)
    print("Secure channel established.")
    
    card.mutually_authenticate()

    # # Step 6: VERIFY PIN
    card.verify_pin(PIN)
    print("PIN verified.")

    # # Step 7: UNPAIR
    # card.unpair(pairing_index)
    # print(f"Unpaired index {pairing_index}.")
    
    # transport.send_apdu(bytes([0x80, 0xFD, 0xAA, 0x55]))