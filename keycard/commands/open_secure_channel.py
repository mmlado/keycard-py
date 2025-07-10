from ecdsa import SigningKey, VerifyingKey, SECP256k1, ECDH

from ..apdu import APDUResponse
from .. import constants
from ..exceptions import APDUError, NotSelectedError
from ..secure_channel import SecureSession

def open_secure_channel(
    transport,
    card_public_key,
    pairing_index: int,
    pairing_key: bytes
) -> None:
    if not card_public_key:
        raise NotSelectedError("Card not selected or missing public key")

    ephemeral_key = SigningKey.generate(curve=SECP256k1)
    eph_pub_bytes = ephemeral_key.verifying_key.to_string("uncompressed")
    print(f"{eph_pub_bytes.hex()=}")
    response: APDUResponse = transport.send_apdu(
        bytes([
            constants.CLA_PROPRIETARY,
            constants.INS_OPEN_SECURE_CHANNEL,
            pairing_index,
            0x00,
            len(eph_pub_bytes)
        ]) + eph_pub_bytes
    )
    
    if response.status_word != 0x9000:
        raise APDUError(response.status_word)

    salt = bytes(response.data[:32])
    print(f"{salt.hex()=}")
    seed_iv = bytes(response.data[32:])
    print(f"{seed_iv.hex()=}")


    public_key = VerifyingKey.from_string(card_public_key, curve=SECP256k1)
    ecdh = ECDH(
        curve=SECP256k1, 
        private_key=ephemeral_key, 
        public_key=public_key
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    return SecureSession.open(
        shared_secret,
        pairing_key,
        salt,
        seed_iv,
    )
