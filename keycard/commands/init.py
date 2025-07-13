from os import urandom
from ecdsa import SigningKey, VerifyingKey, ECDH, SECP256k1

from ..apdu import APDUResponse
from .. import constants
from ..crypto.aes import aes_cbc_encrypt
from ..exceptions import APDUError, NotSelectedError


def init(
    transport,
    card_public_key,
    pin: bytes,
    puk: bytes,
    pairing_secret: bytes
) -> None:
    if card_public_key is None:
        raise NotSelectedError("Card not selected. Call select() first.")

    ephemeral_key = SigningKey.generate(curve=SECP256k1)
    our_pubkey_bytes: bytes = ephemeral_key.verifying_key.to_string("uncompressed")
    card_pubkey = VerifyingKey.from_string(card_public_key, curve=SECP256k1)
    ecdh = ECDH(
        curve=SECP256k1,
        private_key=ephemeral_key,
        public_key=card_pubkey
    )
    shared_secret = ecdh.generate_sharedsecret_bytes()

    plaintext: bytes = pin + puk + pairing_secret
    iv: bytes = urandom(16)
    ciphertext: bytes = aes_cbc_encrypt(shared_secret, iv, plaintext)
    data: bytes = (
        bytes([len(our_pubkey_bytes)])
        + our_pubkey_bytes
        + iv
        + ciphertext
    )

    if len(data) > 255:
        raise ValueError("Data too long for single APDU")

    apdu: bytes = (
        bytes([
            constants.CLA_PROPRIETARY,
            constants.INS_INIT,
            0x00,
            0x00,
            len(data),
        ])
        + data
    )

    response: APDUResponse = transport.send_apdu(apdu)

    if response.status_word != constants.SW_SUCCESS:
        raise APDUError(response.status_word)
