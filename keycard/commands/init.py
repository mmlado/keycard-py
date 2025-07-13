from os import urandom

from ..apdu import APDUResponse
from .. import constants
from ..crypto.aes import aes_cbc_encrypt
from ..crypto.ecc import (
    derive_shared_secret,
    export_uncompressed_public_key,
    generate_ephemeral_keypair,
    parse_uncompressed_public_key,
)
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

    ephemeral_key = generate_ephemeral_keypair()
    our_pubkey_bytes: bytes = export_uncompressed_public_key(ephemeral_key)
    card_pubkey = parse_uncompressed_public_key(card_public_key)
    shared_secret: bytes = derive_shared_secret(ephemeral_key, card_pubkey)

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
