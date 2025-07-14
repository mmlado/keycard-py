import hashlib
from os import urandom

from .. import constants
from ..crypto.generate_pairing_token import generate_pairing_token
from ..exceptions import APDUError, InvalidResponseError


def pair(transport, shared_secret: bytes) -> tuple[int, bytes]:
    """
    Performs an ECDH-based pairing handshake with the card.

    This function initiates a mutual challenge-response authentication and
    derives a secure pairing key.

    Args:
        transport: A transport instance used to send APDU commands.
        shared_secret (bytes): A 32-byte ECDH-derived secret or a passphrase
            convertible to one.

    Returns:
        tuple[int, bytes]: The pairing index (0–15) and a derived 32-byte
        pairing key.

    Raises:
        ValueError: If the shared secret is not 32 bytes.
        APDUError: If the card returns a non-success status word.
        InvalidResponseError: If response lengths or values are unexpected.
    """
    if not isinstance(shared_secret, bytes):
        shared_secret: bytes = generate_pairing_token(shared_secret)

    if len(shared_secret) != 32:
        raise ValueError("Shared secret must be 32 bytes")

    client_challenge = urandom(32)

    response = transport.send_apdu(
        bytes([
            constants.CLA_PROPRIETARY,
            constants.INS_PAIR,
            0x00,
            0x00,
            len(client_challenge)
        ]) + client_challenge
    )

    if response.status_word != 0x9000:
        raise APDUError(response.status_word)
    if len(response.data) != 64:
        raise InvalidResponseError("Unexpected response length")

    card_cryptogram = bytes(response.data[:32])
    card_challenge = bytes(response.data[32:])

    expected = hashlib.sha256(shared_secret + client_challenge).digest()

    if card_cryptogram != expected:
        raise InvalidResponseError("Card cryptogram mismatch")

    client_cryptogram = hashlib.sha256(shared_secret + card_challenge).digest()

    response = transport.send_apdu(
        bytes([
            constants.CLA_PROPRIETARY,
            constants.INS_PAIR,
            0x01,
            0x00,
            len(client_cryptogram)
        ]) + client_cryptogram
    )
    if response.status_word != 0x9000:
        raise APDUError(response.status_word)
    if len(response.data) != 33:
        raise InvalidResponseError("Unexpected response length")

    pairing_index = response.data[0]
    salt = bytes(response.data[1:])

    pairing_key = hashlib.sha256(shared_secret + salt).digest()

    return pairing_index, pairing_key
