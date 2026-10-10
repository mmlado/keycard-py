from os import urandom
from typing import Optional

from .. import constants
from ..card_interface import CardInterface
from ..crypto.aes import aes_cbc_encrypt
from ..crypto.ecdh import ecdh_shared_secret, generate_key_pair
from ..crypto.generate_pairing_token import generate_pairing_token
from ..exceptions import NotSelectedError
from ..preconditions import require_selected
from ..secure_channel import SecureChannelVersion, channel_version

DEFAULT_PIN_RETRIES = 3
DEFAULT_PUK_RETRIES = 5
PIN_RETRIES_RANGE = range(2, 11)
PUK_RETRIES_RANGE = range(3, 13)
PIN_LENGTH = 6


@require_selected
def init(
    card: CardInterface,
    pin: str | bytes,
    puk: str | bytes,
    pairing_secret: Optional[str | bytes] = None,
    pin_retries: Optional[int] = None,
    puk_retries: Optional[int] = None,
    alt_pin: Optional[str | bytes] = None
) -> None:
    '''
    Initializes the card the way its secure channel version requires.

    Secure Channel V1 (3.x) cards need the pairing secret and receive the
    credentials encrypted once to the card's public key. Secure Channel V2
    (4.x) cards take no pairing secret and receive INIT inside the secure
    channel, which is opened if needed and stays open.

    Args:
        card: The card interface.
        pin: The 6-digit PIN.
        puk: The 12-digit PUK.
        pairing_secret: A 32-byte secret or a passphrase (V1 only).
        pin_retries: PIN attempts, 2 to 10 (default 3).
        puk_retries: PUK attempts, 3 to 12 (default 5).
        alt_pin: Optional 6-digit Alternate PIN.

    Raises:
        ValueError: If the pairing secret is missing on V1, given on V2, or a
            parameter is out of range.
        APDUError: If the card returns a failure status word.
    '''
    if channel_version(card.version) == SecureChannelVersion.V2:
        if pairing_secret is not None:
            raise ValueError(
                'Secure Channel V2 cards do not use a pairing secret')
        _init_v2(card, _credentials(
            pin, puk, b'', pin_retries, puk_retries, alt_pin))
        return

    if pairing_secret is None:
        raise ValueError('Secure Channel V1 cards need a pairing secret')
    if not isinstance(pairing_secret, bytes):
        pairing_secret = generate_pairing_token(pairing_secret)
    _init_v1(card, _credentials(
        pin, puk, pairing_secret, pin_retries, puk_retries, alt_pin))


def _init_v1(card: CardInterface, credentials: bytes) -> None:
    if card.card_public_key is None:
        raise NotSelectedError('Card not selected. Call select() first.')

    ephemeral_key, ephemeral_public_key = generate_key_pair()
    shared_secret = ecdh_shared_secret(ephemeral_key, card.card_public_key)
    iv = urandom(16)
    data = (
        bytes([len(ephemeral_public_key)])
        + ephemeral_public_key
        + iv
        + aes_cbc_encrypt(shared_secret, iv, credentials)
    )
    if len(data) > 255:
        raise ValueError('Data too long for single APDU')

    card.send_apdu(ins=constants.INS_INIT, data=data)


def _init_v2(card: CardInterface, credentials: bytes) -> None:
    if not card.is_secure_channel_open:
        card.open_secure_channel()
    card.send_secure_apdu(ins=constants.INS_INIT, data=credentials)


def _to_bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode('ascii')


def _credentials(
    pin: str | bytes,
    puk: str | bytes,
    pairing_secret: bytes,
    pin_retries: Optional[int],
    puk_retries: Optional[int],
    alt_pin: Optional[str | bytes]
) -> bytes:
    data = _to_bytes(pin) + _to_bytes(puk) + pairing_secret
    if pin_retries is None and puk_retries is None and alt_pin is None:
        return data

    pin_retries = pin_retries or DEFAULT_PIN_RETRIES
    puk_retries = puk_retries or DEFAULT_PUK_RETRIES
    if pin_retries not in PIN_RETRIES_RANGE:
        raise ValueError('pin_retries must be between 2 and 10')
    if puk_retries not in PUK_RETRIES_RANGE:
        raise ValueError('puk_retries must be between 3 and 12')
    data += bytes([pin_retries, puk_retries])

    if alt_pin is not None:
        alt_pin = _to_bytes(alt_pin)
        if len(alt_pin) != PIN_LENGTH:
            raise ValueError(f'alt_pin must be {PIN_LENGTH} digits')
        data += alt_pin
    return data
