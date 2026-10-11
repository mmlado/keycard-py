from os import urandom

from .. import constants
from ..card_interface import CardInterface
from ..crypto.ecdh import ecdh_shared_secret, generate_key_pair
from ..exceptions import (
    InvalidResponseError,
    InvalidStateError,
    NotSelectedError,
)
from ..parsing.certificate import IdentityCertificate
from ..preconditions import require_selected
from ..secure_channel import (
    SecureChannel,
    SecureChannelV1,
    SecureChannelV2,
    SecureChannelVersion,
    channel_version,
)
from ..secure_channel.v2 import transcript_digest

CHALLENGE_SIZE = 32
PUBLIC_KEY_SIZE = 65
SALT_SIZE = 32


@require_selected
def open_secure_channel(card: CardInterface) -> SecureChannel:
    '''
    Opens a secure channel with the selected card, using the channel version
    its applet supports.

    Secure Channel V1 (3.x) uses the card's pairing and runs MUTUALLY
    AUTHENTICATE. Secure Channel V2 (4.x) first checks the card's Identity
    Certificate against the trusted Keycard CAs.

    Args:
        card: The card interface.

    Returns:
        SecureChannel: The open channel.

    Raises:
        InvalidStateError: If a V1 card has no pairing or is not initialized.
        UntrustedCardError: If a V2 card is not trusted.
        InvalidResponseError: If the handshake does not verify.
        APDUError: If the card returns a failure status word.
    '''
    if channel_version(card.version) == SecureChannelVersion.V2:
        return _open_v2(card)
    return _open_v1(card)


def _open_v1(card: CardInterface) -> SecureChannelV1:
    if not card.is_initialized:
        raise InvalidStateError('Card Initialization must be satisfied.')
    pairing = card.pairing
    if pairing is None:
        raise InvalidStateError(
            'Secure Channel V1 needs a pairing: call pair() or set pairing')
    if not card.card_public_key:
        raise NotSelectedError('Card not selected or missing public key')

    ephemeral_key, ephemeral_public_key = generate_key_pair()
    response = card.send_apdu(
        ins=constants.INS_OPEN_SECURE_CHANNEL,
        p1=pairing.slot,
        data=ephemeral_public_key
    )
    shared_secret = ecdh_shared_secret(ephemeral_key, card.card_public_key)
    channel = SecureChannelV1.from_handshake(
        shared_secret, pairing.key, response[:32], response[32:])

    # The channel is not on the card interface yet, so send through it here.
    challenge_response = channel.unwrap(card.send_raw_apdu(channel.wrap(
        constants.INS_MUTUALLY_AUTHENTICATE, 0x00, 0x00,
        urandom(CHALLENGE_SIZE))))
    if len(challenge_response) != CHALLENGE_SIZE:
        raise InvalidResponseError(
            'Response to MUTUALLY AUTHENTICATE is not 32 bytes')
    return channel


def _open_v2(card: CardInterface) -> SecureChannelV2:
    if card.identity_certificate is None:
        raise InvalidResponseError(
            'Card did not report an Identity Certificate')
    certificate = IdentityCertificate.parse(card.identity_certificate)
    certificate.check_trust(card.ca_public_keys, card.trusted_identity_keys)

    salt = urandom(SALT_SIZE)
    ephemeral_key, client_public_key = generate_key_pair()
    response = card.send_apdu(
        ins=constants.INS_OPEN_SECURE_CHANNEL,
        data=salt + client_public_key
    )
    if len(response) <= PUBLIC_KEY_SIZE:
        raise InvalidResponseError('OPEN SECURE CHANNEL response too short')
    card_public_key = response[:PUBLIC_KEY_SIZE]

    certificate.verify(
        transcript_digest(salt, client_public_key, card_public_key),
        response[PUBLIC_KEY_SIZE:]
    )
    return SecureChannelV2.from_handshake(
        salt, ecdh_shared_secret(ephemeral_key, card_public_key))
