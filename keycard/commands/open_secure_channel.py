from .. import constants
from ..card_interface import CardInterface
from ..crypto.ecdh import ecdh_shared_secret, generate_key_pair
from ..exceptions import NotSelectedError
from ..secure_channel import SecureChannel
from ..preconditions import require_initialized


@require_initialized
def open_secure_channel(
    card: CardInterface,
    pairing_index: int,
    pairing_key: bytes
) -> SecureChannel:
    '''
    Opens a secure session with the Keycard using ECDH and a pairing key.

    This function performs an ephemeral ECDH key exchange with the card,
    sends the ephemeral public key, and receives cryptographic material
    from the card to derive a secure session.

    Args:
        transport: The transport used to communicate with the card.
        card_public_key (bytes): The ECC public key of the card, retrieved
            via select().
        pairing_index (int): The index of the previously established
            pairing slot.
        pairing_key (bytes): The shared 32-byte pairing key.

    Returns:
        SecureChannel: A newly established secure session with the card.

    Raises:
        NotSelectedError: If no card public key is provided.
        APDUError: If the card returns a failure status word.
    '''
    if not card.card_public_key:
        raise NotSelectedError('Card not selected or missing public key')

    ephemeral_key, eph_pub_bytes = generate_key_pair()
    response: bytes = card.send_apdu(
        ins=constants.INS_OPEN_SECURE_CHANNEL,
        p1=pairing_index,
        data=eph_pub_bytes
    )

    salt = bytes(response[:32])
    seed_iv = bytes(response[32:])

    shared_secret = ecdh_shared_secret(ephemeral_key, card.card_public_key)

    return SecureChannel.open(
        shared_secret,
        pairing_key,
        salt,
        seed_iv,
    )
