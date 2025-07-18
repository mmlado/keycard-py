from .. import constants
from ..parsing.identity import Identity
from ..preconditions import require_selected


@require_selected
def ident(card, challenge: bytes) -> Identity:
    '''
    Sends a challenge to the card to receive a signed identity response.

    Args:
        transport: An instance of the Transport class to communicate with
            the card.
        challenge (bytes): A challenge (nonce or data) to send to the card.

    Returns:
        Identity: A parsed identity object containing the card's response.

    Raises:
        APDUError: If the response status word is not successful (0x9000).
    '''
    response: bytes = card.send_apdu(
        ins=constants.INS_IDENT,
        data=challenge
    )

    return Identity.parse(response)
