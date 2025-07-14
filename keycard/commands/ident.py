from .. import constants
from ..exceptions import APDUError
from ..parsing.identity import Identity


def ident(transport, challenge: bytes) -> Identity:
    """
    Sends a challenge to the card to receive a signed identity response.

    Args:
        transport: An instance of the Transport class to communicate with
            the card.
        challenge (bytes): A challenge (nonce or data) to send to the card.

    Returns:
        Identity: A parsed identity object containing the card's response.

    Raises:
        APDUError: If the response status word is not successful (0x9000).
    """
    apdu = (
        bytes([
            constants.CLA_PROPRIETARY,
            constants.INS_IDENT,
            0x00,
            0x00,
            len(challenge)
        ]) + challenge
    )
    response = transport.send_apdu(apdu)

    if response.status_word != 0x9000:
        raise APDUError(response.status_word)

    return Identity.parse(bytes(response.data))
