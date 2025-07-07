from .. import constants
from ..exceptions import APDUError


def unpair(transport, secure_session, index: int):
    """
    Sends the UNPAIR command to remove a pairing index from the card.

    Args:
        transport: The transport interface used to send APDUs.
        secure_session: The active SecureSession object.
        index (int): The pairing index to unpair.

    Raises:
        ValueError: If transport or secure_session is not provided, or if
            the session is not authenticated.
        APDUError: If the response status word indicates an error.
    """
    if not transport:
        raise ValueError("Transport must be provided")
    if not secure_session:
        raise ValueError("Secure session must be provided")
    if not secure_session.authenticated:
        raise ValueError("Secure session must be authenticated")

    cla, ins, p1, p2, data = secure_session.wrap_apdu(
        constants.CLA_PROPRIETARY, constants.INS_UNPAIR, index, 0x00, b""
    )
    response = transport.send_apdu(bytes([cla, ins, p1, p2]) + data)

    if response.status_word != 0x9000:
        raise APDUError(response.status_word)
