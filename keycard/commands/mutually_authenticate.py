import os
from .. import constants
from ..apdu import APDUResponse
from ..exceptions import APDUError


def mutually_authenticate(transport, session) -> None:
    """
    Performs mutual authentication between the client and the card.

    Raises:
        APDUError: If the response status word (SW) is not 0x9000.
        ValueError: If the response to MUTUALLY AUTHENTICATE is not
            32 bytes.
    """
    client_challenge = os.urandom(32)

    cla, ins, p1, p2, data = session.wrap_apdu(
        cla=constants.CLA_PROPRIETARY,
        ins=constants.INS_MUTUALLY_AUTHENTICATE,
        p1=0x00,
        p2=0x00,
        data=client_challenge
    )

    response: APDUResponse = transport.send_apdu(
        bytes([cla, ins, p1, p2, len(data)]) + data)

    if response.status_word != 0x9000:
        raise APDUError(response.status_word)

    plaintext, sw = session.unwrap_response(response)

    if sw != 0x9000:
        raise APDUError(sw)

    if len(plaintext) != 32:
        raise ValueError(
            'Response to MUTUALLY AUTHENTICATE is not 32 bytes')
