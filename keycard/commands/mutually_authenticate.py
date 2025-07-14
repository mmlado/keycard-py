import os
from .. import constants
from ..apdu import APDUResponse
from ..exceptions import APDUError


def mutually_authenticate(transport, session, client_challenge=None) -> None:
    """
    Performs mutual authentication between the client and the Keycard.

    The card will respond with a cryptographic challenge. The secure
    session will verify the response. If the response is not exactly
    32 bytes, or if the response has an unexpected status word, the
    function raises an error.

    Args:
        transport: A Transport instance for sending APDUs.
        session: A SecureSession instance used for wrapping/unwrapping.
        client_challenge (bytes, optional): Optional challenge bytes.
            If not provided, a random 32-byte value will be generated.

    Raises:
        APDUError: If the response status word is not 0x9000.
        ValueError: If the decrypted response is not exactly 32 bytes.
    """
    client_challenge = client_challenge or os.urandom(32)

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
