from .. import constants
from ..exceptions import APDUError
from ..parsing.identity import Identity


def ident(transport, challenge: bytes) -> Identity:
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
