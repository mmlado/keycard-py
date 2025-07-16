from .. import constants
from ..exceptions import APDUError

def factory_reset(transport):
    """
    Sends the FACTORY_RESET command to the card.
    """
    apdu = bytes([
        constants.CLA_PROPRIETARY,
        constants.INS_FACTORY_RESET,  # FACTORY_RESET
        0xAA,
        0x55
    ])

    response = transport.send_apdu(apdu)

    if response.status_word != constants.SW_SUCCESS:
        raise APDUError(response.status_word)
