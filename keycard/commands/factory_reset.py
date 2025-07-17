from .. import constants
from ..exceptions import APDUError

def factory_reset(card):
    """
    Sends the FACTORY_RESET command to the card.
    """
    card.send_apdu(
        ins=constants.INS_FACTORY_RESET,
        p1=0xAA,
        p2=0x55
    )
