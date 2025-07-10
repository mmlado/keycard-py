from .. import constants
from ..apdu import APDUResponse
from ..exceptions import APDUError
from ..parsing.application_info import ApplicationInfo

def select(transport) -> ApplicationInfo:
    """
    Selects the Keycard application on the smart card and retrieves
    application information.

    Sends a SELECT APDU command using the Keycard AID, checks for a
    successful response, parses the returned application information, and
    stores the card's public key.

    Returns:
        ApplicationInfo: Parsed information about the selected application.
    Return type:
        ApplicationInfo

    Raises:
        APDUError: If the card returns a status word indicating failure.
    """
    P1: int = 0x04
    P2: int = 0x00
    aid: bytes = constants.KEYCARD_AID
    apdu: bytes = (
        bytes([constants.CLAISO7816, constants.INS_SELECT, P1, P2, len(aid)]) + aid
    )
    response: APDUResponse = transport.send_apdu(apdu)

    if response.status_word != constants.SW_SUCCESS:
        raise APDUError(response.status_word)

    info: ApplicationInfo = ApplicationInfo.parse(response.data)
    print(info)
    return info
