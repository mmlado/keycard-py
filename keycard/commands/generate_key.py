from .. import constants
from ..preconditions import require_secure_channel


@require_secure_channel
def generate_key(card) -> bytes:
    '''
    Generates a new key on the card and returns the key UID.

    Preconditions:
        - Secure Channel must be opened
        - PIN must be verified

    Args:
        transport: Transport instance for APDU communication
        session: SecureSession instance for wrapping/unwrapping

    Returns:
        bytes: Key UID (SHA-256 of the public key)

    Raises:
        APDUError: If the response status word is not 0x9000
    '''
    return card.send_secure_apdu(
        ins=constants.INS_GENERATE_KEY
    )
