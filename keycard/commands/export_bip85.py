from .. import constants
from ..card_interface import CardInterface
from ..constants import DerivationSource
from ..exceptions import InvalidResponseError
from ..parsing.keypath import KeyPath
from ..preconditions import require_pin_verified


@require_pin_verified
def export_bip85(card: CardInterface, path: str, length: int) -> bytes:
    '''
    Exports BIP-85 entropy derived from the loaded key (applet 4.0).

    Args:
        card: The card interface.
        path (str): Derivation path starting with "m/83696968'", every
            component hardened, e.g. "m/83696968'/0'/0'". The card rejects
            any other path.
        length (int): Number of entropy bytes, 1 to 64.

    Returns:
        bytes: The first `length` bytes of the BIP-85 entropy.

    Raises:
        ValueError: If the length is out of range or the path does not
            start at the master key.
        InvalidResponseError: If the card returns a different length.
        APDUError: If the card returns a failure status word.
    '''
    if not 1 <= length <= 64:
        raise ValueError('length must be between 1 and 64')

    key_path = KeyPath(path)
    if key_path.source != DerivationSource.MASTER:
        raise ValueError('BIP-85 paths derive from the master key; start at m')

    response = card.send_secure_apdu(
        ins=constants.INS_EXPORT_BIP85,
        p1=length,
        data=key_path.data
    )

    if len(response) != length:
        raise InvalidResponseError(
            f'Expected {length} entropy bytes, got {len(response)}')
    return response
