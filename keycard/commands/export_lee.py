from .. import constants
from ..card_interface import CardInterface
from ..constants import DerivationSource
from ..exceptions import InvalidResponseError
from ..parsing import tlv
from ..parsing.keypath import KeyPath
from ..parsing.lee_keys import LeeKeys
from ..preconditions import require_pin_verified

LEE_KEY_TAGS = {'ask': 0x84, 'nsk': 0x83, 'vsk_d': 0x85, 'vsk_z': 0x86}


@require_pin_verified
def export_lee(card: CardInterface, path: str = 'm') -> LeeKeys:
    '''
    Exports the LEE keys at a path (applet 4.0).

    The card must be in LEE mode, entered by loading a seed with
    LoadKeyType.LEE_SEED.

    Args:
        card: The card interface.
        path (str): Derivation path from the master key, e.g.
            "m/44'/60'". "m" exports the master keys.

    Returns:
        LeeKeys: ASK, NSK, VSK_D and VSK_Z, 32 bytes each.

    Raises:
        ValueError: If the path does not start at the master key.
        InvalidResponseError: If a key is missing or not 32 bytes.
        APDUError: If the card returns a failure status word.
    '''
    key_path = KeyPath(path)
    if key_path.source != DerivationSource.MASTER:
        raise ValueError('LEE keys derive from the master key; start at m')

    response = card.send_secure_apdu(
        ins=constants.INS_EXPORT_LEE,
        data=key_path.data
    )

    template = tlv.parse_tlv(response).get(0xA1)
    if not template:
        raise InvalidResponseError('Missing LEE key template (tag 0xA1)')
    inner = tlv.parse_tlv(template[0])

    keys = {}
    for name, tag in LEE_KEY_TAGS.items():
        values = inner.get(tag)
        if not values or len(values[0]) != 32:
            raise InvalidResponseError(f'Missing 32-byte LEE key {tag:#04x}')
        keys[name] = values[0]
    return LeeKeys(**keys)
