from .. import constants
from ..card_interface import CardInterface
from ..constants import DerivationOption, KeyExportOption
from ..exceptions import APDUError
from ..utils import serialize_derivation_path
from ..parsing import tlv


def export_key(
    card: CardInterface,
    p1: DerivationOption = DerivationOption.CURRENT,
    p2: KeyExportOption = KeyExportOption.PUBLIC_ONLY,
    derivation_path: list[int] = None
) -> dict:
    """
    Export public (or extended) key from the card.

    Args:
        card: Card transport/session with secure channel and verified PIN
        p1 (DerivationOption): Key selection or derivation mode
        p2 (KeyExportOption): What to export (public, private, or extended public)
        derivation_path (list[int], optional): Required for p1 = DERIVE or DERIVE_AND_MAKE_CURRENT

    Returns:
        dict with:
            - public_key (bytes): 64 bytes (X || Y)
            - private_key (bytes): if p2 == PRIVATE_AND_PUBLIC and permitted
            - chain_code (bytes): if p2 == EXTENDED_PUBLIC
    """
    data = b""
    if p1 in (
        DerivationOption.DERIVE,
        DerivationOption.DERIVE_AND_MAKE_CURRENT
    ):
        if not derivation_path:
            raise ValueError("Derivation path is required for DERIVE or DERIVE_AND_MAKE_CURRENT")
        data = serialize_derivation_path(derivation_path)

    response = card.send_secure_apdu(
        cla=constants.CLA_PROPRIETARY,
        ins=constants.INS_EXPORT_KEY,
        p1=p1,
        p2=p2,
        data=data
    )

    outer = tlv.parse_tlv(response)
    key_template = outer.get(0xA1)
    if not key_template:
        raise ValueError("Missing keypair template (tag 0xA1)")

    inner = tlv.parse_tlv(key_template[0])

    result = {}

    if 0x80 in inner:
        result['public_key'] = inner[0x80][0]

    if 0x81 in inner:
        result['private_key'] = inner[0x81][0]

    if 0x82 in inner:
        result['chain_code'] = inner[0x82][0]

    return result
