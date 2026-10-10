from .. import constants
from ..card_interface import CardInterface
from ..exceptions import InvalidResponseError
from ..preconditions import require_selected


SEGMENTED_NDEF_VERSION = (4, 0)


def _send_get_data(
    card: CardInterface,
    slot: constants.StorageSlot,
    p2: int = 0
) -> bytes:
    if card.is_secure_channel_open:
        return card.send_secure_apdu(
            ins=constants.INS_GET_DATA,
            p1=slot.value,
            p2=p2
        )

    return card.send_apdu(
        cla=constants.CLA_PROPRIETARY,
        ins=constants.INS_GET_DATA,
        p1=slot.value,
        p2=p2
    )


def _get_ndef_segmented(card: CardInterface) -> bytes:
    data = bytes(_send_get_data(card, constants.StorageSlot.NDEF))
    if len(data) < 2:
        raise InvalidResponseError("NDEF data is missing its length header")

    total = int.from_bytes(data[:2], 'big') + 2
    while len(data) < total:
        if len(data) % 4:
            raise InvalidResponseError("NDEF segment not aligned to 4 bytes")

        segment = _send_get_data(
            card, constants.StorageSlot.NDEF, len(data) // 4)
        if not segment:
            raise InvalidResponseError("Card returned an empty NDEF segment")
        data += segment

    return data[:total]


@require_selected
def get_data(
    card: CardInterface,
    slot: constants.StorageSlot = constants.StorageSlot.PUBLIC
) -> bytes:
    """
    Gets the data on the card previously stored with the store data command
    in the specified slot.

    If the secure channel is open, it uses the secure APDU command.
    Otherwise, it uses the proprietary APDU command.

    NDEF data is the complete NDEF file, starting with its 2-byte length.
    From applet 4.0 it is read in segments until the whole file is received;
    earlier applets return at most the first 223 bytes.

    Args:
        card: The card session object.
        slot (StorageSlot): Where to retrieve the data from (PUBLIC, NDEF,
            CASH)

    Raises:
        InvalidResponseError: If segmented NDEF data is malformed.
    """
    if (
        slot == constants.StorageSlot.NDEF and
        card.version >= SEGMENTED_NDEF_VERSION
    ):
        return _get_ndef_segmented(card)

    return _send_get_data(card, slot)
