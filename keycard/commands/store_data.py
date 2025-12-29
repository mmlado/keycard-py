from ..constants import INS_STORE_DATA, StorageSlot
from .. import CardInterface
from ..preconditions import require_pin_verified


NDEF_MAX_CHUNK_SIZE = 220
LONG_NDEF_SUPPORT = {
    'major': 3,
    'minor': 2
}


def _store_long_ndef(card: CardInterface, data: bytes) -> None:
    if len(data) % 4 != 0:
        raise ValueError('Data size not divisible by 4')

    remaining = data
    offset = 0
    while len(remaining):
        part = remaining[:NDEF_MAX_CHUNK_SIZE]
        remaining = remaining[NDEF_MAX_CHUNK_SIZE:]

        card.send_secure_apdu(
            ins=INS_STORE_DATA,
            p1=StorageSlot.NDEF,
            p2=offset // 4,
            data=part
        )

        offset = offset + len(part)


@require_pin_verified
def store_data(
    card: CardInterface,
    data: bytes,
    slot: StorageSlot = StorageSlot.PUBLIC
) -> None:
    """
    Stores data on the card in the specified slot.

    Args:
        card: The card session object.
        data (bytes): The data to store (max 127 bytes).
        slot (StorageSlot): Where to store the data (PUBLIC, NDEF, CASH)

    Raises:
        ValueError: If slot is invalid or data is too long.
    """
    (major, minor) = card.version
    if slot == StorageSlot.NDEF and\
            major >= LONG_NDEF_SUPPORT['major'] and\
            minor >= LONG_NDEF_SUPPORT['minor']:
        return _store_long_ndef(card, data)

    if len(data) > 127:
        raise ValueError("Data too long. Maximum allowed is 127 bytes.")

    card.send_secure_apdu(
        ins=INS_STORE_DATA,
        p1=slot.value,
        data=data
    )

    return
