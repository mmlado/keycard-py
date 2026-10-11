from ..card_interface import CardInterface
from ..constants import INS_STORE_DATA, StorageSlot
from ..preconditions import require_pin_verified


MAX_DATA_SIZE = 127
NDEF_MAX_SIZE = 512
# Largest multiple of 4 that fits the 223-byte Secure Channel V1 payload.
NDEF_CHUNK_SIZE = 220
CHUNKED_NDEF_VERSION = (3, 2)


def _store_ndef_chunked(card: CardInterface, data: bytes) -> None:
    if len(data) > NDEF_MAX_SIZE:
        raise ValueError(
            f"NDEF data too long. Maximum allowed is {NDEF_MAX_SIZE} bytes.")

    for offset in range(0, max(len(data), 1), NDEF_CHUNK_SIZE):
        card.send_secure_apdu(
            ins=INS_STORE_DATA,
            p1=StorageSlot.NDEF,
            p2=offset // 4,
            data=data[offset:offset + NDEF_CHUNK_SIZE]
        )


@require_pin_verified
def store_data(
    card: CardInterface,
    data: bytes,
    slot: StorageSlot = StorageSlot.PUBLIC
) -> None:
    """
    Stores data on the card in the specified slot.

    NDEF data is the complete NDEF file, starting with its 2-byte length.
    From applet 3.2 it can be up to 512 bytes and is sent in chunks.

    Args:
        card: The card session object.
        data (bytes): The data to store (max 127 bytes, or 512 bytes for
            NDEF from applet 3.2).
        slot (StorageSlot): Where to store the data (PUBLIC, NDEF, CASH)

    Raises:
        ValueError: If the data is too long.
    """
    if slot == StorageSlot.NDEF and card.version >= CHUNKED_NDEF_VERSION:
        _store_ndef_chunked(card, data)
        return

    if len(data) > MAX_DATA_SIZE:
        raise ValueError(
            f"Data too long. Maximum allowed is {MAX_DATA_SIZE} bytes.")

    card.send_secure_apdu(
        ins=INS_STORE_DATA,
        p1=slot.value,
        data=data
    )
