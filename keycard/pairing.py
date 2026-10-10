from typing import NamedTuple


class Pairing(NamedTuple):
    """A Secure Channel V1 pairing: the card's pairing slot and key."""
    slot: int
    key: bytes
