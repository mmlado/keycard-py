from typing import Optional

from ber_tlv.tlv import Tlv

from .. import constants
from ..card_interface import CardInterface
from ..preconditions import require_pin_verified


@require_pin_verified
def load_key(
    card: CardInterface,
    key_type: constants.LoadKeyType,
    public_key: Optional[bytes] = None,
    private_key: Optional[bytes] = None,
    chain_code: Optional[bytes] = None,
    bip39_seed: Optional[bytes] = None
) -> bytes:
    """
    Load a key into the card for signing purposes.

    Args:
        card: The card interface.
        key_type: Key type
        public_key: Optional ECC public key (tag 0x80).
        private_key: ECC private key (tag 0x81).
        chain_code: Optional chain code (tag 0x82, only for extended key).
        bip39_seed: 16 to 64-byte binary seed (only for key_type BIP39_SEED,
            or LEE_SEED to also derive the LEE keys on applet 4.0).

    Returns:
        UID of the loaded key (SHA-256 of public key).
    """
    if key_type in (
        constants.LoadKeyType.BIP39_SEED,
        constants.LoadKeyType.LEE_SEED
    ):
        if bip39_seed is None or not 16 <= len(bip39_seed) <= 64:
            raise ValueError("Seed must be 16 to 64 bytes")
        data = bip39_seed
    else:
        if private_key is None:
            raise ValueError("Private key (tag 0x81) is required")
        elements: list[tuple[int, bytes]] = []
        if public_key is not None:
            elements.append((0x80, public_key))
        elements.append((0x81, private_key))
        if (
            key_type == constants.LoadKeyType.EXTENDED_ECC and
            chain_code is not None
        ):
            elements.append((0x82, chain_code))
        data = bytes(Tlv.build([(0xA1, elements)]))

    response = card.send_secure_apdu(
        ins=constants.INS_LOAD_KEY,
        p1=key_type,
        data=data
    )

    return response
