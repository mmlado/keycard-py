from typing import Optional

from .. import constants
from ..card_interface import CardInterface
from ..parsing import tlv
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
        bip39_seed: 64-byte BIP39 seed (only for key_type=BIP39_SEED).

    Returns:
        UID of the loaded key (SHA-256 of public key).
    """
    if key_type == constants.LoadKeyType.BIP39_SEED:
        if bip39_seed is None or len(bip39_seed) != 64:
            raise ValueError(
                "BIP39 seed must be 64 bytes for key_type = BIP39_SEED")
        data = bip39_seed
    else:
        inner_tlv = []
        if public_key is not None:
            inner_tlv.append(tlv.encode_tlv(0x80, public_key))
        if private_key is None:
            raise ValueError("Private key (tag 0x81) is required")
        inner_tlv.append(tlv.encode_tlv(0x81, private_key))
        if (
            key_type == constants.LoadKeyType.EXTENDED_ECC and
            chain_code is not None
        ):
            inner_tlv.append(tlv.encode_tlv(0x82, chain_code))
        tpl = tlv.encode_tlv(0xA1, b''.join(inner_tlv))
        data = tpl

    response = card.send_secure_apdu(
        ins=constants.INS_LOAD_KEY,
        p1=key_type,
        data=data
    )

    return response
