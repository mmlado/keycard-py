from typing import List, Optional
from .. import constants
from ..card_interface import CardInterface
from ..parsing import tlv
from ..exceptions import InvalidStateError
from ..constants import DerivationOption, SigningAlgorithm


def sign(
    card: CardInterface,
    digest: bytes,
    p1: DerivationOption = DerivationOption.CURRENT,
    p2: SigningAlgorithm = SigningAlgorithm.ECDSA_SECP256K1,
    derivation_path: Optional[List[int]]=None
) -> dict:
    """
    Sign a 32-byte digest using the specified key and algorithm.

    Preconditions:
        - For p1 = CURRENT, DERIVE, DERIVE_AND_MAKE_CURRENT:
            - Secure Channel must be open
            - PIN must be verified
        - For p1 = PINLESS:
            - No secure channel or PIN is required
            - A PIN-less path must have been previously configured

    Args:
        card: Card transport object with session state and send_secure_apdu method.
        digest (bytes): The hash to sign (must be exactly 32 bytes).
        p1 (DerivationOption): Key derivation mode (default: CURRENT).
        p2 (SigningAlgorithm): Signing algorithm (default: ECDSA over secp256k1).
        derivation_path (list[int], optional): List of 32-bit integers for
            BIP32-style derivation path.

    Returns:
        dict with:
            - 'signature': bytes — the raw or DER-encoded signature
            - 'format': str — 'raw' or 'template'
            - 'public_key': bytes (only present if format is 'template')

    Raises:
        ValueError: If digest is not 32 bytes or response format is unknown.
        InvalidStateError: If signing preconditions are not satisfied.
        APDUError: If the card returns an error status word.
    """
    if len(digest) != 32:
        raise ValueError("Digest must be exactly 32 bytes")

    if p1 != DerivationOption.PINLESS:
        if not card.is_pin_verified:
            raise InvalidStateError("PIN must be verified to sign with this"
                                    " derivation option")

    data = digest
    if p1 in (
        DerivationOption.DERIVE,
        DerivationOption.DERIVE_AND_MAKE_CURRENT
    ):
        if not derivation_path:
            raise ValueError("Derivation path cannot be empty")
        if any(
            not isinstance(i, int) or not (0 <= i < 2**32)
            for i in derivation_path
        ):
            raise ValueError(
                "Derivation path elements must be 32-bit integers")
        data += b''.join(i.to_bytes(4, 'big') for i in derivation_path)

    response = card.send_secure_apdu(
        ins=constants.INS_SIGN,
        p1=p1,
        p2=p2,
        data=data
    )

    if response.startswith(b'\x80'):
        return {
            'signature': response[1:],
            'format': 'raw'
        }

    if response.startswith(b'\xA0'):
        outer = tlv.parse_tlv(response)
        sig_tpl = outer.get(0xA0)
        if not sig_tpl:
            raise ValueError("Missing signature template (tag 0xA0)")
        inner = tlv.parse_tlv(sig_tpl[0])
        return {
            'signature': inner[0x30][0],
            'public_key': inner[0x80][0],
            'format': 'template'
        }

    raise ValueError("Unexpected response format")
