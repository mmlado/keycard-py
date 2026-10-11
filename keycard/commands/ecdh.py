from .. import constants
from ..card_interface import CardInterface
from ..constants import DerivationOption, DerivationSource
from ..exceptions import InvalidResponseError
from ..parsing.keypath import KeyPath
from ..preconditions import require_pin_verified


@require_pin_verified
def ecdh(card: CardInterface, public_key: bytes, path: str) -> bytes:
    '''
    Computes an ECDH shared secret with the key at a path (applet 4.0).

    The result is the raw X coordinate of the shared point, not an
    encryption key; run it through the protocol's own KDF.

    Args:
        card: The card interface.
        public_key (bytes): The peer's uncompressed public key, 65 bytes.
        path (str): Derivation path under "m/44'/1237'" (NIP-44) or
            "m/43'/60'/1581'" (EIP-1581), at least 5 levels deep. The card
            rejects any other path.

    Returns:
        bytes: The 32-byte X coordinate of the shared point.

    Raises:
        ValueError: If the public key is not 65 bytes starting with 0x04, or
            the path does not start at the master key.
        InvalidResponseError: If the card returns a different length.
        APDUError: If the card returns a failure status word.
    '''
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise ValueError('public_key must be a 65-byte uncompressed point')

    key_path = KeyPath(path)
    if key_path.source != DerivationSource.MASTER:
        raise ValueError('ECDH keys derive from the master key; start at m')

    response = card.send_secure_apdu(
        ins=constants.INS_ECDH,
        p1=DerivationOption.DERIVE,
        data=bytes(public_key) + key_path.data
    )

    if len(response) != 32:
        raise InvalidResponseError(
            f'Expected a 32-byte shared secret, got {len(response)}')
    return response
