from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv
from .certificate import IdentityCertificate


def parse(challenge: bytes, data: bytes) -> bytes:
    """
    Parses an IDENTIFY CARD response and verifies the card's signature over
    the challenge.

    Args:
        challenge (bytes): The 32-byte challenge sent to the card.
        data (bytes): The response data.

    Returns:
        bytes: The compressed public key of the Keycard CA that signed the
            card's Identity Certificate.

    Raises:
        InvalidResponseError: If the response is malformed or the signature
            does not verify.
    """
    try:
        inner = parse_tlv(parse_tlv(data)[0xA0][0])
        certificate = IdentityCertificate.parse(inner[0x8A][0])
        signature = inner[0x30][0]
    except IndexError as e:
        raise InvalidResponseError('Malformed identity response') from e

    certificate.verify(
        challenge, b'\x30' + bytes([len(signature)]) + signature)
    return certificate.ca_public_key
