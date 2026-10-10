from collections import defaultdict

from ber_tlv.tlv import BadLength, BadTag, Tlv, UnexpectedEnd

from keycard.exceptions import InvalidResponseError


def parse_tlv(data: bytes) -> defaultdict[int, list[bytes]]:
    """
    Parses one level of BER-TLV encoded data.

    Constructed values are returned as raw bytes; parse them again to read
    their children.

    Args:
        data (bytes): The byte sequence to parse.

    Returns:
        defaultdict[int, list[bytes]]: The values of each tag, in the order
            they appear. Repeated tags keep every value.

    Raises:
        InvalidResponseError: If the data is not valid BER-TLV.
    """
    try:
        elements = Tlv.parse(bytes(data), recursive=False)
    except (BadTag, BadLength, UnexpectedEnd) as e:
        raise InvalidResponseError(f"Malformed TLV data: {e!r}") from e

    result: defaultdict[int, list[bytes]] = defaultdict(list)
    for tag, value in elements:
        result[tag].append(value)

    return result
