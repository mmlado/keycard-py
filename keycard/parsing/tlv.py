from collections import defaultdict
from typing import Tuple

from keycard.exceptions import InvalidResponseError


def _parse_ber_length(data: bytes, index: int) -> tuple[int, int]:
    """
    Parses a BER-encoded length field from a byte sequence starting at the
    given index.

    Args:
        data (bytes): The byte sequence containing the BER-encoded length.
        index (int): The starting index in the byte sequence to parse the
            length from.

    Returns:
        tuple[int, int]: A tuple containing the parsed length (int) and the
            total number of bytes consumed (int).

    Raises:
        InvalidResponseError: If the length encoding is unsupported or exceeds
            the remaining buffer.
    """
    first = data[index]
    index += 1

    if first < 0x80:
        return first, 1

    num_bytes = first & 0x7F
    if num_bytes > 4:
        raise InvalidResponseError("Unsupported length encoding")

    if index + num_bytes > len(data):
        raise InvalidResponseError("Length exceeds remaining buffer")

    length = int.from_bytes(data[index:index+num_bytes], "big")
    return length, 1 + num_bytes


def parse_tlv(data: bytes) -> defaultdict[Tuple[int, bytes]]:
    """
    Parses a byte sequence containing TLV (Tag-Length-Value) encoded data.

    Args:
        data (bytes): The byte sequence to parse.

    Returns:
        List[Tuple[int, bytes]]: A list of tuples, each containing the tag
            (as an int) and the value (as bytes).

    Raises:
        InvalidResponseError: If the TLV header is incomplete or the declared
            length exceeds the available data.
    """
    index = 0
    result = defaultdict(list)

    while index < len(data):
        tag = data[index]
        index += 1

        length, length_size = _parse_ber_length(data, index)
        index += length_size

        value = data[index:index+length]

        if len(value) < length:
            raise InvalidResponseError("Not enough bytes for value")

        index += length

        result[tag].append(value)

    return result
