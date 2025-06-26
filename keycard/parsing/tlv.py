from typing import List, Tuple

from keycard.exceptions import InvalidResponseError


def parse_tlv(data: bytes) -> List[Tuple[int, bytes]]:
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
    result = []

    while index < len(data):
        if index + 2 > len(data):
            raise InvalidResponseError(
                "Incomplete TLV header")

        tag = data[index]
        index += 1

        length = data[index]
        index += 1

        if index + length > len(data):
            raise InvalidResponseError(
                "Declared length exceeds available data")

        value = data[index:index + length]
        index += length

        result.append((tag, value))

    return result
