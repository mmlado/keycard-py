from typing import List, Tuple

from keycard.exceptions import InvalidResponseError


def parse_tlv(data: bytes) -> List[Tuple[int, bytes]]:
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
