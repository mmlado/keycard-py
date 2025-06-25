from typing import List, Tuple

from keycard.exceptions import TLVParseError


def parse_tlv(data: bytes) -> List[Tuple[int, bytes]]:
    index = 0
    result = []

    while index < len(data):
        if index + 2 > len(data):
            raise TLVParseError("Incomplete TLV header")

        tag = data[index]
        index += 1

        length = data[index]
        index += 1

        if index + length > len(data):
            raise TLVParseError("Declared length exceeds available data")

        value = data[index : index + length]
        index += length

        result.append((tag, value))

    return result
