from dataclasses import dataclass

@dataclass
class APDUResponse:
    data: bytes
    status_word: int

def encode_lv(value: bytes) -> bytes:
    if len(value) > 255:
        raise ValueError("LV encoding supports up to 255 bytes")
    return bytes([len(value)]) + value