from dataclasses import dataclass

@dataclass
class APDUResponse:
    data: bytes
    status_word: int