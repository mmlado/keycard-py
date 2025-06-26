from enum import IntFlag


class Capabilities(IntFlag):
    SECURE_CHANNEL = 0x01
    KEY_MANAGEMENT = 0x02
    CREDENTIALS_MANAGEMENT = 0x04
    NDEF = 0x08

    @classmethod
    def parse(cls, value: int) -> "Capabilities":
        return cls(value)
