from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..exceptions import InvalidResponseError
from .capabilities import Capabilities
from .tlv import parse_tlv


@dataclass
class ApplicationInfo:
    capabilities: Optional[int]
    ecc_public_key: Optional[bytes]
    instance_uid: Optional[bytes]
    key_uid: Optional[bytes]
    version_major: int
    version_minor: int

    @staticmethod
    def parse(data: bytes) -> "ApplicationInfo":
        tlvs = ApplicationInfo._parse_response(data)

        version_major = version_minor = 0
        instance_uid = None
        key_uid = None
        ecc_public_key = None
        capabilities = None

        for tag, value in tlvs:
            if tag == 0x02 and len(value) == 2:
                version_major, version_minor = value[0], value[1]
            elif tag == 0x8F:
                instance_uid = value
            elif tag == 0x80:
                ecc_public_key = value
            elif tag == 0x8E:
                key_uid = value
            elif tag == 0x8D:
                capabilities = Capabilities.parse(value[0])

        return ApplicationInfo(
            capabilities=capabilities,
            ecc_public_key=ecc_public_key,
            instance_uid=instance_uid,
            key_uid=key_uid,
            version_major=version_major,
            version_minor=version_minor,
        )

    @staticmethod
    def _parse_response(data: bytes) -> List[Tuple[int, bytes]]:
        if len(data) < 2:
            raise InvalidResponseError("Response too short")

        if data[0] != 0xA4:
            raise InvalidResponseError("Invalid top-level tag, expected 0xA4")

        total_length = data[1]
        if len(data) < 2 + total_length:
            raise InvalidResponseError("Invalid total length in response")

        inner_data = data[2:2 + total_length]

        return parse_tlv(inner_data)
