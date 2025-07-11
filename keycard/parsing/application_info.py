from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..exceptions import InvalidResponseError
from .capabilities import Capabilities
from .tlv import parse_tlv


@dataclass
class ApplicationInfo:
    """
    Represents parsed application information from a TLV-encoded response.

    Attributes:
        capabilities (Optional[int]): Parsed capabilities value, if present.
        ecc_public_key (Optional[bytes]): ECC public key bytes, if present.
        instance_uid (Optional[bytes]): Unique identifier for the application
            instance, if present.
        key_uid (Optional[bytes]): Unique identifier for the key, if present.
        version_major (int): Major version number of the application.
        version_minor (int): Minor version number of the application.
    """
    capabilities: Optional[int]
    ecc_public_key: Optional[bytes]
    instance_uid: Optional[bytes]
    key_uid: Optional[bytes]
    version_major: int
    version_minor: int

    @staticmethod
    def parse(data: bytes) -> "ApplicationInfo":
        """
        Parses a byte sequence containing TLV-encoded application information
        and returns an ApplicationInfo instance.

        Args:
            data (bytes): The TLV-encoded response data to parse.

        Returns:
            ApplicationInfo: An instance populated with the parsed application
                information fields.

        The function extracts the following fields from the TLV data:
            - version_major (int): Major version number (from tag 0x02).
            - version_minor (int): Minor version number (from tag 0x02).
            - instance_uid (bytes or None): Instance UID (from tag 0x8F).
            - key_uid (bytes or None): Key UID (from tag 0x8E).
            - ecc_public_key (bytes or None): ECC public key (from tag 0x80).
            - capabilities (Capabilities or None): Capabilities object
                (from tag 0x8D).

        Raises:
            Any exceptions raised by ApplicationInfo._parse_response or
            Capabilities.parse.
        """
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
