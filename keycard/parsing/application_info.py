from dataclasses import dataclass
from typing import Optional

from ..exceptions import InvalidResponseError
from .capabilities import Capabilities
from .tlv import parse_tlv

STATUS_INITIALIZED = 0x10
STATUS_LEE_MODE = 0x20
STATUS_PIN_RETRIES_MASK = 0x0F


@dataclass
class ApplicationInfo:
    """
    Represents parsed application information from a SELECT response.

    Fields a card version does not report are None.

    Attributes:
        capabilities (Optional[int]): Parsed capabilities value, if present.
        ecc_public_key (Optional[bytes]): Secure Channel V1 public key
            (3.x only).
        instance_uid (Optional[bytes]): Instance UID (3.x only).
        key_uid (Optional[bytes]): Unique identifier for the key, if present.
        version_major (int): Major version number of the application.
        version_minor (int): Minor version number of the application.
        free_pairing_slots (Optional[int]): Free pairing slots (3.x only).
        status (Optional[int]): Application status byte (4.x only).
        identity_certificate (Optional[bytes]): The card's Identity
            Certificate (4.x only).
    """
    capabilities: Optional[int]
    ecc_public_key: Optional[bytes]
    instance_uid: Optional[bytes]
    key_uid: Optional[bytes]
    version_major: int
    version_minor: int
    free_pairing_slots: Optional[int] = None
    status: Optional[int] = None
    identity_certificate: Optional[bytes] = None

    @property
    def is_initialized(self) -> bool:
        """
        Checks if the application is initialized: from the status byte on
        4.x, from the presence of the key UID before.

        Returns:
            bool: True if the application is initialized.
        """
        if self.status is not None:
            return bool(self.status & STATUS_INITIALIZED)
        return self.key_uid is not None

    @property
    def pin_retries(self) -> Optional[int]:
        """Remaining PIN attempts (4.x only)."""
        if self.status is None:
            return None
        return self.status & STATUS_PIN_RETRIES_MASK

    @property
    def is_lee_mode(self) -> bool:
        """Whether a LEE seed is loaded (4.x only)."""
        return self.status is not None and bool(self.status & STATUS_LEE_MODE)

    @staticmethod
    def parse(data: bytes) -> "ApplicationInfo":
        """
        Parses a SELECT response.

        Args:
            data (bytes): The response data.

        Returns:
            ApplicationInfo: The parsed application information.

        Raises:
            InvalidResponseError: If the response is malformed.
        """
        if data[0] == 0x80:
            length = data[1]
            pubkey = data[2:2+length]
            capabilities = Capabilities.CREDENTIALS_MANAGEMENT
            if pubkey:
                capabilities |= Capabilities.SECURE_CHANNEL

            return ApplicationInfo(
                capabilities=Capabilities.parse(capabilities),
                ecc_public_key=bytes(pubkey),
                instance_uid=None,
                key_uid=None,
                version_major=0,
                version_minor=0,
            )

        tlv = parse_tlv(data)
        if 0xA4 not in tlv:
            raise InvalidResponseError(
                "Invalid top-level tag, expected 0xA4")

        inner = parse_tlv(tlv[0xA4][0])
        integers = inner.get(0x02, [])
        version = next((v for v in integers if len(v) == 2), None)
        if version is None:
            raise InvalidResponseError("Missing application version")
        free_slots = next((v[0] for v in integers if len(v) == 1), None)

        def first(tag: int) -> Optional[bytes]:
            values = inner.get(tag)
            return bytes(values[0]) if values else None

        capability_bytes = first(0x8D)
        status = first(0x8C)

        return ApplicationInfo(
            capabilities=(
                Capabilities.parse(capability_bytes[0])
                if capability_bytes else None
            ),
            ecc_public_key=first(0x80),
            instance_uid=first(0x8F),
            key_uid=first(0x8E),
            version_major=version[0],
            version_minor=version[1],
            free_pairing_slots=free_slots,
            status=status[0] if status else None,
            identity_certificate=first(0x8A),
        )

    def __str__(self) -> str:
        def hexed(value: Optional[bytes]) -> Optional[str]:
            return value.hex() if value is not None else None

        return (
            f"ApplicationInfo(version="
            f"{self.version_major}.{self.version_minor}, "
            f"instance_uid={hexed(self.instance_uid)}, "
            f"key_uid={hexed(self.key_uid)}, "
            f"ecc_public_key={hexed(self.ecc_public_key)}, "
            f"capabilities={self.capabilities}, "
            f"free_pairing_slots={self.free_pairing_slots}, "
            f"status={self.status}, "
            f"identity_certificate={hexed(self.identity_certificate)})"
        )
