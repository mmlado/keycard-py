# keycard/parsing/signature.py
from dataclasses import dataclass
from typing import Optional

from ..constants import SigningAlgorithm


@dataclass
class SignatureResult:
    algo: SigningAlgorithm
    format: str
    signature: bytes
    recovery_id: Optional[int] = None
    public_key: Optional[bytes] = None

    @classmethod
    def from_r_s(
        cls,
        algo: SigningAlgorithm,
        r: bytes,
        s: bytes,
        recovery_id: Optional[int] = None,
        public_key: Optional[bytes] = None
    ) -> "SignatureResult":
        r_encoded = b'\x02' + bytes([len(r)]) + r
        s_encoded = b'\x02' + bytes([len(s)]) + s
        seq = r_encoded + s_encoded
        der = b'\x30' + bytes([len(seq)]) + seq

        return cls(
            algo=algo,
            format="rs_tlv",
            signature=der,
            recovery_id=recovery_id,
            public_key=public_key
        )
