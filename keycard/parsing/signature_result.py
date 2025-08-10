# keycard/parsing/signature.py
from dataclasses import dataclass
from typing import Optional

from ..constants import SigningAlgorithm


@dataclass
class SignatureResult:
    algo: SigningAlgorithm
    r: bytes
    s: bytes
    recovery_id: Optional[int] = None
    public_key: Optional[bytes] = None

    @classmethod
    def from_r_s(
        cls,
        digest: str,
        algo: SigningAlgorithm,
        r: bytes,
        s: bytes,
        public_key: Optional[bytes] = None
    ) -> "SignatureResult":

        

        return cls(
            algo=algo,
            r=r,
            s=s,
            recovery_id=recovery_id,
            public_key=public_key
        )
