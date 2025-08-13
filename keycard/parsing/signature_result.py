from dataclasses import dataclass
from ecdsa import VerifyingKey, util, SECP256k1
from typing import Optional

from ..constants import SigningAlgorithm


@dataclass
class SignatureResult:
    algo: SigningAlgorithm
    r: bytes
    s: bytes
    recovery_id: Optional[int] = None
    public_key: Optional[bytes] = None

    def __init__(
        self,
        digest: str,
        algo: SigningAlgorithm,
        r: int,
        s: int,
        recovery_id: Optional[int] = None,
        public_key: Optional[bytes] = None
    ) -> "SignatureResult":

        self.algo = algo
        self.r = r.to_bytes((r.bit_length() + 7) // 8, 'big')
        self.s = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        if public_key is None and recovery_id is None:
            raise ValueError(
                "Public key and recovery id not returned from card")
        
        self.public_key = \
            public_key if public_key else self._recover_public_key(digest)
                    
        self.recovery_id = \
            recovery_id if recovery_id else self._recover_v(digest)

    @property
    def signature(self):
        return self.r + self.s
    
    @property
    def signature_der(self):
        return util.sigencode_der(
            int.from_bytes(self.r), int.from_bytes(self.s), self.recovery_id)
    
    def _recover_public_key(self, digest):
        return VerifyingKey.from_public_key_recovery_with_digest(
            self.signature_der,
            digest,
            SECP256k1,
            sigdecode=util.sigdecode_der)

    def _recover_v(self, digest):
        public_keys = VerifyingKey.from_public_key_recovery_with_digest(
            self.signature, digest, SECP256k1)

        index = 0
        for public_key in public_keys:
            if self.public_key[1:] == public_key.to_string():
                return index
            index += 1

        raise RuntimeError("Recovery ID not found")

    def _signature_der(self, id: Optional[int] = 0):
        return 
