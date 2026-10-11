from dataclasses import dataclass


@dataclass
class LeeKeys:
    ask: bytes
    nsk: bytes
    vsk_d: bytes
    vsk_z: bytes
