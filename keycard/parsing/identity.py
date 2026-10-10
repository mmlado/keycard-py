from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from ecdsa import VerifyingKey, SECP256k1

from ..exceptions import InvalidResponseError
from ..parsing.tlv import parse_tlv


def parse(challenge: bytes, data: bytes) -> bytes:
    tlvs = parse_tlv(data)

    inner_tlvs = parse_tlv(tlvs[0xA0][0])

    try:
        certificate = inner_tlvs[0x8A][0]
        signature = inner_tlvs[0x30][0]
    except (IndexError, KeyError):
        raise InvalidResponseError('Malformed identity response')

    signature = b'\x30' + len(signature).to_bytes(1, 'big') + signature
    if len(certificate) < 95 or len(signature) < 65:
        raise InvalidResponseError('Malformed identity response')

    _verify(certificate, signature, challenge)
    return _recover_public_key(certificate)


def _verify(certificate: bytes, signature: bytes, challenge: bytes) -> None:
    identity_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), certificate[:33])
    try:
        identity_key.verify(
            signature, challenge, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature as e:
        raise InvalidResponseError('Identity signature is invalid') from e


def _recover_public_key(certificate: bytes) -> bytes:
    signature = certificate[33:]
    v = signature[-1]
    digest = sha256(certificate).digest()

    vk = VerifyingKey.from_public_key_recovery_with_digest(
        signature[:-1], digest, SECP256k1)

    public_key = vk[v] if isinstance(vk, list) else vk
    der: bytes = public_key.to_der('compressed')
    return der
