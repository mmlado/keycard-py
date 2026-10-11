from typing import Optional

from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)

from .. import constants
from ..constants import DerivationOption, DerivationSource, SigningAlgorithm
from ..card_interface import CardInterface
from ..exceptions import InvalidStateError
from ..parsing import tlv
from ..parsing.keypath import KeyPath
from ..parsing.signature_result import SignatureResult
from ..secure_channel import SecureChannelVersion, channel_version


def sign(
    card: CardInterface,
    digest: bytes,
    p1: DerivationOption = DerivationOption.CURRENT,
    p2: SigningAlgorithm = SigningAlgorithm.ECDSA_SECP256K1,
    derivation_path: Optional[str] = None,
    tweak: Optional[bytes] = None
) -> SignatureResult:
    """
    Sign a 32-byte digest using the specified key and signing algorithm.

    This command sends the SIGN APDU to the Keycard and parses the response,
    returning a structured `SignatureResult` object. The signature may be
    returned as a DER-encoded structure, a raw 65-byte format including
    the recovery ID, or an ECDSA template depending on card behavior.
    Schnorr signatures are 64 bytes, R.x || s, with no recovery ID.

    Preconditions:
        - Secure Channel must be opened (unless using PINLESS)
        - PIN must be verified (unless using PINLESS)
        - A valid keypair must be loaded on the card
        - If P1=PINLESS, a PIN-less path must be configured

    Args:
        card (CardInterface): Active Keycard transport session.
        digest (bytes): 32-byte hash to be signed.
        p1 (DerivationOption): Key derivation option. One of:
            - CURRENT: Sign with the currently loaded key; on applet 4.0,
              which has no current key, with the master key
            - DERIVE: Derive key for signing without changing current
            - DERIVE_AND_MAKE_CURRENT: Derive and load for future use
            - PINLESS: Use pre-defined PIN-less key without SC/PIN
            Applet 4.0 accepts only CURRENT and DERIVE from the master key.
        p2 (SigningAlgorithm): Signing algorithm. Defaults to
            ECDSA_SECP256K1. Applet 4.0 also supports SCHNORR_BIP340.
        derivation_path (Optional[str]): String-formatted BIP32 path
            (e.g. "m/44'/60'/0'/0/0"). Required if `p1` uses derivation;
            "m" is the master key. The source (master/parent/current) is
            inferred from the path prefix.
        tweak (Optional[bytes]): 32 bytes the card adds to the private key
            before a Schnorr signature, e.g. a Taproot tweak. Defaults to
            zeros, an untweaked BIP-340 signature. The returned public key
            is the untweaked one.

    Returns:
        SignatureResult: Parsed signature result, including the signature
        (DER or raw), algorithm, and optional recovery ID or public key.

    Raises:
        ValueError: If the digest or tweak is not 32 bytes, a tweak is
            given for ECDSA, or the path is invalid.
        InvalidStateError: If preconditions (PIN, SC) are not met.
        APDUError: If the card returns an error (e.g., SW=0x6985).
    """
    if p2 not in (
        SigningAlgorithm.ECDSA_SECP256K1,
        SigningAlgorithm.SCHNORR_BIP340
    ):
        raise NotImplementedError(
            f"Signature algorithm {p2} not supported"
        )

    if len(digest) != 32:
        raise ValueError("Digest must be exactly 32 bytes")

    if p2 == SigningAlgorithm.SCHNORR_BIP340:
        if tweak is None:
            tweak = bytes(32)
        if len(tweak) != 32:
            raise ValueError("Tweak must be exactly 32 bytes")
    elif tweak is not None:
        raise ValueError("A tweak is only used with Schnorr signatures")

    if p1 != DerivationOption.PINLESS and not card.is_pin_verified:
        raise InvalidStateError(
            "PIN must be verified to sign with this derivation option")

    data = digest + (tweak or b'')
    source = DerivationSource.MASTER
    if p1 in (
        DerivationOption.DERIVE,
        DerivationOption.DERIVE_AND_MAKE_CURRENT
    ):
        if not derivation_path:
            raise ValueError("Derivation path cannot be empty")
        key_path = KeyPath(derivation_path)
        data += key_path.data
        source = key_path.source
    elif (
        p1 == DerivationOption.CURRENT and
        channel_version(card.version) == SecureChannelVersion.V2
    ):
        # 4.x has no current key; an empty path signs with the master key.
        p1 = DerivationOption.DERIVE

    response = card.send_secure_apdu(
        ins=constants.INS_SIGN,
        p1=p1 | source,
        p2=p2,
        data=data
    )

    if response.startswith(b'\xA0'):
        outer = tlv.parse_tlv(response)
        inner = tlv.parse_tlv(outer[0xA0][0])
        pub = inner.get(0x80, [None])[0]

        if 0x88 in inner:
            raw = inner[0x88][0]
            if len(raw) != 64:
                raise ValueError("Expected 64-byte Schnorr signature (R.x||s)")
            return SignatureResult(
                algo=p2,
                digest=digest,
                r=int.from_bytes(raw[:32], "big"),
                s=int.from_bytes(raw[32:], "big"),
                public_key=pub
            )

        der_bytes = (
            b'\x30' +
            len(inner[0x30][0]).to_bytes(1, 'big') +
            inner[0x30][0]
        )
        r, s = decode_dss_signature(der_bytes)
        return SignatureResult(
            algo=p2,
            digest=digest,
            r=r,
            s=s,
            public_key=pub
        )
    elif response.startswith(b'\x80'):
        outer = tlv.parse_tlv(response)
        raw = outer[0x80][0]
        if len(raw) != 65:
            raise ValueError("Expected 65-byte raw signature (r||s||recId)")
        return SignatureResult(
            algo=p2,
            digest=digest,
            r=int.from_bytes(raw[:32], "big"),
            s=int.from_bytes(raw[32:64], "big"),
            recovery_id=int(raw[64])
        )

    raise ValueError("Unexpected SIGN response format")
