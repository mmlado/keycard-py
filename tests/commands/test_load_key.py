import pytest
from keycard.commands.load_key import load_key
from keycard import constants
from hashlib import sha256


def test_load_key_bip39(card):
    seed = b"\xAA" * 64
    fake_uid = b"\xBB" * 32
    card.send_secure_apdu.return_value = fake_uid

    result = load_key(
        card,
        key_type=constants.LoadKeyType.BIP39_SEED,
        bip39_seed=seed
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_LOAD_KEY,
        p1=constants.LoadKeyType.BIP39_SEED,
        data=seed
    )
    assert result == fake_uid


def test_load_key_pair(card):
    public_key = b'\x04' + b'\x01' * 64
    private_key = b'\x02' * 32
    uid = sha256(public_key).digest()
    card.send_secure_apdu.return_value = uid

    inner = b'\x80\x41' + public_key + b'\x81\x20' + private_key
    encoded = b'\xA1' + bytes([len(inner)]) + inner

    result = load_key(
        card,
        key_type=constants.LoadKeyType.ECC,
        public_key=public_key,
        private_key=private_key
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_LOAD_KEY,
        p1=constants.LoadKeyType.ECC,
        data=encoded
    )
    assert result == uid


def test_load_key_extended_long_form_length(card):
    public_key = b'\x04' + b'\x01' * 64
    private_key = b'\x02' * 32
    chain_code = b'\x03' * 32
    card.send_secure_apdu.return_value = b'\xBB' * 32

    inner = (
        b'\x80\x41' + public_key +
        b'\x81\x20' + private_key +
        b'\x82\x20' + chain_code
    )
    encoded = b'\xA1\x81' + bytes([len(inner)]) + inner

    load_key(
        card,
        key_type=constants.LoadKeyType.EXTENDED_ECC,
        public_key=public_key,
        private_key=private_key,
        chain_code=chain_code
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_LOAD_KEY,
        p1=constants.LoadKeyType.EXTENDED_ECC,
        data=encoded
    )


@pytest.mark.parametrize('length', [16, 64])
def test_load_key_lee_seed(card, length):
    seed = b"\xAA" * length
    card.send_secure_apdu.return_value = b"\xBB" * 32

    load_key(
        card,
        key_type=constants.LoadKeyType.LEE_SEED,
        bip39_seed=seed
    )

    card.send_secure_apdu.assert_called_once_with(
        ins=constants.INS_LOAD_KEY,
        p1=0x04,
        data=seed
    )


@pytest.mark.parametrize('key_type', [
    constants.LoadKeyType.BIP39_SEED,
    constants.LoadKeyType.LEE_SEED,
])
@pytest.mark.parametrize('length', [15, 65])
def test_seed_wrong_length(card, key_type, length):
    with pytest.raises(ValueError, match="Seed must be 16 to 64 bytes"):
        load_key(card, key_type=key_type, bip39_seed=b"\xAA" * length)
    card.send_secure_apdu.assert_not_called()


@pytest.mark.parametrize('key_type', [
    constants.LoadKeyType.BIP39_SEED,
    constants.LoadKeyType.LEE_SEED,
])
def test_seed_missing(card, key_type):
    with pytest.raises(ValueError, match="Seed must be 16 to 64 bytes"):
        load_key(card, key_type=key_type)


def test_ecc_missing_private_key(card):
    with pytest.raises(ValueError, match="Private key.*required"):
        load_key(
            card,
            key_type=constants.LoadKeyType.ECC,
            public_key=b"\x04" + b"\x01" * 64
        )


def test_extended_ecc_missing_private_key(card):
    with pytest.raises(ValueError, match="Private key.*required"):
        load_key(
            card,
            key_type=constants.LoadKeyType.EXTENDED_ECC,
            public_key=b"\x04" + b"\x02" * 64,
            chain_code=b"\x00" * 32
        )
