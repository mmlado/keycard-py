import pytest

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from keycard.secure_channel import SecureSession


@pytest.fixture
def session():
    shared_secret = get_random_bytes(32)
    pairing_key = get_random_bytes(32)
    salt = get_random_bytes(16)
    seed_iv = get_random_bytes(16)
    return SecureSession.open(shared_secret, pairing_key, salt, seed_iv)


def test_derive_keys_length():
    shared_secret = b'a' * 32
    pairing_key = b'b' * 32
    salt = b'c' * 16
    enc_key, mac_key = SecureSession.derive_keys(
        shared_secret,
        pairing_key,
        salt
    )
    assert len(enc_key) == 32
    assert len(mac_key) == 32
    assert enc_key != mac_key


def test_open_returns_session():
    shared_secret = b'a' * 32
    pairing_key = b'b' * 32
    salt = b'c' * 16
    seed_iv = b'd' * 16
    session = SecureSession.open(shared_secret, pairing_key, salt, seed_iv)
    assert isinstance(session, SecureSession)
    assert session.enc_key
    assert session.mac_key
    assert session.iv == seed_iv


def test_wrap_apdu_and_unwrap_response(session):
    cla, ins, p1, p2 = 0x80, 0xCA, 0x00, 0x00
    data = b"test data"
    # Wrap APDU
    out_cla, out_ins, out_p1, out_p2, wrapped = session.wrap_apdu(
        cla, ins, p1, p2, data
    )
    assert (out_cla, out_ins, out_p1, out_p2) == (cla, ins, p1, p2)
    assert isinstance(wrapped, bytes)
    assert len(wrapped) > 16  # MAC + encrypted

    response_data = b'response'
    sw = (0x90, 0x00)
    plaintext = response_data + bytes(sw)

    padded = pad(plaintext, 16, style='iso7816')
    cipher = AES.new(session.enc_key, AES.MODE_CBC, iv=session.iv)
    encrypted = cipher.encrypt(padded)

    lr = len(encrypted)
    mac_input = bytes([lr]) + b'\x00' * 15 + encrypted
    mac_cipher = AES.new(session.mac_key, AES.MODE_CBC, iv=bytes(16))
    mac = mac_cipher.encrypt(mac_input)[-16:]
    response = mac + encrypted

    unwrapped, sw_out = session.unwrap_response(response)
    assert unwrapped == response_data
    assert sw_out == 0x9000


def test_unwrap_response_invalid_mac(session):
    response_data = b'abc'
    sw = (0x90, 0x00)

    plaintext = response_data + bytes(sw)
    padded = pad(plaintext, 16, style='iso7816')
    cipher = AES.new(session.enc_key, AES.MODE_CBC, iv=session.iv)
    encrypted = cipher.encrypt(padded)

    lr = len(encrypted)
    mac_input = bytes([lr]) + b'\x00' * 15 + encrypted
    mac_cipher = AES.new(session.mac_key, AES.MODE_CBC, iv=bytes(16))
    mac = mac_cipher.encrypt(mac_input)[-16:]

    bad_mac = bytes([b ^ 0xFF for b in mac])
    response = bad_mac + encrypted

    with pytest.raises(ValueError, match="Invalid MAC"):
        session.unwrap_response(response)


def test_unwrap_response_too_short(session):
    with pytest.raises(ValueError, match="Invalid secure response length"):
        session.unwrap_response(b'short')


def test_unwrap_response_missing_sw(session):
    plaintext = b'x'  # less than 2 bytes
    padded = pad(plaintext, 16, style='iso7816')
    cipher = AES.new(session.enc_key, AES.MODE_CBC, iv=session.iv)
    encrypted = cipher.encrypt(padded)

    lr = len(encrypted)
    mac_input = bytes([lr]) + b'\x00' * 15 + encrypted
    mac_cipher = AES.new(session.mac_key, AES.MODE_CBC, iv=bytes(16))
    mac = mac_cipher.encrypt(mac_input)[-16:]
    response = mac + encrypted

    with pytest.raises(ValueError, match="Missing status word in response"):
        session.unwrap_response(response)
